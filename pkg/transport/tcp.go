package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tcpKeepAlivePeriod is how often the kernel sends keepalive probes on
// idle TCP connections in the alias table. Without this, half-closed
// peers (rebooted, network-partitioned) would silently keep an entry
// in the table until the next write fails.
const tcpKeepAlivePeriod = 30 * time.Second

// TCPTransport keeps every accepted and every dialed TCP connection
// open and persistent in an alias table keyed by the peer's address
// (host:port). Subsequent sends to a peer reuse the existing
// connection instead of opening a new one. Inbound and outbound share
// one table — if a peer happens to connect to us from the same
// address we are about to dial, the existing connection is reused.
type TCPTransport struct {
	listener *net.TCPListener
	handler  func(Packet)

	mu        sync.RWMutex
	alias     map[string]*net.TCPConn // peer addr → connection
	dialLocks sync.Map                // map[string]*sync.Mutex, per-dst

	done chan struct{}
}

func NewTCPTransport(ip string, port int, handler func(Packet)) (*TCPTransport, error) {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return nil, err
	}

	t := &TCPTransport{
		listener: listener,
		handler:  handler,
		alias:    make(map[string]*net.TCPConn),
		done:     make(chan struct{}),
	}

	go t.acceptLoop()
	return t, nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.listener.AcceptTCP()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				log.Printf("[tcp] accept error: %v", err)
				continue
			}
		}

		configureKeepalive(conn)

		peer := conn.RemoteAddr().String()
		t.register(peer, conn)

		log.Printf("[tcp] accepted from %s (alias table size: %d)", peer, t.aliasCount())

		go t.handleConn(conn)
	}
}

// handleConn parses SIP messages off conn, dispatches each to the
// transport handler, and prunes the alias table when the connection
// closes.
func (t *TCPTransport) handleConn(conn *net.TCPConn) {
	peer := conn.RemoteAddr().String()
	defer func() {
		t.removeIfMatches(peer, conn)
		conn.Close()
	}()

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-t.done:
			return
		default:
		}

		msg, err := readSIPMessage(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[tcp] read error from %s: %v", peer, err)
			}
			return
		}

		t.handler(Packet{
			Data:       msg,
			RemoteAddr: conn.RemoteAddr(),
			LocalAddr:  conn.LocalAddr(),
			Transport:  "TCP",
		})
	}
}

// Send writes data to the connection associated with dst.
//
// Path 1 — fast path: a cached connection exists and the write
// succeeds. Returns immediately.
//
// Path 2 — broken cached connection: the cached connection's write
// fails (peer reset, half-closed, etc.). The entry is removed from
// the alias table and we fall through to a fresh dial.
//
// Path 3 — no cached connection: dial under a per-dst lock so
// concurrent senders only open one socket, register it in the alias
// table, and send.
//
// At most one re-dial is attempted per call. A failure on the freshly
// dialed connection bubbles up — we don't loop.
func (t *TCPTransport) Send(data []byte, dst string) error {
	if conn := t.lookup(dst); conn != nil {
		if _, err := conn.Write(data); err == nil {
			return nil
		}
		// Cached connection is broken. Drop it and dial fresh.
		t.removeIfMatches(dst, conn)
		conn.Close()
		log.Printf("[tcp] cached connection to %s was broken — re-dialing", dst)
	}

	return t.dialAndSend(data, dst)
}

// dialAndSend serializes connect-or-reuse for a single destination
// behind a per-dst lock. It re-checks the alias table inside the lock
// in case another goroutine has just dialed; if the entry it finds is
// also broken, that entry too is replaced.
func (t *TCPTransport) dialAndSend(data []byte, dst string) error {
	l := t.lockForDst(dst)
	l.Lock()
	defer l.Unlock()

	if conn := t.lookup(dst); conn != nil {
		if _, err := conn.Write(data); err == nil {
			return nil
		}
		t.removeIfMatches(dst, conn)
		conn.Close()
	}

	conn, err := t.dial(dst)
	if err != nil {
		return err
	}
	t.register(dst, conn)
	log.Printf("[tcp] opened outbound to %s (alias table size: %d)", dst, t.aliasCount())
	go t.handleConn(conn)

	if _, err := conn.Write(data); err != nil {
		t.removeIfMatches(dst, conn)
		conn.Close()
		return err
	}
	return nil
}

func (t *TCPTransport) lookup(dst string) *net.TCPConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.alias[dst]
}

func (t *TCPTransport) dial(dst string) (*net.TCPConn, error) {
	addr, err := net.ResolveTCPAddr("tcp4", dst)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTCP("tcp4", nil, addr)
	if err != nil {
		return nil, err
	}
	configureKeepalive(conn)
	return conn, nil
}

// register inserts conn into the alias table, replacing (and closing)
// any prior connection for the same peer.
func (t *TCPTransport) register(peer string, conn *net.TCPConn) {
	t.mu.Lock()
	if existing, ok := t.alias[peer]; ok && existing != conn {
		existing.Close()
	}
	t.alias[peer] = conn
	t.mu.Unlock()
}

// removeIfMatches drops the entry for peer only if it still points at
// conn — i.e. don't accidentally evict a fresher replacement.
func (t *TCPTransport) removeIfMatches(peer string, conn *net.TCPConn) {
	t.mu.Lock()
	if t.alias[peer] == conn {
		delete(t.alias, peer)
	}
	t.mu.Unlock()
}

func (t *TCPTransport) lockForDst(dst string) *sync.Mutex {
	val, _ := t.dialLocks.LoadOrStore(dst, &sync.Mutex{})
	return val.(*sync.Mutex)
}

// AliasCount reports the number of live TCP connections in the alias
// table (each accepted or dialed connection counts once).
func (t *TCPTransport) AliasCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.alias)
}

// AliasTable returns a snapshot of the alias table mapping peer
// address → local socket address. Useful for management UIs.
func (t *TCPTransport) AliasTable() map[string]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]string, len(t.alias))
	for k, c := range t.alias {
		out[k] = c.LocalAddr().String()
	}
	return out
}

// aliasCount is a private helper used by log lines so we don't
// double-acquire the read lock.
func (t *TCPTransport) aliasCount() int { return t.AliasCount() }

func (t *TCPTransport) Stop() {
	close(t.done)
	t.listener.Close()
	t.mu.Lock()
	for _, conn := range t.alias {
		conn.Close()
	}
	t.alias = make(map[string]*net.TCPConn)
	t.mu.Unlock()
}

func configureKeepalive(c *net.TCPConn) {
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(tcpKeepAlivePeriod)
}

func readSIPMessage(reader *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	contentLength := 0
	foundCL := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		buf.WriteString(line)

		trimmed := strings.TrimSpace(line)
		if !foundCL && strings.HasPrefix(strings.ToLower(trimmed), "content-length") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				cl, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					contentLength = cl
					foundCL = true
				}
			}
		}

		if trimmed == "" {
			break
		}
	}

	if contentLength > 0 {
		body := make([]byte, contentLength)
		_, err := io.ReadFull(reader, body)
		if err != nil {
			return nil, err
		}
		buf.Write(body)
	}

	return buf.Bytes(), nil
}
