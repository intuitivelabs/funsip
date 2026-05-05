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
)

type TCPTransport struct {
	listener *net.TCPListener
	handler  func(Packet)
	conns    map[string]net.Conn
	mu       sync.RWMutex
	done     chan struct{}
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
		conns:    make(map[string]net.Conn),
		done:     make(chan struct{}),
	}

	go t.acceptLoop()
	return t, nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				log.Printf("[tcp] accept error: %v", err)
				continue
			}
		}

		t.mu.Lock()
		t.conns[conn.RemoteAddr().String()] = conn
		t.mu.Unlock()

		go t.handleConn(conn)
	}
}

func (t *TCPTransport) handleConn(conn net.Conn) {
	defer func() {
		t.mu.Lock()
		delete(t.conns, conn.RemoteAddr().String())
		t.mu.Unlock()
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
				log.Printf("[tcp] read error from %s: %v", conn.RemoteAddr(), err)
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

func (t *TCPTransport) Send(data []byte, dst string) error {
	t.mu.RLock()
	conn, exists := t.conns[dst]
	t.mu.RUnlock()

	if !exists {
		tcpAddr, err := net.ResolveTCPAddr("tcp4", dst)
		if err != nil {
			return err
		}
		conn, err = net.DialTCP("tcp4", nil, tcpAddr)
		if err != nil {
			return err
		}
		t.mu.Lock()
		t.conns[dst] = conn
		t.mu.Unlock()
		go t.handleConn(conn)
	}

	_, err := conn.Write(data)
	return err
}

func (t *TCPTransport) Stop() {
	close(t.done)
	t.listener.Close()
	t.mu.Lock()
	for _, conn := range t.conns {
		conn.Close()
	}
	t.mu.Unlock()
}
