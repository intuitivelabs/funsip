package play

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Session streams one G.711 µ-law audio file to a single RTP
// destination. Allocate one per call. The session goroutine is
// started by Start() and stops on Stop() (or end-of-file).
type Session struct {
	CallID   string
	Filename string

	conn      *net.UDPConn
	localIP   string
	localPort int

	dest atomic.Pointer[net.UDPAddr]
	ssrc uint32

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New allocates a Session bound to a fresh UDP socket on localIP.
// The audio file is opened up front so any parse error surfaces
// before the SIP 200 OK goes out.
func New(localIP, callID, filename string) (*Session, error) {
	// Validate the file is something we can play.
	wf, err := openWav(filename)
	if err != nil {
		return nil, fmt.Errorf("open audio: %w", err)
	}
	wf.Close() // re-opened on Start

	addr := net.ParseIP(localIP)
	if addr == nil {
		return nil, fmt.Errorf("invalid local IP %q", localIP)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: addr, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind rtp socket: %w", err)
	}

	var ssrcBuf [4]byte
	_, _ = rand.Read(ssrcBuf[:])
	ssrc := binary.BigEndian.Uint32(ssrcBuf[:])

	return &Session{
		CallID:    callID,
		Filename:  filename,
		conn:      conn,
		localIP:   localIP,
		localPort: conn.LocalAddr().(*net.UDPAddr).Port,
		ssrc:      ssrc,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}, nil
}

// LocalPort is the RTP port this session listens on (and sends
// from). The SIP layer puts this number in the m= line of the
// 200 OK SDP.
func (s *Session) LocalPort() int { return s.localPort }

// SSRC returns the RTP SSRC the session will use. Stable for the
// session lifetime — the proxy layer reuses it to derive a stable
// To-tag for the 200 OK so retransmits remain consistent.
func (s *Session) SSRC() uint32 { return s.ssrc }

// SDPBody returns the SDP answer (UTF-8 bytes, CRLF line endings)
// the SIP 200 OK should carry. It advertises PCMU (PT 0) on the
// allocated RTP port. RTCP defaults to port+1; we don't open it
// but include it implicitly per RFC3550.
func (s *Session) SDPBody() []byte {
	t := time.Now().Unix()
	return []byte(fmt.Sprintf(
		"v=0\r\n"+
			"o=funsip %d %d IN IP4 %s\r\n"+
			"s=funsip-play\r\n"+
			"c=IN IP4 %s\r\n"+
			"t=0 0\r\n"+
			"m=audio %d RTP/AVP 0\r\n"+
			"a=rtpmap:0 PCMU/8000\r\n"+
			"a=sendrecv\r\n",
		t, t, s.localIP, s.localIP, s.localPort,
	))
}

// SetDestination updates where the session sends RTP. Calling this
// before Start() avoids the brief initial dead period when the
// caller's ACK hasn't been processed yet.
func (s *Session) SetDestination(addr *net.UDPAddr) {
	s.dest.Store(addr)
}

// Start launches the sender goroutine. It pumps 20 ms G.711 µ-law
// frames out of the file at wall-clock cadence, looping the file
// once it runs out of samples (typical for hold music / IVR
// prompts). Returns immediately; the goroutine runs until Stop().
func (s *Session) Start() {
	go s.run()
}

func (s *Session) run() {
	defer close(s.done)

	wf, err := openWav(s.Filename)
	if err != nil {
		log.Printf("[play] reopen %s: %v", s.Filename, err)
		return
	}
	defer wf.Close()

	const period = 20 * time.Millisecond
	const samplesPerFrame = 160 // 8 kHz × 20 ms
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	var (
		seq uint16
		ts  uint32
	)
	// A random initial seq/ts is conventional, though for a one-off
	// playback session it doesn't really matter.
	seqB := make([]byte, 4)
	_, _ = rand.Read(seqB)
	seq = binary.BigEndian.Uint16(seqB[0:2])
	ts = binary.BigEndian.Uint32(seqB[0:4])

	// Discard the initial Tick — it fires immediately.
	<-ticker.C

	pkt := make([]byte, 12+samplesPerFrame)

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}

		dst := s.dest.Load()
		if dst == nil {
			// We don't know where to send yet (ACK not in, or
			// caller had no SDP). Skip this tick.
			ts += samplesPerFrame
			seq++
			continue
		}

		frame, err := wf.nextFrame()
		if err != nil {
			log.Printf("[play] read error: %v", err)
			return
		}
		if frame == nil {
			// EOF — loop the file.
			wf.Close()
			wf, err = openWav(s.Filename)
			if err != nil {
				log.Printf("[play] reopen on loop: %v", err)
				return
			}
			continue
		}

		// Pad short last frame with µ-law silence (0xFF).
		if len(frame) < samplesPerFrame {
			padded := make([]byte, samplesPerFrame)
			copy(padded, frame)
			for i := len(frame); i < samplesPerFrame; i++ {
				padded[i] = 0xFF
			}
			frame = padded
		}

		// V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU)
		pkt[0] = 0x80
		pkt[1] = 0x00
		binary.BigEndian.PutUint16(pkt[2:4], seq)
		binary.BigEndian.PutUint32(pkt[4:8], ts)
		binary.BigEndian.PutUint32(pkt[8:12], s.ssrc)
		copy(pkt[12:], frame)

		if _, err := s.conn.WriteToUDP(pkt, dst); err != nil {
			if isClosedConnErr(err) {
				return
			}
			log.Printf("[play] write: %v", err)
		}

		seq++
		ts += samplesPerFrame
	}
}

// Stop terminates the sender and releases the UDP socket. Safe to
// call from any goroutine and idempotent.
func (s *Session) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stop)
		s.conn.Close()
		<-s.done
	})
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "use of closed network connection" ||
		(len(err.Error()) > 10 && err.Error()[len(err.Error())-10:] == "connection")
}

// ----- Manager: per-Call-ID lifecycle -----

// Manager owns the active play sessions, keyed by Call-ID. The
// server's request handler calls CleanupForCallID on BYE.
type Manager struct {
	localIP  string
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewManager(localIP string) *Manager {
	return &Manager{
		localIP:  localIP,
		sessions: make(map[string]*Session),
	}
}

// Open creates a new session, opens the audio file, and stashes it
// under callID. Returns the session so the caller can fetch the
// SDP and start the sender.
func (m *Manager) Open(callID, filename string) (*Session, error) {
	s, err := New(m.localIP, callID, filename)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if old, ok := m.sessions[callID]; ok {
		old.Stop()
	}
	m.sessions[callID] = s
	m.mu.Unlock()
	return s, nil
}

// Get returns the session for callID, or nil.
func (m *Manager) Get(callID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[callID]
}

// CleanupForCallID stops the session for callID, if any. Safe to
// call on unknown Call-IDs.
func (m *Manager) CleanupForCallID(callID string) {
	m.mu.Lock()
	s := m.sessions[callID]
	delete(m.sessions, callID)
	m.mu.Unlock()
	if s != nil {
		s.Stop()
	}
}

// ActiveCount returns the number of currently-streaming sessions.
func (m *Manager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// CloseAll stops every session and clears the map.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	sess := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sess = append(sess, s)
	}
	m.sessions = map[string]*Session{}
	m.mu.Unlock()
	for _, s := range sess {
		s.Stop()
	}
}
