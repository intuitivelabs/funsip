// Package media implements a transport-only RTP/RTCP UDP relay used by
// the SIP stack to "anchor" media. RTP packets are not parsed; the relay
// simply moves UDP datagrams between two opposite local sockets.
//
// For each media stream allocated for a session two pairs of UDP
// sockets are bound on the local relay address:
//
//   - the "A-side" socket pair (RTP + RTCP) is the address that B sees
//     in A's rewritten SDP. B sends here; the relay forwards to A.
//   - the "B-side" socket pair is the address A sees in B's rewritten
//     SDP. A sends here; the relay forwards to B.
//
// Forwarding modes:
//
//   - symmetric (default true): packets are forwarded to the address
//     where the peer was last seen sending FROM. We do not use the
//     SDP-advertised peer address. This is "RTP latching" / RFC4961-ish
//     behaviour; it is what real-world SIP softphones behind NAT need.
//
//   - asymmetric (symmetric:false): packets are forwarded to the peer
//     address advertised in the SDP, regardless of where the peer is
//     actually sending from.
package media

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funsip/funsip/pkg/sdp"
)

type Options struct {
	Symmetric bool
}

func DefaultOptions() Options {
	return Options{Symmetric: true}
}

type Manager struct {
	localIP  string
	sessions map[string]*Session
	mu       sync.Mutex
}

func NewManager(localIP string) *Manager {
	return &Manager{localIP: localIP, sessions: make(map[string]*Session)}
}

func (m *Manager) LocalIP() string { return m.localIP }

func (m *Manager) Get(callID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[callID]
}

func (m *Manager) GetOrCreate(callID string, opts Options) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[callID]; ok {
		return s
	}
	s := &Session{
		CallID:  callID,
		opts:    opts,
		manager: m,
	}
	m.sessions[callID] = s
	return s
}

func (m *Manager) Delete(callID string) {
	m.mu.Lock()
	s := m.sessions[callID]
	delete(m.sessions, callID)
	m.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

func (m *Manager) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

type Session struct {
	CallID  string
	Streams []*Stream
	opts    Options
	manager *Manager
	mu      sync.Mutex
}

func (s *Session) Symmetric() bool { return s.opts.Symmetric }

// AnchorOffer rewrites the offer SDP in place: each m= port and the
// session/media-level c= lines are replaced with the relay's local
// address and freshly allocated A-side ports. The original endpoint
// addresses are recorded so that asymmetric forwarding can use them.
func (s *Session) AnchorOffer(in *sdp.SDP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionAddr := ""
	if in.Connection != nil {
		sessionAddr = in.Connection.Address
	}

	for i, m := range in.Media {
		addr := sessionAddr
		if m.Connection != nil {
			addr = m.Connection.Address
		}
		if m.Port == 0 {
			continue
		}

		rtpPort := m.Port
		rtcpPort := rtpPort + 1
		if p, _, ok := m.RTCPAttr(); ok {
			rtcpPort = p
		}

		stream, err := s.ensureStream(i)
		if err != nil {
			return err
		}

		if ip := net.ParseIP(addr); ip != nil {
			stream.aSDPRTP.Store(&net.UDPAddr{IP: ip, Port: rtpPort})
			stream.aSDPRTCP.Store(&net.UDPAddr{IP: ip, Port: rtcpPort})
		}

		m.Port = stream.aRtpPort
		if m.Connection != nil {
			m.Connection.Address = s.manager.localIP
		}
		if _, _, ok := m.RTCPAttr(); ok {
			m.SetRTCPAttr(stream.aRtcpPort, "")
		} else if rtcpPort != rtpPort+1 {
			m.SetRTCPAttr(stream.aRtcpPort, "")
		}
	}

	if in.Connection != nil {
		in.Connection.Address = s.manager.localIP
	}
	return nil
}

// AnchorAnswer is the same as AnchorOffer but for the answer SDP and
// the B-side ports.
func (s *Session) AnchorAnswer(in *sdp.SDP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionAddr := ""
	if in.Connection != nil {
		sessionAddr = in.Connection.Address
	}

	for i, m := range in.Media {
		if i >= len(s.Streams) {
			break
		}
		stream := s.Streams[i]

		addr := sessionAddr
		if m.Connection != nil {
			addr = m.Connection.Address
		}
		if m.Port == 0 {
			continue
		}

		rtpPort := m.Port
		rtcpPort := rtpPort + 1
		if p, _, ok := m.RTCPAttr(); ok {
			rtcpPort = p
		}

		if ip := net.ParseIP(addr); ip != nil {
			stream.bSDPRTP.Store(&net.UDPAddr{IP: ip, Port: rtpPort})
			stream.bSDPRTCP.Store(&net.UDPAddr{IP: ip, Port: rtcpPort})
		}

		m.Port = stream.bRtpPort
		if m.Connection != nil {
			m.Connection.Address = s.manager.localIP
		}
		if _, _, ok := m.RTCPAttr(); ok {
			m.SetRTCPAttr(stream.bRtcpPort, "")
		} else if rtcpPort != rtpPort+1 {
			m.SetRTCPAttr(stream.bRtcpPort, "")
		}
	}

	if in.Connection != nil {
		in.Connection.Address = s.manager.localIP
	}
	return nil
}

func (s *Session) ensureStream(i int) (*Stream, error) {
	for len(s.Streams) <= i {
		stream := &Stream{symmetric: s.opts.Symmetric, done: make(chan struct{})}
		if err := stream.allocate(s.manager.localIP); err != nil {
			return nil, err
		}
		s.Streams = append(s.Streams, stream)
		stream.start()
	}
	return s.Streams[i], nil
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.Streams {
		st.Close()
	}
	s.Streams = nil
}

// Stream represents one RTP+RTCP relay slot with two opposite socket pairs.
type Stream struct {
	symmetric bool

	aRtpConn, bRtpConn   *net.UDPConn
	aRtcpConn, bRtcpConn *net.UDPConn

	aRtpPort, aRtcpPort int
	bRtpPort, bRtcpPort int

	// SDP-advertised peer addresses (RTP/RTCP for A and for B).
	aSDPRTP, aSDPRTCP atomic.Pointer[net.UDPAddr]
	bSDPRTP, bSDPRTCP atomic.Pointer[net.UDPAddr]

	// Most recently observed source addresses.
	aSrcRTP, aSrcRTCP atomic.Pointer[net.UDPAddr]
	bSrcRTP, bSrcRTCP atomic.Pointer[net.UDPAddr]

	done   chan struct{}
	closed atomic.Bool
}

func (s *Stream) ARtpPort() int  { return s.aRtpPort }
func (s *Stream) BRtpPort() int  { return s.bRtpPort }
func (s *Stream) ARtcpPort() int { return s.aRtcpPort }
func (s *Stream) BRtcpPort() int { return s.bRtcpPort }

func (s *Stream) allocate(localIP string) error {
	addr := net.ParseIP(localIP)

	conns := []**net.UDPConn{&s.aRtpConn, &s.aRtcpConn, &s.bRtpConn, &s.bRtcpConn}
	ports := []*int{&s.aRtpPort, &s.aRtcpPort, &s.bRtpPort, &s.bRtcpPort}

	for i, c := range conns {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: addr, Port: 0})
		if err != nil {
			s.closeAll()
			return fmt.Errorf("allocate udp socket: %w", err)
		}
		*c = conn
		*ports[i] = conn.LocalAddr().(*net.UDPAddr).Port
	}
	return nil
}

func (s *Stream) start() {
	// A-side socket: receives from B, forwards to A using B-side socket.
	go s.relay(s.aRtpConn, s.bRtpConn,
		&s.bSrcRTP, &s.aSrcRTP, &s.aSDPRTP, "A-side RTP")
	go s.relay(s.aRtcpConn, s.bRtcpConn,
		&s.bSrcRTCP, &s.aSrcRTCP, &s.aSDPRTCP, "A-side RTCP")

	// B-side socket: receives from A, forwards to B using A-side socket.
	go s.relay(s.bRtpConn, s.aRtpConn,
		&s.aSrcRTP, &s.bSrcRTP, &s.bSDPRTP, "B-side RTP")
	go s.relay(s.bRtcpConn, s.aRtcpConn,
		&s.aSrcRTCP, &s.bSrcRTCP, &s.bSDPRTCP, "B-side RTCP")
}

// relay reads packets on `in`, stores the source address in `srcStore`
// (so that the OTHER direction can latch onto it for symmetric mode),
// looks up the destination via `peerSrcStore` (symmetric) or
// `peerSDPStore` (asymmetric), and writes the packet on `out`.
func (s *Stream) relay(
	in, out *net.UDPConn,
	srcStore, peerSrcStore *atomic.Pointer[net.UDPAddr],
	peerSDPStore *atomic.Pointer[net.UDPAddr],
	label string,
) {
	buf := make([]byte, 65535)
	for {
		_ = in.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, src, err := in.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("[media] %s read error: %v", label, err)
			return
		}

		srcStore.Store(src)

		var dst *net.UDPAddr
		if s.symmetric {
			dst = peerSrcStore.Load()
		} else {
			dst = peerSDPStore.Load()
		}
		if dst == nil {
			continue
		}
		if _, err := out.WriteToUDP(buf[:n], dst); err != nil {
			if s.closed.Load() {
				return
			}
			log.Printf("[media] %s write error: %v", label, err)
		}
	}
}

func (s *Stream) Close() {
	if s.closed.Swap(true) {
		return
	}
	s.closeAll()
	if s.done != nil {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
}

func (s *Stream) closeAll() {
	for _, c := range []*net.UDPConn{s.aRtpConn, s.aRtcpConn, s.bRtpConn, s.bRtcpConn} {
		if c != nil {
			_ = c.Close()
		}
	}
}
