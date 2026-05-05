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

	"github.com/intuitivelabs/funsip/pkg/sdp"
)

type Options struct {
	Symmetric   bool
	IdleTimeout time.Duration
}

const DefaultIdleTimeout = 2 * time.Minute

func DefaultOptions() Options {
	return Options{Symmetric: true, IdleTimeout: DefaultIdleTimeout}
}

type Manager struct {
	localIP  string
	sessions map[string]*Session
	mu       sync.Mutex

	sweepInterval time.Duration
	stopSweep     chan struct{}
}

func NewManager(localIP string) *Manager {
	m := &Manager{
		localIP:       localIP,
		sessions:      make(map[string]*Session),
		sweepInterval: 5 * time.Second,
		stopSweep:     make(chan struct{}),
	}
	go m.sweepLoop()
	return m
}

// SetSweepInterval changes how often the manager checks for idle
// streams. Intended for tests; production code should use the default.
// The new interval takes effect on the next sweep cycle.
func (m *Manager) SetSweepInterval(d time.Duration) {
	m.sweepInterval = d
}

// SweepNow runs one synchronous sweep. Useful in tests to avoid
// waiting on the periodic ticker.
func (m *Manager) SweepNow() {
	m.sweepIdle()
}

func (m *Manager) sweepLoop() {
	for {
		t := time.NewTimer(m.sweepInterval)
		select {
		case <-t.C:
			m.sweepIdle()
		case <-m.stopSweep:
			t.Stop()
			return
		}
	}
}

// sweepIdle closes streams that have not seen any RTP activity for
// longer than their idleTimeout — but only if neither side of the
// stream is on hold. Sessions whose streams are all closed are
// removed from the map.
func (m *Manager) sweepIdle() {
	m.mu.Lock()
	live := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		live = append(live, s)
	}
	m.mu.Unlock()

	now := time.Now().UnixNano()
	for _, s := range live {
		s.mu.Lock()
		anyAlive := false
		for _, st := range s.Streams {
			if st.closed.Load() {
				continue
			}
			if st.IsOnHold() {
				anyAlive = true
				continue
			}
			if st.idleTimeout > 0 {
				last := st.lastActivity.Load()
				if last > 0 && time.Duration(now-last) > st.idleTimeout {
					log.Printf("[media] stream idle for >%v — releasing sockets", st.idleTimeout)
					st.Close()
					continue
				}
			}
			anyAlive = true
		}
		s.mu.Unlock()

		if !anyAlive {
			m.mu.Lock()
			if cur, ok := m.sessions[s.CallID]; ok && cur == s {
				delete(m.sessions, s.CallID)
			}
			m.mu.Unlock()
		}
	}
}

// Stop terminates the sweeper goroutine. Used at server shutdown.
func (m *Manager) Stop() {
	select {
	case <-m.stopSweep:
	default:
		close(m.stopSweep)
	}
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

		stream.holdA.Store(isHold(m, in.Connection, in.Attributes))

		if ip := net.ParseIP(addr); ip != nil {
			stream.aSDPRTP.Store(&net.UDPAddr{IP: ip, Port: rtpPort})
			stream.aSDPRTCP.Store(&net.UDPAddr{IP: ip, Port: rtcpPort})
		}

		m.Port = stream.aRtpPort
		if m.Connection != nil {
			m.Connection.Address = s.manager.localIP
		}
		rewriteRTCP(m, stream.aRtpPort, stream.aRtcpPort)
	}

	if in.Connection != nil {
		in.Connection.Address = s.manager.localIP
	}
	return nil
}

// rewriteRTCP fixes up the RTCP signaling in a media descriptor whose
// m= port has just been changed to relayRtpPort. There are three
// signaling modes to preserve:
//
//   - a=rtcp-mux (RFC5761): RTP and RTCP share the m= port. Keep the
//     attribute. If a=rtcp was also present, RFC5761 requires its
//     port to equal the rtp port — rewrite accordingly.
//
//   - a=rtcp:port (RFC3605, no mux): explicit RTCP port. Rewrite the
//     attribute to point at relayRtcpPort so the peer sends RTCP to
//     a port we actually listen on.
//
//   - implicit (no a=rtcp, no rtcp-mux): the peer assumes rtp+1.
//     Because the relay always allocates relayRtcpPort = relayRtpPort+1,
//     no a=rtcp attribute needs to be emitted — the peer's implicit
//     calculation already matches our listening port.
func rewriteRTCP(m *sdp.Media, relayRtpPort, relayRtcpPort int) {
	hasMux := m.HasAttr("rtcp-mux")
	_, _, hasExplicit := m.RTCPAttr()

	switch {
	case hasMux:
		if hasExplicit {
			// Per RFC5761 the explicit rtcp port must equal the rtp
			// port when rtcp-mux is in use.
			m.SetRTCPAttr(relayRtpPort, "")
		}
	case hasExplicit:
		m.SetRTCPAttr(relayRtcpPort, "")
	default:
		// Implicit — nothing to add. relayRtcpPort == relayRtpPort+1
		// by construction.
	}
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

		stream.holdB.Store(isHold(m, in.Connection, in.Attributes))

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
		rewriteRTCP(m, stream.bRtpPort, stream.bRtcpPort)
	}

	if in.Connection != nil {
		in.Connection.Address = s.manager.localIP
	}
	return nil
}

func (s *Session) ensureStream(i int) (*Stream, error) {
	for len(s.Streams) <= i {
		stream := &Stream{
			symmetric:   s.opts.Symmetric,
			idleTimeout: s.opts.IdleTimeout,
			done:        make(chan struct{}),
		}
		if err := stream.allocate(s.manager.localIP); err != nil {
			return nil, err
		}
		s.Streams = append(s.Streams, stream)
		stream.start()
	}
	return s.Streams[i], nil
}

// isHold returns true if the given media descriptor (with its
// session-level fallbacks) marks the stream as on-hold per the
// established conventions: a=sendonly, a=inactive, or c=0.0.0.0
// (the deprecated marker).
func isHold(m *sdp.Media, sessionConn *sdp.Connection, sessionAttrs []sdp.Attribute) bool {
	dir := mediaDirection(m, sessionAttrs)
	if dir == "sendonly" || dir == "inactive" {
		return true
	}
	addr := ""
	if m.Connection != nil {
		addr = m.Connection.Address
	} else if sessionConn != nil {
		addr = sessionConn.Address
	}
	return addr == "0.0.0.0"
}

func mediaDirection(m *sdp.Media, sessionAttrs []sdp.Attribute) string {
	for _, a := range m.Attributes {
		switch a.Name {
		case "sendrecv", "sendonly", "recvonly", "inactive":
			return a.Name
		}
	}
	for _, a := range sessionAttrs {
		switch a.Name {
		case "sendrecv", "sendonly", "recvonly", "inactive":
			return a.Name
		}
	}
	return "sendrecv"
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

	// Idle release: lastActivity is updated on every received RTP/RTCP
	// datagram. The sweeper closes the stream when (now - lastActivity)
	// exceeds idleTimeout, unless either side has signalled hold.
	lastActivity atomic.Int64
	idleTimeout  time.Duration
	holdA, holdB atomic.Bool

	done   chan struct{}
	closed atomic.Bool
}

// Closed reports whether the stream's UDP sockets have been released.
// Safe to call concurrently.
func (s *Stream) Closed() bool { return s.closed.Load() }

// IsOnHold reports whether at least one side of the stream is in a
// hold state (a=sendonly, a=inactive, or c=0.0.0.0).
func (s *Stream) IsOnHold() bool { return s.holdA.Load() || s.holdB.Load() }

// LastActivity returns the unix-nano timestamp of the last received
// RTP/RTCP datagram. Useful for tests.
func (s *Stream) LastActivity() int64 { return s.lastActivity.Load() }

func (s *Stream) ARtpPort() int  { return s.aRtpPort }
func (s *Stream) BRtpPort() int  { return s.bRtpPort }
func (s *Stream) ARtcpPort() int { return s.aRtcpPort }
func (s *Stream) BRtcpPort() int { return s.bRtcpPort }

// allocate binds two consecutive UDP port pairs on localIP — one pair
// for the A side (rtp + rtcp = rtp+1) and one for the B side. The
// consecutive layout means implicit RTCP signaling (no a=rtcp, peer
// computes rtp+1) just works without rewriting the SDP, and explicit
// rewriting can simply emit a=rtcp:<rtcp-port>.
func (s *Stream) allocate(localIP string) error {
	rtp, rtcp, rtpPort, rtcpPort, err := allocateConsecutivePair(localIP)
	if err != nil {
		return fmt.Errorf("allocate A-side: %w", err)
	}
	s.aRtpConn, s.aRtcpConn, s.aRtpPort, s.aRtcpPort = rtp, rtcp, rtpPort, rtcpPort

	rtp, rtcp, rtpPort, rtcpPort, err = allocateConsecutivePair(localIP)
	if err != nil {
		s.aRtpConn.Close()
		s.aRtcpConn.Close()
		return fmt.Errorf("allocate B-side: %w", err)
	}
	s.bRtpConn, s.bRtcpConn, s.bRtpPort, s.bRtcpPort = rtp, rtcp, rtpPort, rtcpPort

	s.lastActivity.Store(time.Now().UnixNano())
	return nil
}

// allocateConsecutivePair binds an RTP socket on a free local port
// and then the next port for RTCP. If the consecutive port is taken,
// it retries with a fresh RTP port. After several attempts it gives
// up — in practice this almost always succeeds on the first try.
func allocateConsecutivePair(localIP string) (rtp, rtcp *net.UDPConn, rtpPort, rtcpPort int, err error) {
	addr := net.ParseIP(localIP)
	const maxAttempts = 50
	for i := 0; i < maxAttempts; i++ {
		rtp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: addr, Port: 0})
		if err != nil {
			return nil, nil, 0, 0, err
		}
		rtpPort = rtp.LocalAddr().(*net.UDPAddr).Port
		rtcp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: addr, Port: rtpPort + 1})
		if err == nil {
			rtcpPort = rtpPort + 1
			return rtp, rtcp, rtpPort, rtcpPort, nil
		}
		rtp.Close()
	}
	return nil, nil, 0, 0, fmt.Errorf("could not allocate consecutive RTP/RTCP port pair after %d attempts", maxAttempts)
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
		s.lastActivity.Store(time.Now().UnixNano())

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
