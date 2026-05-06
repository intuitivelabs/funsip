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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/funsip/pkg/pcap"
	"github.com/intuitivelabs/funsip/pkg/rtp"
	"github.com/intuitivelabs/funsip/pkg/sdp"
)

type Options struct {
	Symmetric   bool
	IdleTimeout time.Duration

	// PCAP captures every received RTP/RTCP datagram on the relay's
	// sockets to a per-Call-ID .pcap file (separate from the SIP
	// signaling pcap that setupDialog opens).
	PCAP bool
	// WAV records the call's audio. For G.711 (PT 0 / 8) the relay
	// decodes payload bytes into 16-bit linear PCM and emits two
	// mono WAV files — one per direction. Other codecs are
	// recognized but not decoded yet.
	WAV bool
	// DTMF parses RFC4733 named telephone events on the audio stream
	// and includes a per-digit report (with the six quality checks)
	// in the call-end event.
	DTMF bool
	// QoS tracks RTP packet loss, inter-arrival jitter and a
	// simplified E-model MoS, included in the call-end event.
	QoS bool

	// Dir is the directory where pcap and wav files are placed.
	// Empty means "no analyzer files" (PCAP / WAV are silently
	// disabled).
	Dir string
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

		stream.configureAnalyzer(s.CallID, m, s.opts)
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
			rate:        8000,
		}
		if err := stream.allocate(s.manager.localIP); err != nil {
			return nil, err
		}
		s.Streams = append(s.Streams, stream)
		stream.start()
	}
	return s.Streams[i], nil
}

// configureAnalyzer is called from AnchorOffer with the parsed media
// descriptor. It picks an audio PT, recognizes a telephone-event PT
// if the SDP advertises one, and sets up pcap / wav / dtmf / qos
// trackers as enabled by the session's options. Idempotent — calling
// it twice (e.g. on a re-INVITE) does not reopen files.
func (s *Stream) configureAnalyzer(callID string, m *sdp.Media, opts Options) {
	// Pick an audio PT we can decode (prefer PCMU, then PCMA), and
	// detect telephone-event from rtpmap.
	var (
		audioPT     uint8
		audioFound  bool
		dtmfPT      uint8
		dtmfFound   bool
		clockRate   uint32 = 8000
	)
	for _, f := range m.Formats {
		pt, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		if !audioFound {
			audioPT = uint8(pt)
			audioFound = true
		}
		if pt == 0 || pt == 8 {
			audioPT = uint8(pt)
			audioFound = true
		}
	}
	for _, a := range m.Attributes {
		if a.Name != "rtpmap" {
			continue
		}
		// Format: "<pt> <encoding-name>/<clock>/[channels]"
		fields := strings.Fields(a.Value)
		if len(fields) < 2 {
			continue
		}
		pt, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		enc := fields[1]
		// e.g. "telephone-event/8000"
		if i := strings.IndexByte(enc, '/'); i >= 0 {
			rateStr := enc[i+1:]
			if j := strings.IndexByte(rateStr, '/'); j >= 0 {
				rateStr = rateStr[:j]
			}
			if r, err := strconv.Atoi(rateStr); err == nil {
				if strings.HasPrefix(strings.ToLower(enc), "telephone-event") {
					dtmfPT = uint8(pt)
					dtmfFound = true
				} else if int(audioPT) == pt {
					clockRate = uint32(r)
				}
			}
		}
	}
	s.audioPT = audioPT
	s.rate = clockRate
	if dtmfFound {
		s.dtmfPT = dtmfPT
		s.hasDTMF = true
	}

	if opts.PCAP && opts.Dir != "" && s.pcap == nil {
		path := filepath.Join(opts.Dir, mediaPcapName(callID))
		w, err := pcap.NewWriter(path)
		if err != nil {
			log.Printf("[media] pcap open error: %v", err)
		} else {
			s.pcap = w
		}
	}
	if opts.WAV && opts.Dir != "" && rtp.IsAudioPT(audioPT) {
		if s.wavA == nil {
			pathA := filepath.Join(opts.Dir, wavName(callID, "a"))
			if w, err := newWavWriter(pathA, clockRate); err == nil {
				s.wavA = w
			} else {
				log.Printf("[media] wav A open error: %v", err)
			}
		}
		if s.wavB == nil {
			pathB := filepath.Join(opts.Dir, wavName(callID, "b"))
			if w, err := newWavWriter(pathB, clockRate); err == nil {
				s.wavB = w
			} else {
				log.Printf("[media] wav B open error: %v", err)
			}
		}
	}
	if opts.DTMF && dtmfFound {
		if s.dtmfA == nil {
			s.dtmfA = newDTMFTracker(dtmfPT, clockRate)
		}
		if s.dtmfB == nil {
			s.dtmfB = newDTMFTracker(dtmfPT, clockRate)
		}
	}
	if opts.QoS {
		if s.qosA == nil {
			s.qosA = newQoSTracker(clockRate)
		}
		if s.qosB == nil {
			s.qosB = newQoSTracker(clockRate)
		}
	}
}

func mediaPcapName(callID string) string {
	return safeFilename("media-"+callID, ".pcap")
}

func wavName(callID, side string) string {
	return safeFilename("audio-"+callID+"-"+side, ".wav")
}

func safeFilename(name, ext string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() > 80 {
			break
		}
	}
	b.WriteString(ext)
	return b.String()
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

// Report aggregates AnalyzerReports across the session's streams.
// Returns nil if no analyzer is active.
func (s *Session) Report() *AnalyzerReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out *AnalyzerReport
	for _, st := range s.Streams {
		r := st.Report()
		if r == nil {
			continue
		}
		if out == nil {
			out = &AnalyzerReport{}
		}
		out.DTMF = append(out.DTMF, r.DTMF...)
		if out.QoS == nil {
			out.QoS = r.QoS
		}
		out.WAV = append(out.WAV, r.WAV...)
		if out.PCAP == "" {
			out.PCAP = r.PCAP
		}
	}
	return out
}

// ReportFor returns the analyzer report for callID, or nil if the
// session is unknown / has no analyzer activity.
func (m *Manager) ReportFor(callID string) *AnalyzerReport {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	s, ok := m.sessions[callID]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return s.Report()
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

	// Analyzer state (only set when at least one of pcap/wav/dtmf/qos
	// is enabled in Options). audioPT / dtmfPT are taken from the SDP
	// so we know how to interpret payloads. Per-direction trackers
	// (`a*` is "B's packets arriving on A-side socket", `b*` is the
	// other way) are nil unless that option is enabled.
	pcap     *pcap.Writer
	wavA     *wavWriter
	wavB     *wavWriter
	dtmfA    *dtmfTracker
	dtmfB    *dtmfTracker
	qosA     *qosTracker
	qosB     *qosTracker
	audioPT  uint8
	dtmfPT   uint8
	hasDTMF  bool
	rate     uint32

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
	// A-side socket: receives from B (so packets here are B's stream
	// in the B→A direction), forwards to A using B-side socket.
	go s.relay(s.aRtpConn, s.bRtpConn,
		&s.bSrcRTP, &s.aSrcRTP, &s.aSDPRTP, "A-side RTP", 'B', true)
	go s.relay(s.aRtcpConn, s.bRtcpConn,
		&s.bSrcRTCP, &s.aSrcRTCP, &s.aSDPRTCP, "A-side RTCP", 'B', false)

	// B-side socket: receives from A (A's stream A→B), forwards to B.
	go s.relay(s.bRtpConn, s.aRtpConn,
		&s.aSrcRTP, &s.bSrcRTP, &s.bSDPRTP, "B-side RTP", 'A', true)
	go s.relay(s.bRtcpConn, s.aRtcpConn,
		&s.aSrcRTCP, &s.bSrcRTCP, &s.bSDPRTCP, "B-side RTCP", 'A', false)
}

// relay reads packets on `in`, stores the source address in
// `srcStore` (so that the OTHER direction can latch onto it for
// symmetric mode), runs the optional analyzer hooks (PCAP capture,
// DTMF tracker, QoS tracker, WAV decode-and-write), looks up the
// destination via `peerSrcStore` (symmetric) or `peerSDPStore`
// (asymmetric), and writes the packet on `out`.
//
// `speaker` identifies whose stream we're relaying — 'A' if packets
// here are A's voice, 'B' if they are B's voice — so the per-side
// analyzer state is updated correctly.
func (s *Stream) relay(
	in, out *net.UDPConn,
	srcStore, peerSrcStore *atomic.Pointer[net.UDPAddr],
	peerSDPStore *atomic.Pointer[net.UDPAddr],
	label string,
	speaker rune,
	isRTP bool,
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

		// Analyzer hooks. PCAP captures the wire bytes verbatim. RTP
		// parsing happens once and is shared by DTMF, QoS, and WAV.
		if s.pcap != nil {
			localAddr, _ := in.LocalAddr().(*net.UDPAddr)
			if localAddr != nil {
				s.pcap.Capture(time.Now(), src.IP, src.Port, localAddr.IP, localAddr.Port, buf[:n])
			}
		}
		if isRTP {
			s.observeRTP(speaker, buf[:n])
		}

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

// observeRTP parses the header and dispatches to the per-side
// analyzer trackers. speaker is the originator of these packets
// (the side whose voice we're recording / measuring).
func (s *Stream) observeRTP(speaker rune, buf []byte) {
	if s.dtmfA == nil && s.dtmfB == nil && s.qosA == nil && s.qosB == nil &&
		s.wavA == nil && s.wavB == nil {
		return
	}
	h := rtp.Parse(buf)
	if h == nil {
		return
	}
	payload := buf[h.PayloadOffset:]
	now := time.Now()

	switch speaker {
	case 'A':
		if s.dtmfA != nil {
			s.dtmfA.Observe(h, payload)
		}
		if s.qosA != nil && (!s.hasDTMF || h.PayloadType != s.dtmfPT) {
			s.qosA.Observe(h, now)
		}
		if s.wavA != nil && h.PayloadType == s.audioPT {
			s.wavA.Push(decodeAudio(h.PayloadType, payload))
		}
	case 'B':
		if s.dtmfB != nil {
			s.dtmfB.Observe(h, payload)
		}
		if s.qosB != nil && (!s.hasDTMF || h.PayloadType != s.dtmfPT) {
			s.qosB.Observe(h, now)
		}
		if s.wavB != nil && h.PayloadType == s.audioPT {
			s.wavB.Push(decodeAudio(h.PayloadType, payload))
		}
	}
}

func decodeAudio(pt uint8, payload []byte) []int16 {
	switch pt {
	case rtp.PTPCMU:
		return rtp.DecodePCMU(payload)
	case rtp.PTPCMA:
		return rtp.DecodePCMA(payload)
	}
	return nil
}

// Report builds an AnalyzerReport snapshot for this stream from the
// active trackers and file paths. Safe to call before Close — for
// example from the dialog manager when emitting a call-end event.
func (s *Stream) Report() *AnalyzerReport {
	if s == nil {
		return nil
	}
	r := &AnalyzerReport{}
	if s.dtmfA != nil {
		r.DTMF = append(r.DTMF, s.dtmfA.Flush()...)
	}
	if s.dtmfB != nil {
		r.DTMF = append(r.DTMF, s.dtmfB.Flush()...)
	}
	// QoS — if both sides exist, return whichever has activity.
	// Calls are usually symmetric so we'd report the same MoS for
	// both directions; reporting one avoids redundancy.
	if rep := s.qosA.Report(); rep != nil && rep.PacketsReceived > 0 {
		r.QoS = rep
	} else if rep := s.qosB.Report(); rep != nil && rep.PacketsReceived > 0 {
		r.QoS = rep
	}
	if s.wavA != nil {
		r.WAV = append(r.WAV, s.wavA.Path())
	}
	if s.wavB != nil {
		r.WAV = append(r.WAV, s.wavB.Path())
	}
	if s.pcap != nil {
		r.PCAP = s.pcap.Path()
	}
	if len(r.DTMF) == 0 && r.QoS == nil && len(r.WAV) == 0 && r.PCAP == "" {
		return nil
	}
	return r
}

func (s *Stream) Close() {
	if s.closed.Swap(true) {
		return
	}
	s.closeAll()
	if s.wavA != nil {
		s.wavA.Close()
	}
	if s.wavB != nil {
		s.wavB.Close()
	}
	if s.pcap != nil {
		s.pcap.Close()
	}
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
