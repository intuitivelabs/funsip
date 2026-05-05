package transport

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/funsip/funsip/pkg/sip"
)

type Packet struct {
	Data       []byte
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Transport  string
}

type MessageHandler func(msg *sip.Message)

// CaptureHook is called for every SIP message that crosses the
// transport boundary. direction is "in" or "out"; peerHost/peerPort
// is the remote peer for that direction.
type CaptureHook func(direction string, msg *sip.Message, peerHost string, peerPort int, transport string)

type Manager struct {
	udp       *UDPTransport
	tcp       *TCPTransport
	handler   MessageHandler
	capture   CaptureHook
	localIP   string
	localPort int
	mu        sync.RWMutex
	stats     Stats
}

type Stats struct {
	UDPReceived  uint64
	UDPSent      uint64
	TCPReceived  uint64
	TCPSent      uint64
	ParseErrors  uint64
}

func NewManager(localIP string, localPort int, handler MessageHandler) *Manager {
	return &Manager{
		localIP:   localIP,
		localPort: localPort,
		handler:   handler,
	}
}

func (m *Manager) SetCaptureHook(h CaptureHook) {
	m.capture = h
}

func (m *Manager) Start() error {
	var err error

	m.udp, err = NewUDPTransport(m.localIP, m.localPort, m.onPacket)
	if err != nil {
		return fmt.Errorf("UDP transport: %w", err)
	}

	m.tcp, err = NewTCPTransport(m.localIP, m.localPort, m.onPacket)
	if err != nil {
		m.udp.Stop()
		return fmt.Errorf("TCP transport: %w", err)
	}

	log.Printf("[transport] listening on %s:%d (UDP+TCP)", m.localIP, m.localPort)
	return nil
}

func (m *Manager) Stop() {
	if m.udp != nil {
		m.udp.Stop()
	}
	if m.tcp != nil {
		m.tcp.Stop()
	}
}

func (m *Manager) onPacket(pkt Packet) {
	msg, err := sip.ParseMessage(pkt.Data)
	if err != nil {
		m.mu.Lock()
		m.stats.ParseErrors++
		m.mu.Unlock()
		log.Printf("[transport] parse error from %s: %v", pkt.RemoteAddr, err)
		return
	}

	host, port, _ := net.SplitHostPort(pkt.RemoteAddr.String())
	msg.SourceIP = host
	fmt.Sscanf(port, "%d", &msg.SourcePort)
	msg.Transport = pkt.Transport

	if msg.IsRequest {
		applyReceivedRport(msg)
	}

	if m.capture != nil {
		m.capture("in", msg, msg.SourceIP, msg.SourcePort, msg.Transport)
	}

	m.mu.Lock()
	if pkt.Transport == "UDP" {
		m.stats.UDPReceived++
	} else {
		m.stats.TCPReceived++
	}
	m.mu.Unlock()

	m.handler(msg)
}

// applyReceivedRport implements RFC3261 §18.2.1 (received) and RFC3581
// (rport) on receive: if the source IP differs from the sent-by host
// in the topmost Via, add a received= parameter; if rport is present
// (with empty value), set it to the actual source port.
func applyReceivedRport(msg *sip.Message) {
	vias := msg.Headers.GetAll("Via")
	if len(vias) == 0 {
		return
	}
	top := sip.ParseVia(vias[0])
	if top == nil {
		return
	}

	changed := false
	if top.Host != msg.SourceIP {
		top.Params["received"] = msg.SourceIP
		changed = true
	}
	if val, has := top.Params["rport"]; has && val == "" {
		top.Params["rport"] = strconv.Itoa(msg.SourcePort)
		changed = true
	}

	if changed {
		msg.Headers.ReplaceFirst("Via", top.String())
	}
}

func (m *Manager) Send(msg *sip.Message, dst string, transport string) error {
	if m.capture != nil {
		host, portStr, err := net.SplitHostPort(dst)
		if err == nil {
			port, _ := strconv.Atoi(portStr)
			m.capture("out", msg, host, port, transport)
		}
	}

	data := msg.Serialize()

	switch transport {
	case "UDP", "udp":
		if m.udp == nil {
			return fmt.Errorf("UDP transport not available")
		}
		err := m.udp.Send(data, dst)
		if err == nil {
			m.mu.Lock()
			m.stats.UDPSent++
			m.mu.Unlock()
		}
		return err
	case "TCP", "tcp":
		if m.tcp == nil {
			return fmt.Errorf("TCP transport not available")
		}
		err := m.tcp.Send(data, dst)
		if err == nil {
			m.mu.Lock()
			m.stats.TCPSent++
			m.mu.Unlock()
		}
		return err
	default:
		return fmt.Errorf("unsupported transport: %s", transport)
	}
}

func (m *Manager) LocalIP() string   { return m.localIP }
func (m *Manager) LocalPort() int    { return m.localPort }

func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}
