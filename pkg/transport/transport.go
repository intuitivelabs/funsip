package transport

import (
	"fmt"
	"log"
	"net"
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

type Manager struct {
	udp       *UDPTransport
	tcp       *TCPTransport
	handler   MessageHandler
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

	m.mu.Lock()
	if pkt.Transport == "UDP" {
		m.stats.UDPReceived++
	} else {
		m.stats.TCPReceived++
	}
	m.mu.Unlock()

	m.handler(msg)
}

func (m *Manager) Send(msg *sip.Message, dst string, transport string) error {
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
