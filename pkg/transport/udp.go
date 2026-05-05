package transport

import (
	"fmt"
	"log"
	"net"
)

type UDPTransport struct {
	conn    *net.UDPConn
	handler func(Packet)
	done    chan struct{}
}

func NewUDPTransport(ip string, port int, handler func(Packet)) (*UDPTransport, error) {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}

	t := &UDPTransport{
		conn:    conn,
		handler: handler,
		done:    make(chan struct{}),
	}

	go t.readLoop()
	return t, nil
}

func (t *UDPTransport) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				log.Printf("[udp] read error: %v", err)
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		t.handler(Packet{
			Data:       data,
			RemoteAddr: remoteAddr,
			LocalAddr:  t.conn.LocalAddr(),
			Transport:  "UDP",
		})
	}
}

func (t *UDPTransport) Send(data []byte, dst string) error {
	addr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		return err
	}
	_, err = t.conn.WriteToUDP(data, addr)
	return err
}

func (t *UDPTransport) Stop() {
	close(t.done)
	t.conn.Close()
}
