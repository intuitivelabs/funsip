// Package sdp implements a minimal RFC4566 / RFC3264 / RFC3605 SDP
// parser and serializer sufficient for media anchoring (rewriting the
// connection address and media ports of an offer/answer).
package sdp

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type SDP struct {
	Version    string
	Origin     string
	SessionName string
	Info       string
	URI        string
	Email      string
	Phone      string
	Connection *Connection
	Bandwidth  []string
	Times      []string
	Repeats    []string
	Zone       string
	Key        string
	Attributes []Attribute
	Media      []*Media
}

type Connection struct {
	NetType  string // "IN"
	AddrType string // "IP4" or "IP6"
	Address  string
}

func (c *Connection) String() string {
	return fmt.Sprintf("%s %s %s", c.NetType, c.AddrType, c.Address)
}

type Attribute struct {
	Name  string
	Value string // empty for property attributes (a=sendrecv etc.)
}

type Media struct {
	Type       string // audio, video, ...
	Port       int
	PortCount  int    // optional /N
	Proto      string // RTP/AVP, RTP/SAVP, ...
	Formats    []string
	Info       string
	Connection *Connection
	Bandwidth  []string
	Key        string
	Attributes []Attribute
}

// RTCPAttr returns (port, addr, true) if the media has an a=rtcp:
// attribute (RFC3605). addr may be empty.
func (m *Media) RTCPAttr() (int, string, bool) {
	for _, a := range m.Attributes {
		if a.Name != "rtcp" {
			continue
		}
		fields := strings.Fields(a.Value)
		if len(fields) == 0 {
			return 0, "", false
		}
		port, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0, "", false
		}
		addr := ""
		if len(fields) >= 4 {
			addr = fields[3]
		}
		return port, addr, true
	}
	return 0, "", false
}

func (m *Media) SetRTCPAttr(port int, addr string) {
	value := strconv.Itoa(port)
	if addr != "" {
		value = fmt.Sprintf("%d IN IP4 %s", port, addr)
	}
	for i, a := range m.Attributes {
		if a.Name == "rtcp" {
			m.Attributes[i].Value = value
			return
		}
	}
	m.Attributes = append(m.Attributes, Attribute{Name: "rtcp", Value: value})
}

func (m *Media) HasAttr(name string) bool {
	for _, a := range m.Attributes {
		if a.Name == name {
			return true
		}
	}
	return false
}

func Parse(data []byte) (*SDP, error) {
	s := &SDP{}
	var current *Media

	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		key := line[0]
		value := string(line[2:])

		switch key {
		case 'v':
			s.Version = value
		case 'o':
			s.Origin = value
		case 's':
			s.SessionName = value
		case 'i':
			if current != nil {
				current.Info = value
			} else {
				s.Info = value
			}
		case 'u':
			s.URI = value
		case 'e':
			s.Email = value
		case 'p':
			s.Phone = value
		case 'c':
			conn, err := parseConnection(value)
			if err != nil {
				continue
			}
			if current != nil {
				current.Connection = conn
			} else {
				s.Connection = conn
			}
		case 'b':
			if current != nil {
				current.Bandwidth = append(current.Bandwidth, value)
			} else {
				s.Bandwidth = append(s.Bandwidth, value)
			}
		case 't':
			s.Times = append(s.Times, value)
		case 'r':
			s.Repeats = append(s.Repeats, value)
		case 'z':
			s.Zone = value
		case 'k':
			if current != nil {
				current.Key = value
			} else {
				s.Key = value
			}
		case 'a':
			attr := parseAttribute(value)
			if current != nil {
				current.Attributes = append(current.Attributes, attr)
			} else {
				s.Attributes = append(s.Attributes, attr)
			}
		case 'm':
			m, err := parseMedia(value)
			if err != nil {
				continue
			}
			current = m
			s.Media = append(s.Media, m)
		}
	}

	return s, nil
}

func parseConnection(s string) (*Connection, error) {
	parts := strings.Fields(s)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid c= line: %q", s)
	}
	return &Connection{NetType: parts[0], AddrType: parts[1], Address: parts[2]}, nil
}

func parseMedia(s string) (*Media, error) {
	parts := strings.Fields(s)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid m= line: %q", s)
	}
	m := &Media{Type: parts[0], Proto: parts[2]}

	portStr := parts[1]
	if slash := strings.IndexByte(portStr, '/'); slash > 0 {
		cnt, _ := strconv.Atoi(portStr[slash+1:])
		m.PortCount = cnt
		portStr = portStr[:slash]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in m= line: %q", parts[1])
	}
	m.Port = port

	if len(parts) > 3 {
		m.Formats = parts[3:]
	}
	return m, nil
}

func parseAttribute(s string) Attribute {
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		return Attribute{Name: s[:colon], Value: s[colon+1:]}
	}
	return Attribute{Name: s}
}

func (s *SDP) Bytes() []byte {
	var b bytes.Buffer
	if s.Version == "" {
		b.WriteString("v=0\r\n")
	} else {
		fmt.Fprintf(&b, "v=%s\r\n", s.Version)
	}
	if s.Origin != "" {
		fmt.Fprintf(&b, "o=%s\r\n", s.Origin)
	}
	if s.SessionName == "" {
		b.WriteString("s=-\r\n")
	} else {
		fmt.Fprintf(&b, "s=%s\r\n", s.SessionName)
	}
	if s.Info != "" {
		fmt.Fprintf(&b, "i=%s\r\n", s.Info)
	}
	if s.URI != "" {
		fmt.Fprintf(&b, "u=%s\r\n", s.URI)
	}
	if s.Email != "" {
		fmt.Fprintf(&b, "e=%s\r\n", s.Email)
	}
	if s.Phone != "" {
		fmt.Fprintf(&b, "p=%s\r\n", s.Phone)
	}
	if s.Connection != nil {
		fmt.Fprintf(&b, "c=%s\r\n", s.Connection)
	}
	for _, bw := range s.Bandwidth {
		fmt.Fprintf(&b, "b=%s\r\n", bw)
	}
	if len(s.Times) == 0 {
		b.WriteString("t=0 0\r\n")
	} else {
		for _, t := range s.Times {
			fmt.Fprintf(&b, "t=%s\r\n", t)
		}
	}
	for _, r := range s.Repeats {
		fmt.Fprintf(&b, "r=%s\r\n", r)
	}
	if s.Zone != "" {
		fmt.Fprintf(&b, "z=%s\r\n", s.Zone)
	}
	if s.Key != "" {
		fmt.Fprintf(&b, "k=%s\r\n", s.Key)
	}
	writeAttrs(&b, s.Attributes)
	for _, m := range s.Media {
		writeMedia(&b, m)
	}
	return b.Bytes()
}

func writeAttrs(b *bytes.Buffer, attrs []Attribute) {
	for _, a := range attrs {
		if a.Value == "" {
			fmt.Fprintf(b, "a=%s\r\n", a.Name)
		} else {
			fmt.Fprintf(b, "a=%s:%s\r\n", a.Name, a.Value)
		}
	}
}

func writeMedia(b *bytes.Buffer, m *Media) {
	port := strconv.Itoa(m.Port)
	if m.PortCount > 0 {
		port = fmt.Sprintf("%d/%d", m.Port, m.PortCount)
	}
	fmt.Fprintf(b, "m=%s %s %s", m.Type, port, m.Proto)
	for _, f := range m.Formats {
		fmt.Fprintf(b, " %s", f)
	}
	b.WriteString("\r\n")
	if m.Info != "" {
		fmt.Fprintf(b, "i=%s\r\n", m.Info)
	}
	if m.Connection != nil {
		fmt.Fprintf(b, "c=%s\r\n", m.Connection)
	}
	for _, bw := range m.Bandwidth {
		fmt.Fprintf(b, "b=%s\r\n", bw)
	}
	if m.Key != "" {
		fmt.Fprintf(b, "k=%s\r\n", m.Key)
	}
	writeAttrs(b, m.Attributes)
}
