package sip

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type Message struct {
	IsRequest    bool
	Method       string
	RequestURI   *URI
	StatusCode   int
	ReasonPhrase string
	SIPVersion   string
	Headers      *Headers
	Body         []byte

	SourceIP   string
	SourcePort int
	Transport  string
}

func NewRequest(method string, ruri *URI) *Message {
	return &Message{
		IsRequest:  true,
		Method:     method,
		RequestURI: ruri,
		SIPVersion: "SIP/2.0",
		Headers:    NewHeaders(),
	}
}

func NewResponse(statusCode int, reason string) *Message {
	return &Message{
		IsRequest:    false,
		StatusCode:   statusCode,
		ReasonPhrase: reason,
		SIPVersion:   "SIP/2.0",
		Headers:      NewHeaders(),
	}
}

func (m *Message) Clone() *Message {
	c := &Message{
		IsRequest:    m.IsRequest,
		Method:       m.Method,
		StatusCode:   m.StatusCode,
		ReasonPhrase: m.ReasonPhrase,
		SIPVersion:   m.SIPVersion,
		SourceIP:     m.SourceIP,
		SourcePort:   m.SourcePort,
		Transport:    m.Transport,
	}
	if m.RequestURI != nil {
		c.RequestURI = m.RequestURI.Clone()
	}
	c.Headers = m.Headers.Clone()
	if m.Body != nil {
		c.Body = make([]byte, len(m.Body))
		copy(c.Body, m.Body)
	}
	return c
}

func (m *Message) CallID() string {
	return m.Headers.Get("Call-ID")
}

func (m *Message) CSeqNum() int {
	cseq := m.Headers.Get("CSeq")
	parts := strings.Fields(cseq)
	if len(parts) < 1 {
		return 0
	}
	n, _ := strconv.Atoi(parts[0])
	return n
}

func (m *Message) CSeqMethod() string {
	cseq := m.Headers.Get("CSeq")
	parts := strings.Fields(cseq)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func (m *Message) TopVia() *Via {
	vias := m.Headers.Vias()
	if len(vias) == 0 {
		return nil
	}
	return vias[0]
}

func (m *Message) From() *Address {
	return ParseAddress(m.Headers.Get("From"))
}

func (m *Message) To() *Address {
	return ParseAddress(m.Headers.Get("To"))
}

func (m *Message) Contacts() []*Address {
	vals := m.Headers.GetAll("Contact")
	var result []*Address
	for _, v := range vals {
		if a := ParseAddress(v); a != nil {
			result = append(result, a)
		}
	}
	return result
}

func (m *Message) ContentLength() int {
	cl := m.Headers.Get("Content-Length")
	if cl == "" {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(cl))
	return n
}

func (m *Message) MaxForwards() int {
	mf := m.Headers.Get("Max-Forwards")
	if mf == "" {
		return -1
	}
	n, _ := strconv.Atoi(strings.TrimSpace(mf))
	return n
}

func (m *Message) Serialize() []byte {
	var buf bytes.Buffer
	if m.IsRequest {
		buf.WriteString(m.Method)
		buf.WriteByte(' ')
		buf.WriteString(m.RequestURI.String())
		buf.WriteByte(' ')
		buf.WriteString(m.SIPVersion)
		buf.WriteString("\r\n")
	} else {
		buf.WriteString(m.SIPVersion)
		buf.WriteByte(' ')
		buf.WriteString(strconv.Itoa(m.StatusCode))
		buf.WriteByte(' ')
		buf.WriteString(m.ReasonPhrase)
		buf.WriteString("\r\n")
	}

	if len(m.Body) > 0 {
		m.Headers.Set("Content-Length", strconv.Itoa(len(m.Body)))
	} else {
		m.Headers.Set("Content-Length", "0")
	}

	for _, kv := range m.Headers.ordered {
		for _, v := range kv.values {
			buf.WriteString(kv.name)
			buf.WriteString(": ")
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}

	buf.WriteString("\r\n")
	if len(m.Body) > 0 {
		buf.Write(m.Body)
	}
	return buf.Bytes()
}

func (m *Message) String() string {
	if m.IsRequest {
		return fmt.Sprintf("%s %s", m.Method, m.RequestURI)
	}
	return fmt.Sprintf("%d %s", m.StatusCode, m.ReasonPhrase)
}

func ParseMessage(data []byte) (*Message, error) {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = bytes.Index(data, []byte("\n\n"))
		if idx < 0 {
			return nil, fmt.Errorf("no header/body separator found")
		}
	}

	headerPart := string(data[:idx])
	var bodyPart []byte
	sepLen := 4
	if data[idx] == '\n' {
		sepLen = 2
	}
	if idx+sepLen < len(data) {
		bodyPart = data[idx+sepLen:]
	}

	lines := splitHeaderLines(headerPart)
	if len(lines) < 1 {
		return nil, fmt.Errorf("empty message")
	}

	msg := &Message{Headers: NewHeaders()}

	firstLine := lines[0]
	if strings.HasPrefix(firstLine, "SIP/") {
		if err := parseStatusLine(msg, firstLine); err != nil {
			return nil, err
		}
	} else {
		if err := parseRequestLine(msg, firstLine); err != nil {
			return nil, err
		}
	}

	for _, line := range lines[1:] {
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		name = expandCompactHeader(name)
		msg.Headers.Add(name, value)
	}

	msg.Body = bodyPart

	return msg, nil
}

func splitHeaderLines(header string) []string {
	raw := strings.Split(header, "\n")
	var lines []string
	for _, r := range raw {
		r = strings.TrimRight(r, "\r")
		if len(r) > 0 && (r[0] == ' ' || r[0] == '\t') && len(lines) > 0 {
			lines[len(lines)-1] += " " + strings.TrimSpace(r)
		} else {
			lines = append(lines, r)
		}
	}
	return lines
}

func parseRequestLine(msg *Message, line string) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid request line: %s", line)
	}
	msg.IsRequest = true
	msg.Method = parts[0]
	uri, err := ParseURI(parts[1])
	if err != nil {
		return fmt.Errorf("invalid request URI: %w", err)
	}
	msg.RequestURI = uri
	msg.SIPVersion = parts[2]
	return nil
}

func parseStatusLine(msg *Message, line string) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid status line: %s", line)
	}
	msg.IsRequest = false
	msg.SIPVersion = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid status code: %s", parts[1])
	}
	msg.StatusCode = code
	if len(parts) == 3 {
		msg.ReasonPhrase = parts[2]
	}
	return nil
}

func expandCompactHeader(name string) string {
	switch name {
	case "v":
		return "Via"
	case "f":
		return "From"
	case "t":
		return "To"
	case "i":
		return "Call-ID"
	case "m":
		return "Contact"
	case "l":
		return "Content-Length"
	case "c":
		return "Content-Type"
	case "k":
		return "Supported"
	case "s":
		return "Subject"
	case "e":
		return "Content-Encoding"
	}
	return name
}

func CreateResponseFromRequest(req *Message, statusCode int, reason string) *Message {
	resp := NewResponse(statusCode, reason)
	for _, v := range req.Headers.GetAll("Via") {
		resp.Headers.Add("Via", v)
	}
	resp.Headers.Set("From", req.Headers.Get("From"))
	resp.Headers.Set("To", req.Headers.Get("To"))
	resp.Headers.Set("Call-ID", req.Headers.Get("Call-ID"))
	resp.Headers.Set("CSeq", req.Headers.Get("CSeq"))
	return resp
}
