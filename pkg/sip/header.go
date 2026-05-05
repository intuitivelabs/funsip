package sip

import (
	"fmt"
	"strconv"
	"strings"
)

type headerEntry struct {
	name   string
	values []string
}

type Headers struct {
	ordered []*headerEntry
	index   map[string]int
}

func NewHeaders() *Headers {
	return &Headers{
		index: make(map[string]int),
	}
}

func (h *Headers) Clone() *Headers {
	c := NewHeaders()
	for _, e := range h.ordered {
		vals := make([]string, len(e.values))
		copy(vals, e.values)
		c.ordered = append(c.ordered, &headerEntry{name: e.name, values: vals})
		c.index[strings.ToLower(e.name)] = len(c.ordered) - 1
	}
	return c
}

func (h *Headers) Get(name string) string {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		if len(h.ordered[idx].values) > 0 {
			return h.ordered[idx].values[0]
		}
	}
	return ""
}

func (h *Headers) GetAll(name string) []string {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		return h.ordered[idx].values
	}
	return nil
}

func (h *Headers) Set(name, value string) {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		h.ordered[idx].values = []string{value}
		return
	}
	h.ordered = append(h.ordered, &headerEntry{name: name, values: []string{value}})
	h.index[key] = len(h.ordered) - 1
}

func (h *Headers) Add(name, value string) {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		h.ordered[idx].values = append(h.ordered[idx].values, value)
		return
	}
	h.ordered = append(h.ordered, &headerEntry{name: name, values: []string{value}})
	h.index[key] = len(h.ordered) - 1
}

func (h *Headers) Prepend(name, value string) {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		h.ordered[idx].values = append([]string{value}, h.ordered[idx].values...)
		return
	}
	entry := &headerEntry{name: name, values: []string{value}}
	h.ordered = append([]*headerEntry{entry}, h.ordered...)
	h.rebuildIndex()
}

func (h *Headers) Remove(name string) {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		h.ordered = append(h.ordered[:idx], h.ordered[idx+1:]...)
		h.rebuildIndex()
	}
}

// ReplaceFirst replaces the first stored value of the named header in
// place. The header order in the message is preserved. No-op if the
// header is absent.
func (h *Headers) ReplaceFirst(name, value string) bool {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok && len(h.ordered[idx].values) > 0 {
		h.ordered[idx].values[0] = value
		return true
	}
	return false
}

func (h *Headers) RemoveFirst(name string) {
	key := strings.ToLower(name)
	if idx, ok := h.index[key]; ok {
		if len(h.ordered[idx].values) > 1 {
			h.ordered[idx].values = h.ordered[idx].values[1:]
		} else {
			h.ordered = append(h.ordered[:idx], h.ordered[idx+1:]...)
			h.rebuildIndex()
		}
	}
}

func (h *Headers) rebuildIndex() {
	h.index = make(map[string]int, len(h.ordered))
	for i, e := range h.ordered {
		h.index[strings.ToLower(e.name)] = i
	}
}

func (h *Headers) Vias() []*Via {
	vals := h.GetAll("Via")
	var vias []*Via
	for _, v := range vals {
		if via := ParseVia(v); via != nil {
			vias = append(vias, via)
		}
	}
	return vias
}

type Via struct {
	Transport string
	Host      string
	Port      int
	Params    map[string]string
}

func (v *Via) Branch() string {
	return v.Params["branch"]
}

func (v *Via) SentBy() string {
	if v.Port > 0 {
		return fmt.Sprintf("%s:%d", v.Host, v.Port)
	}
	return v.Host
}

func (v *Via) String() string {
	var sb strings.Builder
	sb.WriteString("SIP/2.0/")
	sb.WriteString(v.Transport)
	sb.WriteByte(' ')
	sb.WriteString(v.Host)
	if v.Port > 0 {
		sb.WriteByte(':')
		sb.WriteString(strconv.Itoa(v.Port))
	}
	for k, val := range v.Params {
		sb.WriteByte(';')
		sb.WriteString(k)
		if val != "" {
			sb.WriteByte('=')
			sb.WriteString(val)
		}
	}
	return sb.String()
}

func ParseVia(s string) *Via {
	v := &Via{Params: make(map[string]string)}

	parts := strings.SplitN(strings.TrimSpace(s), " ", 2)
	if len(parts) != 2 {
		return nil
	}

	proto := parts[0]
	protoParts := strings.Split(proto, "/")
	if len(protoParts) == 3 {
		v.Transport = strings.ToUpper(protoParts[2])
	} else {
		v.Transport = "UDP"
	}

	rest := parts[1]
	paramParts := strings.Split(rest, ";")
	hostPart := strings.TrimSpace(paramParts[0])

	if colonIdx := strings.LastIndexByte(hostPart, ':'); colonIdx >= 0 {
		v.Host = hostPart[:colonIdx]
		port, err := strconv.Atoi(hostPart[colonIdx+1:])
		if err == nil {
			v.Port = port
		}
	} else {
		v.Host = hostPart
	}

	for _, p := range paramParts[1:] {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			v.Params[strings.ToLower(kv[0])] = kv[1]
		} else {
			v.Params[strings.ToLower(kv[0])] = ""
		}
	}

	return v
}

type Address struct {
	DisplayName string
	URI         *URI
	Params      map[string]string
}

func (a *Address) Tag() string {
	if a.Params != nil {
		return a.Params["tag"]
	}
	return ""
}

func (a *Address) String() string {
	var sb strings.Builder
	if a.DisplayName != "" {
		sb.WriteByte('"')
		sb.WriteString(a.DisplayName)
		sb.WriteString("\" ")
	}
	sb.WriteByte('<')
	sb.WriteString(a.URI.String())
	sb.WriteByte('>')
	for k, v := range a.Params {
		sb.WriteByte(';')
		sb.WriteString(k)
		if v != "" {
			sb.WriteByte('=')
			sb.WriteString(v)
		}
	}
	return sb.String()
}

func ParseAddress(s string) *Address {
	if s == "" {
		return nil
	}
	a := &Address{Params: make(map[string]string)}

	s = strings.TrimSpace(s)

	var uriStr string
	if langle := strings.IndexByte(s, '<'); langle >= 0 {
		a.DisplayName = strings.Trim(strings.TrimSpace(s[:langle]), "\"")
		rangle := strings.IndexByte(s[langle:], '>')
		if rangle < 0 {
			return nil
		}
		uriStr = s[langle+1 : langle+rangle]
		rest := s[langle+rangle+1:]
		parseAddrParams(a, rest)
	} else {
		if semiIdx := strings.IndexByte(s, ';'); semiIdx >= 0 {
			uriStr = s[:semiIdx]
			parseAddrParams(a, s[semiIdx:])
		} else {
			uriStr = s
		}
	}

	uri, err := ParseURI(uriStr)
	if err != nil {
		return nil
	}
	a.URI = uri
	return a
}

func parseAddrParams(a *Address, s string) {
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			a.Params[strings.ToLower(kv[0])] = kv[1]
		} else {
			a.Params[strings.ToLower(kv[0])] = ""
		}
	}
}

func ParseRouteHeader(s string) *URI {
	s = strings.TrimSpace(s)
	if len(s) > 0 && s[0] == '<' {
		end := strings.IndexByte(s, '>')
		if end > 0 {
			s = s[1:end]
		}
	}
	uri, _ := ParseURI(s)
	return uri
}
