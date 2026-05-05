package sip

import (
	"fmt"
	"strconv"
	"strings"
)

type URI struct {
	Scheme  string
	User    string
	Host    string
	Port    int
	Params  map[string]string
	Headers map[string]string
}

func (u *URI) Clone() *URI {
	c := &URI{
		Scheme: u.Scheme,
		User:   u.User,
		Host:   u.Host,
		Port:   u.Port,
	}
	if u.Params != nil {
		c.Params = make(map[string]string, len(u.Params))
		for k, v := range u.Params {
			c.Params[k] = v
		}
	}
	if u.Headers != nil {
		c.Headers = make(map[string]string, len(u.Headers))
		for k, v := range u.Headers {
			c.Headers[k] = v
		}
	}
	return c
}

func (u *URI) HostPort() string {
	if u.Port > 0 {
		return fmt.Sprintf("%s:%d", u.Host, u.Port)
	}
	return u.Host
}

func (u *URI) AOR() string {
	if u.User != "" {
		return fmt.Sprintf("%s:%s@%s", u.Scheme, u.User, u.Host)
	}
	return fmt.Sprintf("%s:%s", u.Scheme, u.Host)
}

func (u *URI) String() string {
	var sb strings.Builder
	sb.WriteString(u.Scheme)
	sb.WriteByte(':')
	if u.User != "" {
		sb.WriteString(u.User)
		sb.WriteByte('@')
	}
	sb.WriteString(u.Host)
	if u.Port > 0 {
		sb.WriteByte(':')
		sb.WriteString(strconv.Itoa(u.Port))
	}
	for k, v := range u.Params {
		sb.WriteByte(';')
		sb.WriteString(k)
		if v != "" {
			sb.WriteByte('=')
			sb.WriteString(v)
		}
	}
	if len(u.Headers) > 0 {
		first := true
		for k, v := range u.Headers {
			if first {
				sb.WriteByte('?')
				first = false
			} else {
				sb.WriteByte('&')
			}
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(v)
		}
	}
	return sb.String()
}

func ParseURI(s string) (*URI, error) {
	u := &URI{Params: make(map[string]string)}

	colonIdx := strings.IndexByte(s, ':')
	if colonIdx < 0 {
		return nil, fmt.Errorf("no scheme in URI: %s", s)
	}
	u.Scheme = strings.ToLower(s[:colonIdx])
	rest := s[colonIdx+1:]

	if hdrIdx := strings.IndexByte(rest, '?'); hdrIdx >= 0 {
		headerPart := rest[hdrIdx+1:]
		rest = rest[:hdrIdx]
		u.Headers = make(map[string]string)
		for _, pair := range strings.Split(headerPart, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				u.Headers[kv[0]] = kv[1]
			}
		}
	}

	if paramIdx := strings.IndexByte(rest, ';'); paramIdx >= 0 {
		paramPart := rest[paramIdx+1:]
		rest = rest[:paramIdx]
		for _, param := range strings.Split(paramPart, ";") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				u.Params[strings.ToLower(kv[0])] = kv[1]
			} else {
				u.Params[strings.ToLower(kv[0])] = ""
			}
		}
	}

	if atIdx := strings.IndexByte(rest, '@'); atIdx >= 0 {
		u.User = rest[:atIdx]
		rest = rest[atIdx+1:]
	}

	if rest == "" {
		return nil, fmt.Errorf("empty host in URI: %s", s)
	}

	if lastColon := strings.LastIndexByte(rest, ':'); lastColon >= 0 {
		portStr := rest[lastColon+1:]
		port, err := strconv.Atoi(portStr)
		if err == nil && port > 0 && port <= 65535 {
			u.Host = rest[:lastColon]
			u.Port = port
		} else {
			u.Host = rest
		}
	} else {
		u.Host = rest
	}

	return u, nil
}
