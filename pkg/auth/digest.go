package auth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
)

type DigestAuth struct {
	db    *store.DB
	realm string
}

func NewDigestAuth(db *store.DB, realm string) *DigestAuth {
	return &DigestAuth{db: db, realm: realm}
}

type Challenge struct {
	Realm  string
	Nonce  string
	Opaque string
	Stale  bool
}

func (c *Challenge) String() string {
	s := fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm=MD5, qop="auth"`, c.Realm, c.Nonce, c.Opaque)
	if c.Stale {
		s += `, stale=true`
	}
	return s
}

type Credentials struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string
	Algorithm string
	Opaque    string
	QOP       string
	NC        string
	CNonce    string
}

func ParseAuthorization(s string) *Credentials {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "Digest ") {
		return nil
	}
	s = s[7:]
	c := &Credentials{}

	for _, param := range splitParams(s) {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), "\"")

		switch key {
		case "username":
			c.Username = val
		case "realm":
			c.Realm = val
		case "nonce":
			c.Nonce = val
		case "uri":
			c.URI = val
		case "response":
			c.Response = val
		case "algorithm":
			c.Algorithm = val
		case "opaque":
			c.Opaque = val
		case "qop":
			c.QOP = val
		case "nc":
			c.NC = val
		case "cnonce":
			c.CNonce = val
		}
	}

	return c
}

func splitParams(s string) []string {
	var params []string
	var current strings.Builder
	inQuotes := false

	for _, ch := range s {
		switch {
		case ch == '"':
			inQuotes = !inQuotes
			current.WriteRune(ch)
		case ch == ',' && !inQuotes:
			params = append(params, current.String())
			current.Reset()
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		params = append(params, current.String())
	}
	return params
}

func (a *DigestAuth) Authenticate(req *sip.Message, realm string) (bool, error) {
	if realm == "" {
		realm = a.realm
	}

	authHeader := req.Headers.Get("Authorization")
	if authHeader == "" {
		authHeader = req.Headers.Get("Proxy-Authorization")
	}

	if authHeader == "" {
		return false, nil
	}

	creds := ParseAuthorization(authHeader)
	if creds == nil {
		return false, nil
	}

	sub, err := a.db.GetSubscriber(creds.Username, creds.Realm)
	if err != nil {
		return false, fmt.Errorf("lookup subscriber: %w", err)
	}
	if sub == nil {
		return false, nil
	}

	method := req.Method
	if !req.IsRequest {
		method = req.CSeqMethod()
	}

	expected := computeResponse(sub.HA1, creds.Nonce, creds.NC, creds.CNonce, creds.QOP, method, creds.URI)

	return expected == creds.Response, nil
}

func (a *DigestAuth) CreateChallenge(realm string) *Challenge {
	if realm == "" {
		realm = a.realm
	}
	return &Challenge{
		Realm:  realm,
		Nonce:  generateNonce(),
		Opaque: generateNonce(),
	}
}

func computeResponse(ha1, nonce, nc, cnonce, qop, method, uri string) string {
	ha2 := md5hex(method + ":" + uri)

	if qop == "auth" || qop == "auth-int" {
		return md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	}
	return md5hex(ha1 + ":" + nonce + ":" + ha2)
}

func ComputeHA1(username, realm, password string) string {
	return md5hex(username + ":" + realm + ":" + password)
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	return md5hex(ts + hex.EncodeToString(b))
}
