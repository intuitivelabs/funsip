package registrar

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/funsip/funsip/pkg/sip"
	"github.com/funsip/funsip/pkg/store"
)

const DefaultExpires = 3600

type Registrar struct {
	db *store.DB
}

func New(db *store.DB) *Registrar {
	return &Registrar{db: db}
}

func (r *Registrar) ProcessRegister(req *sip.Message) *sip.Message {
	toAddr := req.To()
	if toAddr == nil || toAddr.URI == nil {
		return sip.CreateResponseFromRequest(req, 400, "Bad Request")
	}

	aor := toAddr.URI.AOR()
	contacts := req.Contacts()

	expires := getExpires(req)

	if len(contacts) == 0 {
		return r.queryBindings(req, aor)
	}

	for _, contact := range contacts {
		if contact.URI == nil {
			continue
		}

		contactStr := contact.URI.String()
		contactExpires := expires

		if ce, ok := contact.Params["expires"]; ok {
			if n, err := strconv.Atoi(ce); err == nil {
				contactExpires = n
			}
		}

		if contactStr == "*" && contactExpires == 0 {
			if err := r.db.DeleteAllBindings(aor); err != nil {
				log.Printf("[registrar] delete all bindings error: %v", err)
				return sip.CreateResponseFromRequest(req, 500, "Server Internal Error")
			}
			log.Printf("[registrar] de-registered all contacts for %s", aor)
			continue
		}

		if contactExpires == 0 {
			if err := r.db.DeleteBinding(aor, contactStr); err != nil {
				log.Printf("[registrar] delete binding error: %v", err)
			}
			log.Printf("[registrar] de-registered %s for %s", contactStr, aor)
			continue
		}

		binding := &store.Binding{
			AOR:          aor,
			Contact:      contactStr,
			ExpiresAt:    time.Now().Add(time.Duration(contactExpires) * time.Second),
			ReceivedIP:   req.SourceIP,
			ReceivedPort: req.SourcePort,
			Transport:    req.Transport,
			UserAgent:    req.Headers.Get("User-Agent"),
			CallID:       req.CallID(),
			CSeq:         req.CSeqNum(),
		}

		if err := r.db.SaveBinding(binding); err != nil {
			log.Printf("[registrar] save binding error: %v", err)
			return sip.CreateResponseFromRequest(req, 500, "Server Internal Error")
		}
		log.Printf("[registrar] registered %s -> %s (expires %ds)", aor, contactStr, contactExpires)
	}

	return r.queryBindings(req, aor)
}

func (r *Registrar) queryBindings(req *sip.Message, aor string) *sip.Message {
	bindings, err := r.db.LookupBindings(aor)
	if err != nil {
		log.Printf("[registrar] lookup error: %v", err)
		return sip.CreateResponseFromRequest(req, 500, "Server Internal Error")
	}

	resp := sip.CreateResponseFromRequest(req, 200, "OK")

	for _, b := range bindings {
		remaining := int(time.Until(b.ExpiresAt).Seconds())
		if remaining < 0 {
			remaining = 0
		}

		contactURI := b.Contact
		if b.ReceivedIP != "" && b.ReceivedPort > 0 {
			contactURI = fmt.Sprintf("sip:%s@%s:%d;transport=%s",
				extractUser(b.Contact), b.ReceivedIP, b.ReceivedPort, strings.ToLower(b.Transport))
		}

		resp.Headers.Add("Contact", fmt.Sprintf("<%s>;expires=%d", contactURI, remaining))
	}

	return resp
}

func (r *Registrar) Lookup(uri *sip.URI) ([]*store.Binding, error) {
	aor := uri.AOR()
	return r.db.LookupBindings(aor)
}

func getExpires(req *sip.Message) int {
	exp := req.Headers.Get("Expires")
	if exp != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(exp)); err == nil {
			return n
		}
	}
	return DefaultExpires
}

func extractUser(contactURI string) string {
	u, err := sip.ParseURI(contactURI)
	if err != nil {
		return ""
	}
	return u.User
}
