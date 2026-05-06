package registrar

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/funsip/pkg/events"
	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
)

const (
	DefaultExpires       = 3600
	defaultExpirySweep   = 60 * time.Second
)

type Registrar struct {
	db            *store.DB
	events        *events.Sink
	sweepInterval time.Duration
	stopSweep     chan struct{}
	stopped       atomic.Bool
}

// SetEventSink wires the event sink. Safe to call once before
// significant traffic — there is no synchronization on the field
// because Set is called during server startup.
func (r *Registrar) SetEventSink(s *events.Sink) { r.events = s }

// SetSweepInterval changes how often the registrar scans for expired
// bindings. Intended for tests; production code uses the default.
func (r *Registrar) SetSweepInterval(d time.Duration) { r.sweepInterval = d }

func New(db *store.DB) *Registrar {
	r := &Registrar{
		db:            db,
		sweepInterval: defaultExpirySweep,
		stopSweep:     make(chan struct{}),
	}
	go r.expiryLoop()
	return r
}

// Stop terminates the expiry sweeper goroutine. Safe to call more
// than once.
func (r *Registrar) Stop() {
	if r.stopped.Swap(true) {
		return
	}
	close(r.stopSweep)
}

// expiryLoop periodically removes expired bindings and emits
// reg-expired events for each.
func (r *Registrar) expiryLoop() {
	for {
		t := time.NewTimer(r.sweepInterval)
		select {
		case <-t.C:
			r.SweepExpired()
		case <-r.stopSweep:
			t.Stop()
			return
		}
	}
}

// SweepExpired removes expired bindings and emits reg-expired events.
// Exposed for tests so they don't have to wait on the periodic timer.
func (r *Registrar) SweepExpired() {
	expired, err := r.db.ExpireBindings()
	if err != nil {
		log.Printf("[registrar] expiry sweep error: %v", err)
		return
	}
	for _, b := range expired {
		log.Printf("[registrar] expired %s -> %s", b.AOR, b.Contact)
		if r.events != nil {
			r.events.Send(events.FromBinding("reg-expired", b, nil))
		}
	}
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
			// Capture the bindings about to be removed so we can emit
			// one reg-del event per actually-deleted contact.
			toDelete, _ := r.db.LookupBindings(aor)
			if err := r.db.DeleteAllBindings(aor); err != nil {
				log.Printf("[registrar] delete all bindings error: %v", err)
				return sip.CreateResponseFromRequest(req, 500, "Server Internal Error")
			}
			log.Printf("[registrar] de-registered all contacts for %s", aor)
			if r.events != nil {
				for _, b := range toDelete {
					r.events.Send(events.FromBinding("reg-del", b, req))
				}
			}
			continue
		}

		if contactExpires == 0 {
			binding := &store.Binding{
				AOR:          aor,
				Contact:      contactStr,
				ReceivedIP:   req.SourceIP,
				ReceivedPort: req.SourcePort,
				Transport:    req.Transport,
				UserAgent:    req.Headers.Get("User-Agent"),
				CallID:       req.CallID(),
			}
			if err := r.db.DeleteBinding(aor, contactStr); err != nil {
				log.Printf("[registrar] delete binding error: %v", err)
			}
			log.Printf("[registrar] de-registered %s for %s", contactStr, aor)
			if r.events != nil {
				r.events.Send(events.FromBinding("reg-del", binding, req))
			}
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
		if r.events != nil {
			r.events.Send(events.FromBinding("reg-new", binding, req))
		}
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
