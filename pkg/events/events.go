// Package events emits SIP-domain events (call-start, call-end,
// auth-failed, …) over HTTP POST to a configured collector URL,
// using the wire format from
// github.com/intuitivelabs/sipcallmon / sipcmbeat — flat top-level
// keys with dot-separated names that downstream consumers
// (Elasticsearch, etc.) parse into nested objects.
//
// Emission is fire-and-forget: callers drop events onto a bounded
// channel and a single worker goroutine drains the channel,
// JSON-encodes each event and POSTs it. If the channel is full or the
// HTTP call fails, the event is dropped and a counter is bumped — the
// SIP / RTP hot path is never blocked on disk or network I/O.
package events

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
)

// Event is a flat dotted-key envelope. The keys match the field
// names used by sipcallmon/sipcmbeat so events emitted by funsip
// can be ingested by the same downstream pipeline. A few examples
// of the keys it carries:
//
//	type                 (event type: call-start, call-end, …)
//	@timestamp
//	sip.call_id
//	sip.fromtag / sip.totag
//	sip.request.method
//	sip.request.sig      (compact request signature, see Signature())
//	sip.response.status / sip.response.last
//	sip.originator       (caller-terminated / callee-terminated / timeout-terminated)
//	event.duration       (seconds, for call-end)
//	event.media          (DTMF / QoS / WAV / PCAP report)
//	event.filename       (for playAudio sessions)
//	client.ip / client.port / client.transport
//	attrs.aor / attrs.from / attrs.to / attrs.contact …
type Event map[string]interface{}

// Type returns the event-type label ("call-start", "auth-failed", …)
// or "" if unset. Convenience helper for tests / collectors.
func (e Event) Type() string {
	if e == nil {
		return ""
	}
	if v, ok := e["type"].(string); ok {
		return v
	}
	return ""
}

// Set sets one dotted-key field. Returns the event for chaining.
func (e Event) Set(key string, value interface{}) Event {
	e[key] = value
	return e
}

// ----- Builders -----

// FromRequest returns an Event with sip.* / client.* / attrs.*
// populated from a SIP request. The caller fills in the response
// fields (WithResponse) and duration (WithDuration) as appropriate.
func FromRequest(eventType string, req *sip.Message) Event {
	transport := strings.ToLower(req.Transport)
	e := Event{
		"@timestamp":          now(),
		"type":                eventType,
		"sip.call_id":         req.CallID(),
		"sip.request.method":  req.Method,
		"sip.request.sig":     Signature(req),
		"client.ip":           req.SourceIP,
		"client.port":         req.SourcePort,
		"client.transport":    transport,
		// attrs.* mirror the most useful identification fields so
		// they can be queried without dragging in the full sip.* tree.
		"attrs.method":     req.Method,
		"attrs.call-id":    req.CallID(),
		"attrs.source":     req.SourceIP,
		"attrs.src-port":   req.SourcePort,
		"attrs.transport":  transport,
	}

	if from := req.From(); from != nil && from.URI != nil {
		e["sip.from"] = from.URI.String()
		e["sip.fromtag"] = from.Tag()
		e["attrs.from"] = from.URI.String()
		e["attrs.from-domain"] = from.URI.Host
	}
	if to := req.To(); to != nil && to.URI != nil {
		e["sip.to"] = to.URI.String()
		if t := to.Tag(); t != "" {
			e["sip.totag"] = t
		}
		e["attrs.to"] = to.URI.String()
	}
	if req.RequestURI != nil {
		e["sip.request.uri"] = req.RequestURI.String()
		e["attrs.r-uri"] = req.RequestURI.String()
	}
	if ua := req.Headers.Get("User-Agent"); ua != "" {
		e["sip.user_agent"] = ua
		e["attrs.from-ua"] = ua
	}
	if cs := req.Contacts(); len(cs) > 0 && cs[0].URI != nil {
		c := cs[0].URI.String()
		e["sip.contact"] = c
		e["attrs.contact"] = c
	}
	return e
}

// WithResponse adds sip.response.status / sip.response.last / reason
// (and the convenience attrs.sip-code mirror).
func (e Event) WithResponse(statusCode int, reason string) Event {
	e["sip.response.status"] = statusCode
	e["sip.response.last"] = statusCode
	e["sip.reason"] = reason
	e["attrs.sip-code"] = statusCode
	e["attrs.reason"] = reason
	return e
}

// WithDuration adds the call-end duration (seconds) and originator
// label ("caller-terminated", "callee-terminated", "timeout-terminated").
func (e Event) WithDuration(d time.Duration, originator string) Event {
	secs := int64(d.Seconds())
	e["event.duration"] = secs
	e["attrs.duration"] = secs
	if originator != "" {
		e["sip.originator"] = originator
	}
	return e
}

// FromBinding builds an event for a registrar-emitted situation
// (reg-new, reg-del, reg-expired). The originating SIP request is
// optional and supplies extra context when available.
func FromBinding(eventType string, b *store.Binding, req *sip.Message) Event {
	e := Event{
		"@timestamp":         now(),
		"type":               eventType,
		"sip.call_id":        b.CallID,
		"sip.contact":        b.Contact,
		"sip.request.method": "REGISTER",
		"client.ip":          b.ReceivedIP,
		"client.port":        b.ReceivedPort,
		"client.transport":   strings.ToLower(b.Transport),
		"attrs.aor":          b.AOR,
		"attrs.call-id":      b.CallID,
		"attrs.contact":      b.Contact,
		"attrs.source":       b.ReceivedIP,
		"attrs.src-port":     b.ReceivedPort,
		"attrs.transport":    strings.ToLower(b.Transport),
	}
	if b.UserAgent != "" {
		e["sip.user_agent"] = b.UserAgent
		e["attrs.from-ua"] = b.UserAgent
	}
	if !b.ExpiresAt.IsZero() {
		e["attrs.expires_at"] = b.ExpiresAt.UTC().Format(time.RFC3339)
	}

	if req != nil {
		e["sip.request.sig"] = Signature(req)
		if from := req.From(); from != nil && from.URI != nil {
			e["sip.from"] = from.URI.String()
			e["sip.fromtag"] = from.Tag()
			e["attrs.from"] = from.URI.String()
			e["attrs.from-domain"] = from.URI.Host
		}
		if to := req.To(); to != nil && to.URI != nil {
			e["sip.to"] = to.URI.String()
			e["attrs.to"] = to.URI.String()
		}
		if req.RequestURI != nil {
			e["sip.request.uri"] = req.RequestURI.String()
			e["attrs.r-uri"] = req.RequestURI.String()
		}
	}
	return e
}

// ----- Signature -----

// Signature returns a compact stable fingerprint of a SIP request,
// matching the *intent* (but not the exact byte format) of sipsp's
// MsgSig: a short string that captures the method, the order and
// case of the headers the UA chose, and structural digests of the
// identity fields (Call-ID, From-tag, Via branch).
//
// Format:
//
//	<METHOD>:<hdrcodes>:<cidhash>
//
// where hdrcodes is a sequence of single letters per occurrence of
// a recognized header in the order they appear in the request
// (uppercase = long form, lowercase = compact form):
//
//	V/v = Via       F/f = From        T/t = To
//	I/i = Call-ID   C   = CSeq        O/m = Contact
//	M   = Max-Forwards    U   = User-Agent
//
// and cidhash is the first 12 hex digits of SHA-1 over
// (method || call-id || from-tag || via-branch). Different UAs end
// up with very different signatures; the same UA placing the same
// call shape yields the same signature across calls.
func Signature(req *sip.Message) string {
	if req == nil {
		return ""
	}
	var hdrCodes strings.Builder
	for _, h := range req.Headers.Names() {
		c := hdrCode(h)
		if c == 0 {
			continue
		}
		hdrCodes.WriteByte(c)
	}

	h := sha1.New()
	h.Write([]byte(req.Method))
	h.Write([]byte{0})
	h.Write([]byte(req.CallID()))
	h.Write([]byte{0})
	if from := req.From(); from != nil {
		h.Write([]byte(from.Tag()))
	}
	h.Write([]byte{0})
	if via := req.TopVia(); via != nil {
		h.Write([]byte(via.Branch()))
	}
	sum := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s:%s:%s", req.Method, hdrCodes.String(), sum[:12])
}

// hdrCode returns the signature letter for a header name. Returns
// 0 for headers we don't include in the signature.
func hdrCode(name string) byte {
	// The header-names list comes from the parser already
	// canonicalized to long form (Headers.Names()), so we only need
	// to map the long names. Compact-form detection would need a
	// separate hook in the parser to remember the wire form.
	switch strings.ToLower(name) {
	case "via":
		return 'V'
	case "from":
		return 'F'
	case "to":
		return 'T'
	case "call-id":
		return 'I'
	case "cseq":
		return 'C'
	case "contact":
		return 'O'
	case "max-forwards":
		return 'M'
	case "user-agent":
		return 'U'
	}
	return 0
}

// ----- Sink -----

const defaultQueueSize = 1024

// Sink is a non-blocking event-to-HTTP forwarder. Send never
// blocks; on overflow the event is dropped and a counter
// incremented. A single worker goroutine drains the queue and POSTs
// each event as a JSON body to the configured URL.
type Sink struct {
	url   string
	httpc *http.Client
	queue chan Event
	done  chan struct{}

	closed   atomic.Bool
	enqueued atomic.Uint64
	posted   atomic.Uint64
	dropped  atomic.Uint64
	failed   atomic.Uint64
}

// NewSink starts a worker goroutine that POSTs events to url. If url
// is empty Send() is a no-op and stats remain zero — this is the
// "events disabled" mode.
func NewSink(url string) *Sink {
	s := &Sink{
		url:   strings.TrimSpace(url),
		httpc: &http.Client{Timeout: 5 * time.Second},
		queue: make(chan Event, defaultQueueSize),
		done:  make(chan struct{}),
	}
	go s.worker()
	return s
}

// Send attempts to enqueue an event. Returns immediately. Drops
// silently if the queue is full, the sink is closed, or the URL is
// not configured.
func (s *Sink) Send(e Event) {
	if s == nil || e == nil {
		return
	}
	if s.url == "" || s.closed.Load() {
		return
	}
	select {
	case s.queue <- e:
		s.enqueued.Add(1)
	default:
		s.dropped.Add(1)
	}
}

func (s *Sink) worker() {
	for e := range s.queue {
		s.post(e)
	}
	close(s.done)
}

func (s *Sink) post(e Event) {
	body, err := json.Marshal(e)
	if err != nil {
		s.failed.Add(1)
		return
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		s.failed.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpc.Do(req)
	if err != nil {
		s.failed.Add(1)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		s.failed.Add(1)
		return
	}
	s.posted.Add(1)
}

// Close stops the worker after draining whatever is already in the
// queue. Subsequent Send calls are no-ops.
func (s *Sink) Close() {
	if s.closed.Swap(true) {
		return
	}
	close(s.queue)
	<-s.done
	if posted := s.posted.Load(); posted > 0 {
		log.Printf("[events] sink closed, posted=%d dropped=%d failed=%d",
			posted, s.dropped.Load(), s.failed.Load())
	}
}

type Stats struct {
	URL      string
	Enqueued uint64
	Posted   uint64
	Dropped  uint64
	Failed   uint64
}

func (s *Sink) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{
		URL:      s.url,
		Enqueued: s.enqueued.Load(),
		Posted:   s.posted.Load(),
		Dropped:  s.dropped.Load(),
		Failed:   s.failed.Load(),
	}
}

func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }
