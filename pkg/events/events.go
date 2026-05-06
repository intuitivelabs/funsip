// Package events emits SIP-domain events (call-start, call-end,
// auth-failed, …) over HTTP POST to a configured collector URL.
//
// Emission is fire-and-forget: callers drop events onto a bounded
// channel and a single worker goroutine drains the channel,
// JSON-encodes each event and POSTs it. If the channel is full or the
// HTTP call fails, the event is dropped and a counter is bumped — the
// SIP / RTP hot path is never blocked on disk or network I/O.
package events

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
)

// Event mirrors the shape of the example events in
// /Users/jirikuthan/tmp/eventsamples/* — a flat top-level "type",
// "type2", "@timestamp" plus an "attrs" map and a nested "sip"
// object. Probe-specific cruft (geoip, agent, dbg, rate, …) is
// intentionally omitted — those are observability metadata for a
// different pipeline.
type Event struct {
	Timestamp string                 `json:"@timestamp"`
	Type      string                 `json:"type"`
	Type2     string                 `json:"type2"`
	Attrs     map[string]interface{} `json:"attrs"`
	Client    *Endpoint              `json:"client,omitempty"`
	Server    *Endpoint              `json:"server,omitempty"`
	SIP       *SIPInfo               `json:"sip,omitempty"`
	EventInfo map[string]interface{} `json:"event,omitempty"`
}

type Endpoint struct {
	IP        string `json:"ip,omitempty"`
	Port      int    `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
}

type SIPInfo struct {
	CallID     string        `json:"call_id,omitempty"`
	Contact    string        `json:"contact,omitempty"`
	From       string        `json:"from,omitempty"`
	FromTag    string        `json:"fromtag,omitempty"`
	To         string        `json:"to,omitempty"`
	ToTag      string        `json:"totag,omitempty"`
	Reason     string        `json:"sip_reason,omitempty"`
	Originator string        `json:"originator,omitempty"`
	Request    *RequestInfo  `json:"request,omitempty"`
	Response   *ResponseInfo `json:"response,omitempty"`
}

type RequestInfo struct {
	Method string `json:"method"`
}

type ResponseInfo struct {
	Status int `json:"status"`
}

// ----- Builders -----

// FromRequest returns an Event with the common attrs/sip/client
// fields filled in from the SIP request.
func FromRequest(eventType string, req *sip.Message) *Event {
	transport := strings.ToLower(req.Transport)
	e := &Event{
		Timestamp: now(),
		Type:      "event",
		Type2:     eventType,
		Attrs: map[string]interface{}{
			"type":      eventType,
			"method":    req.Method,
			"call-id":   req.CallID(),
			"source":    req.SourceIP,
			"src-port":  req.SourcePort,
			"transport": transport,
		},
		Client: &Endpoint{
			IP:        req.SourceIP,
			Port:      req.SourcePort,
			Transport: transport,
		},
		SIP: &SIPInfo{
			CallID:  req.CallID(),
			Request: &RequestInfo{Method: req.Method},
		},
	}

	if from := req.From(); from != nil && from.URI != nil {
		e.Attrs["from"] = from.URI.String()
		e.Attrs["from-domain"] = from.URI.Host
		e.SIP.From = from.URI.String()
		e.SIP.FromTag = from.Tag()
	}
	if to := req.To(); to != nil && to.URI != nil {
		e.Attrs["to"] = to.URI.String()
		e.SIP.To = to.URI.String()
		if t := to.Tag(); t != "" {
			e.SIP.ToTag = t
		}
	}
	if req.RequestURI != nil {
		e.Attrs["r-uri"] = req.RequestURI.String()
	}
	if ua := req.Headers.Get("User-Agent"); ua != "" {
		e.Attrs["from-ua"] = ua
	}
	if cs := req.Contacts(); len(cs) > 0 && cs[0].URI != nil {
		c := cs[0].URI.String()
		e.Attrs["contact"] = c
		e.SIP.Contact = c
	}
	return e
}

// WithResponse adds the response status / reason fields.
func (e *Event) WithResponse(statusCode int, reason string) *Event {
	e.Attrs["sip-code"] = statusCode
	e.Attrs["reason"] = reason
	if e.SIP == nil {
		e.SIP = &SIPInfo{}
	}
	e.SIP.Response = &ResponseInfo{Status: statusCode}
	e.SIP.Reason = reason
	return e
}

// WithDuration adds call-end duration fields and the originator label
// ("caller-terminated", "callee-terminated", "timeout").
func (e *Event) WithDuration(d time.Duration, originator string) *Event {
	secs := int64(d.Seconds())
	e.Attrs["duration"] = secs
	if e.EventInfo == nil {
		e.EventInfo = map[string]interface{}{}
	}
	e.EventInfo["duration"] = secs
	if originator != "" {
		if e.SIP == nil {
			e.SIP = &SIPInfo{}
		}
		e.SIP.Originator = originator
	}
	return e
}

// FromBinding returns an Event for a registrar-emitted situation
// (reg-new, reg-del, reg-expired). Optional `req` carries SIP-level
// context for reg-new/reg-del; reg-expired typically has no request.
func FromBinding(eventType string, b *store.Binding, req *sip.Message) *Event {
	e := &Event{
		Timestamp: now(),
		Type:      "event",
		Type2:     eventType,
		Attrs: map[string]interface{}{
			"type":      eventType,
			"call-id":   b.CallID,
			"contact":   b.Contact,
			"source":    b.ReceivedIP,
			"src-port":  b.ReceivedPort,
			"transport": strings.ToLower(b.Transport),
		},
		Client: &Endpoint{
			IP:        b.ReceivedIP,
			Port:      b.ReceivedPort,
			Transport: strings.ToLower(b.Transport),
		},
		SIP: &SIPInfo{
			CallID:  b.CallID,
			Contact: b.Contact,
			Request: &RequestInfo{Method: "REGISTER"},
		},
	}
	if b.UserAgent != "" {
		e.Attrs["from-ua"] = b.UserAgent
	}
	e.Attrs["aor"] = b.AOR
	if !b.ExpiresAt.IsZero() {
		e.Attrs["expires_at"] = b.ExpiresAt.UTC().Format(time.RFC3339)
	}

	if req != nil {
		if from := req.From(); from != nil && from.URI != nil {
			e.Attrs["from"] = from.URI.String()
			e.Attrs["from-domain"] = from.URI.Host
			e.SIP.From = from.URI.String()
			e.SIP.FromTag = from.Tag()
		}
		if to := req.To(); to != nil && to.URI != nil {
			e.Attrs["to"] = to.URI.String()
			e.SIP.To = to.URI.String()
		}
		if req.RequestURI != nil {
			e.Attrs["r-uri"] = req.RequestURI.String()
		}
	}
	return e
}

// ----- Sink -----

const defaultQueueSize = 1024

// Sink is a non-blocking event-to-HTTP forwarder. Send() never
// blocks; on overflow the event is dropped and a counter
// incremented. A single worker goroutine drains the queue and POSTs
// each event as a JSON body to the configured URL.
type Sink struct {
	url   string
	httpc *http.Client
	queue chan *Event
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
		queue: make(chan *Event, defaultQueueSize),
		done:  make(chan struct{}),
	}
	go s.worker()
	return s
}

// Send attempts to enqueue an event. Returns immediately. Drops
// silently if the queue is full, the sink is closed, or the URL is
// not configured.
func (s *Sink) Send(e *Event) {
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

func (s *Sink) post(e *Event) {
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
// queue. Subsequent Send() calls are no-ops.
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
