package proxy

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/intuitivelabs/funsip/pkg/events"
	"github.com/intuitivelabs/funsip/pkg/media"
	"github.com/intuitivelabs/funsip/pkg/metrics"
	"github.com/intuitivelabs/funsip/pkg/sdp"
	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
	"github.com/intuitivelabs/funsip/pkg/transaction"
)

type Proxy struct {
	txLayer   *transaction.Layer
	localIP   string
	localPort int
	domain    string
	metrics   *metrics.Metrics
	media     *media.Manager
	events    *events.Sink
	mediaDir  string

	confirmDialog func(resp *sip.Message)
}

func (p *Proxy) SetEventSink(s *events.Sink) { p.events = s }

// SetMediaDir configures the directory where the media analyzer
// drops its pcap and wav artifacts. Picked up by anchorMedia from
// the cfg.PCAPDir setting.
func (p *Proxy) SetMediaDir(dir string) { p.mediaDir = dir }

func New(txLayer *transaction.Layer, localIP string, localPort int, domain string, m *metrics.Metrics) *Proxy {
	return &Proxy{
		txLayer:   txLayer,
		localIP:   localIP,
		localPort: localPort,
		domain:    domain,
		metrics:   m,
	}
}

func (p *Proxy) SetMediaManager(m *media.Manager) { p.media = m }
func (p *Proxy) MediaManager() *media.Manager     { return p.media }

// SetDialogConfirm registers a callback invoked once per response
// just before it is forwarded back to the original sender. Used by
// the dialog manager to confirm an early dialog upon a 2xx with a
// To-tag.
func (p *Proxy) SetDialogConfirm(fn func(resp *sip.Message)) {
	p.confirmDialog = fn
}

// ForwardOptions tunes how a single proxy forward is constructed. A
// nil *ForwardOptions means "default": Record-Route the request with
// loose-routing enabled. Setting RecordRoute to false suppresses the
// Record-Route header — appropriate for stateless edge proxies that
// do not need to stay in the signaling path of subsequent in-dialog
// messages.
type ForwardOptions struct {
	RecordRoute bool
}

// recordRouteEnabled returns the effective Record-Route policy. nil
// opts → true (default).
func (o *ForwardOptions) recordRouteEnabled() bool {
	if o == nil {
		return true
	}
	return o.RecordRoute
}

// AnchorMedia parses the SDP body of req, allocates a relay slot per
// media stream, and rewrites the SDP in place so that the connection
// address and ports point to this proxy. The session is keyed by
// Call-ID so that the answer SDP can be rewritten symmetrically when
// the response comes back through forwardResponse.
func (p *Proxy) AnchorMedia(req *sip.Message, opts media.Options) error {
	if p.media == nil {
		return fmt.Errorf("media manager not configured")
	}
	if len(req.Body) == 0 {
		return nil
	}

	parsed, err := sdp.Parse(req.Body)
	if err != nil {
		return fmt.Errorf("parse SDP: %w", err)
	}

	if opts.Dir == "" {
		opts.Dir = p.mediaDir
	}
	sess := p.media.GetOrCreate(req.CallID(), opts)
	if err := sess.AnchorOffer(parsed); err != nil {
		return err
	}

	req.Body = parsed.Bytes()
	req.Headers.Set("Content-Length", strconv.Itoa(len(req.Body)))
	return nil
}

// CleanupMediaForCallID terminates the media session associated with
// the given Call-ID, if any. Used on BYE.
func (p *Proxy) CleanupMediaForCallID(callID string) {
	if p.media == nil {
		return
	}
	p.media.Delete(callID)
}

// emitResponseEvent emits an event for a final SIP response sent on
// behalf of req. Provisional responses (<200) are ignored.
//   - 401 / 407 → auth-failed
//   - INVITE 2xx → call-start
//   - INVITE 3xx-6xx (excluding 401/407) → call-attempt
// Other final responses produce no event.
func (p *Proxy) emitResponseEvent(req *sip.Message, statusCode int, reason string) {
	if p.events == nil || statusCode < 200 {
		return
	}
	switch {
	case statusCode == 401 || statusCode == 407:
		p.events.Send(events.FromRequest("auth-failed", req).WithResponse(statusCode, reason))
	case req.Method == "INVITE" && statusCode >= 200 && statusCode < 300:
		p.events.Send(events.FromRequest("call-start", req).WithResponse(statusCode, reason))
	case req.Method == "INVITE" && statusCode >= 300:
		p.events.Send(events.FromRequest("call-attempt", req).WithResponse(statusCode, reason))
	}
}

func (p *Proxy) recordFinalDelay(req *sip.Message, statusCode int) {
	if p.metrics == nil || statusCode < 200 {
		return
	}
	stx := p.txLayer.FindServerTx(req)
	if stx != nil {
		p.metrics.RecordDelay(time.Since(stx.CreatedAt()).Milliseconds())
	}
}

func (p *Proxy) ForwardRequest(req *sip.Message, dst string, transport string, opts *ForwardOptions) error {
	if p.metrics != nil {
		p.metrics.RecordForwarded()
	}
	fwd := req.Clone()

	mf := fwd.MaxForwards()
	if mf <= 0 {
		resp := sip.CreateResponseFromRequest(req, 483, "Too Many Hops")
		p.txLayer.RespondToRequest(req, resp)
		return nil
	}
	fwd.Headers.Set("Max-Forwards", strconv.Itoa(mf-1))

	branch := transaction.GenerateBranch()
	via := &sip.Via{
		Transport: strings.ToUpper(transport),
		Host:      p.localIP,
		Port:      p.localPort,
		Params: map[string]string{
			"branch": branch,
			"rport":  "",
		},
	}
	fwd.Headers.Prepend("Via", via.String())

	if opts.recordRouteEnabled() {
		rr := fmt.Sprintf("<sip:%s:%d;lr>", p.localIP, p.localPort)
		fwd.Headers.Prepend("Record-Route", rr)
	}

	p.removeProxyAuth(fwd)

	dstHost, dstPort := resolveDestination(dst, transport)
	fullDst := fmt.Sprintf("%s:%d", dstHost, dstPort)

	fwd.RequestURI = &sip.URI{
		Scheme: "sip",
		Host:   dstHost,
		Port:   dstPort,
	}
	if req.RequestURI != nil && req.RequestURI.User != "" {
		fwd.RequestURI.User = req.RequestURI.User
	}

	_, err := p.txLayer.NewClientTxFor(req, fwd, fullDst, transport, func(resp *sip.Message) {
		p.forwardResponse(req, resp)
	})
	return err
}

func (p *Proxy) ForwardToBinding(req *sip.Message, binding *store.Binding, opts *ForwardOptions) error {
	if p.metrics != nil {
		p.metrics.RecordForwarded()
	}
	fwd := req.Clone()

	mf := fwd.MaxForwards()
	if mf <= 0 {
		resp := sip.CreateResponseFromRequest(req, 483, "Too Many Hops")
		p.txLayer.RespondToRequest(req, resp)
		return nil
	}
	fwd.Headers.Set("Max-Forwards", strconv.Itoa(mf-1))

	transport := strings.ToUpper(binding.Transport)
	if transport == "" {
		transport = "UDP"
	}

	branch := transaction.GenerateBranch()
	via := &sip.Via{
		Transport: transport,
		Host:      p.localIP,
		Port:      p.localPort,
		Params: map[string]string{
			"branch": branch,
			"rport":  "",
		},
	}
	fwd.Headers.Prepend("Via", via.String())

	if opts.recordRouteEnabled() {
		rr := fmt.Sprintf("<sip:%s:%d;lr>", p.localIP, p.localPort)
		fwd.Headers.Prepend("Record-Route", rr)
	}

	p.removeProxyAuth(fwd)

	dst := fmt.Sprintf("%s:%d", binding.ReceivedIP, binding.ReceivedPort)

	contactURI, err := sip.ParseURI(binding.Contact)
	if err == nil {
		fwd.RequestURI = contactURI
	}

	_, err = p.txLayer.NewClientTxFor(req, fwd, dst, transport, func(resp *sip.Message) {
		p.forwardResponse(req, resp)
	})
	return err
}

// ForwardToRequestURI forwards req to the host:port encoded in its
// Request-URI without rewriting the URI itself. This is the "send to where
// the request says to go" mode used by proxy() with no arguments.
func (p *Proxy) ForwardToRequestURI(req *sip.Message, opts *ForwardOptions) error {
	if req.RequestURI == nil {
		return fmt.Errorf("forward: no Request-URI")
	}
	if p.metrics != nil {
		p.metrics.RecordForwarded()
	}

	fwd := req.Clone()

	mf := fwd.MaxForwards()
	if mf <= 0 {
		resp := sip.CreateResponseFromRequest(req, 483, "Too Many Hops")
		p.txLayer.RespondToRequest(req, resp)
		return nil
	}
	fwd.Headers.Set("Max-Forwards", strconv.Itoa(mf-1))

	transport := strings.ToUpper(req.RequestURI.Params["transport"])
	if transport == "" {
		transport = "UDP"
	}

	branch := transaction.GenerateBranch()
	via := &sip.Via{
		Transport: transport,
		Host:      p.localIP,
		Port:      p.localPort,
		Params: map[string]string{
			"branch": branch,
			"rport":  "",
		},
	}
	fwd.Headers.Prepend("Via", via.String())

	if opts.recordRouteEnabled() {
		rr := fmt.Sprintf("<sip:%s:%d;lr>", p.localIP, p.localPort)
		fwd.Headers.Prepend("Record-Route", rr)
	}

	p.removeProxyAuth(fwd)

	port := req.RequestURI.Port
	if port == 0 {
		port = 5060
	}
	dst := fmt.Sprintf("%s:%d", req.RequestURI.Host, port)

	dstHost, dstPort := resolveDestination(dst, transport)
	fullDst := fmt.Sprintf("%s:%d", dstHost, dstPort)

	_, err := p.txLayer.NewClientTxFor(req, fwd, fullDst, transport, func(resp *sip.Message) {
		p.forwardResponse(req, resp)
	})
	return err
}

func (p *Proxy) ForwardInDialog(req *sip.Message) error {
	if p.metrics != nil {
		p.metrics.RecordForwarded()
	}
	routes := req.Headers.GetAll("Route")
	if len(routes) == 0 {
		return fmt.Errorf("no Route header for in-dialog request")
	}

	topRoute := sip.ParseRouteHeader(routes[0])
	if topRoute == nil {
		return fmt.Errorf("cannot parse top Route header")
	}

	if p.isOurRoute(topRoute) {
		req.Headers.RemoveFirst("Route")
		routes = req.Headers.GetAll("Route")
	}

	var dst string
	var transport string

	if len(routes) > 0 {
		nextRoute := sip.ParseRouteHeader(routes[0])
		if nextRoute != nil {
			port := nextRoute.Port
			if port == 0 {
				port = 5060
			}
			dst = fmt.Sprintf("%s:%d", nextRoute.Host, port)
			transport = strings.ToUpper(nextRoute.Params["transport"])
		}
	}

	if dst == "" && req.RequestURI != nil {
		port := req.RequestURI.Port
		if port == 0 {
			port = 5060
		}
		dst = fmt.Sprintf("%s:%d", req.RequestURI.Host, port)
	}

	if transport == "" {
		transport = "UDP"
	}

	fwd := req.Clone()

	mf := fwd.MaxForwards()
	if mf <= 0 {
		resp := sip.CreateResponseFromRequest(req, 483, "Too Many Hops")
		p.txLayer.RespondToRequest(req, resp)
		return nil
	}
	fwd.Headers.Set("Max-Forwards", strconv.Itoa(mf-1))

	branch := transaction.GenerateBranch()
	via := &sip.Via{
		Transport: transport,
		Host:      p.localIP,
		Port:      p.localPort,
		Params: map[string]string{
			"branch": branch,
			"rport":  "",
		},
	}
	fwd.Headers.Prepend("Via", via.String())

	p.removeProxyAuth(fwd)

	_, err := p.txLayer.NewClientTxFor(req, fwd, dst, transport, func(resp *sip.Message) {
		p.forwardResponse(req, resp)
	})
	return err
}

func (p *Proxy) forwardResponse(origReq *sip.Message, resp *sip.Message) {
	fwd := resp.Clone()

	vias := fwd.Headers.GetAll("Via")
	if len(vias) > 0 {
		topVia := sip.ParseVia(vias[0])
		if topVia != nil && topVia.Host == p.localIP {
			portMatch := topVia.Port == p.localPort || (topVia.Port == 0 && p.localPort == 5060)
			if portMatch {
				fwd.Headers.RemoveFirst("Via")
			}
		}
	}

	p.maybeAnchorAnswer(fwd)

	if p.confirmDialog != nil {
		p.confirmDialog(fwd)
	}

	p.recordFinalDelay(origReq, fwd.StatusCode)
	p.emitResponseEvent(origReq, fwd.StatusCode, fwd.ReasonPhrase)
	p.txLayer.RespondToRequest(origReq, fwd)
}

// maybeAnchorAnswer rewrites the SDP in resp if a media session is
// active for the corresponding Call-ID. This is the offer/answer
// completion: the offer was already anchored when the request was
// processed, and now we install B's address/port and rewrite the
// answer so that the original sender (A) sends RTP to our relay.
func (p *Proxy) maybeAnchorAnswer(resp *sip.Message) {
	if p.media == nil || len(resp.Body) == 0 {
		return
	}
	sess := p.media.Get(resp.CallID())
	if sess == nil {
		return
	}
	parsed, err := sdp.Parse(resp.Body)
	if err != nil {
		log.Printf("[proxy] answer SDP parse error: %v", err)
		return
	}
	if err := sess.AnchorAnswer(parsed); err != nil {
		log.Printf("[proxy] anchor answer error: %v", err)
		return
	}
	resp.Body = parsed.Bytes()
	resp.Headers.Set("Content-Length", strconv.Itoa(len(resp.Body)))
}

func (p *Proxy) removeProxyAuth(msg *sip.Message) {
	msg.Headers.Remove("Proxy-Authorization")
}

func (p *Proxy) isOurRoute(uri *sip.URI) bool {
	if uri.Host == p.localIP || uri.Host == p.domain {
		port := uri.Port
		if port == 0 {
			port = 5060
		}
		return port == p.localPort
	}
	return false
}

func (p *Proxy) IsInDialog(req *sip.Message) bool {
	toTag := ""
	to := req.To()
	if to != nil {
		toTag = to.Tag()
	}
	return toTag != ""
}

func resolveDestination(dst string, transport string) (string, int) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		addrs, err := net.LookupHost(dst)
		if err == nil && len(addrs) > 0 {
			return addrs[0], 5060
		}
		return dst, 5060
	}

	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 5060
	}

	addrs, err := net.LookupHost(host)
	if err == nil && len(addrs) > 0 {
		host = addrs[0]
	}

	return host, port
}

func (p *Proxy) FixContact(req *sip.Message) {
	contacts := req.Contacts()
	if len(contacts) == 0 {
		return
	}

	for i, c := range contacts {
		if c.URI == nil {
			continue
		}
		c.URI.Host = req.SourceIP
		c.URI.Port = req.SourcePort
		if i == 0 {
			req.Headers.Set("Contact", c.String())
		} else {
			req.Headers.Add("Contact", c.String())
		}
	}
}

func (p *Proxy) SendResponse(req *sip.Message, code int, reason string) {
	if p.metrics != nil && code >= 200 {
		p.metrics.RecordLocallyAnswered()
	}
	resp := sip.CreateResponseFromRequest(req, code, reason)
	p.recordFinalDelay(req, code)
	p.emitResponseEvent(req, code, reason)
	p.txLayer.RespondToRequest(req, resp)
}

func (p *Proxy) SendResponseMsg(req *sip.Message, resp *sip.Message) {
	if p.metrics != nil && resp.StatusCode >= 200 {
		p.metrics.RecordLocallyAnswered()
	}
	p.recordFinalDelay(req, resp.StatusCode)
	p.emitResponseEvent(req, resp.StatusCode, resp.ReasonPhrase)
	p.txLayer.RespondToRequest(req, resp)
}

func (p *Proxy) TxLayer() *transaction.Layer {
	return p.txLayer
}
