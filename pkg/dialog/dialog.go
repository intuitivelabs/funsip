// Package dialog implements optional dialog-state tracking on top of
// the stateful proxy. A dialog is created from a dialog-initiating
// INVITE (no To-tag) when the routing script calls setupDialog, and
// confirmed when a 2xx response with a To-tag passes through. While a
// dialog is alive the manager:
//
//   - matches in-dialog requests by Call-ID + tag pair so the server
//     can refuse mismatched in-dialog traffic with 481 (dlgGate);
//   - tears down its state and (optionally) closes a per-dialog PCAP
//     file when a BYE arrives;
//   - if no BYE arrives within a configurable timeout (default 61
//     min) it acts as a back-to-back UA, sending a BYE to each side
//     of the call and bumping a "timed-out" counter.
package dialog

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funsip/funsip/pkg/metrics"
	"github.com/funsip/funsip/pkg/pcap"
	"github.com/funsip/funsip/pkg/sip"
	"github.com/funsip/funsip/pkg/transaction"
)

const DefaultTimeout = 61 * time.Minute

type Options struct {
	DlgGate bool
	Pcap    bool
	Timeout time.Duration
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultTimeout
}

// Sender is the subset of the transport manager that the dialog
// manager needs. Decoupled from the proxy so timeouts can fire
// without going back through the script.
type Sender interface {
	Send(msg *sip.Message, dst string, transport string) error
}

type Manager struct {
	dialogs map[string]*Dialog
	mu      sync.RWMutex

	sender       Sender
	metrics      *metrics.Metrics
	pcapDir      string
	localIP      string
	localPort    int
	mediaCleanup func(callID string)

	dlgGate atomic.Bool
}

func NewManager(sender Sender, m *metrics.Metrics, localIP string, localPort int, pcapDir string) *Manager {
	return &Manager{
		dialogs:   make(map[string]*Dialog),
		sender:    sender,
		metrics:   m,
		localIP:   localIP,
		localPort: localPort,
		pcapDir:   pcapDir,
	}
}

// SetMediaCleanup registers a callback invoked when a dialog ends
// via a path that does not naturally tear media down (currently: the
// timeout-driven B2BUA BYE). On a regular BYE the request handler
// already calls Proxy.CleanupMediaForCallID directly.
func (m *Manager) SetMediaCleanup(fn func(callID string)) {
	m.mediaCleanup = fn
}

func (m *Manager) DialogCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.dialogs)
}

// DlgGateActive reports whether at least one setupDialog call has
// enabled dialog gating since the server started.
func (m *Manager) DlgGateActive() bool {
	return m.dlgGate.Load()
}

type Dialog struct {
	CallID string

	caller *side
	callee *side

	confirmed atomic.Bool
	dlgGate   bool
	pcap      *pcap.Writer

	timer   *time.Timer
	timeout time.Duration

	cseq atomic.Int64

	manager *Manager

	mu sync.Mutex
}

type side struct {
	AOR       *sip.URI
	Tag       string
	Contact   *sip.URI
	Addr      string
	Transport string
}

// Setup is called from the script (via setupDialog) on a dialog-
// initiating INVITE. It records the caller side and arms the timeout.
// On confirmation (a 2xx response with To-tag) ConfirmFromResponse
// fills in the callee side.
func (m *Manager) Setup(req *sip.Message, opts Options) (*Dialog, error) {
	if req.Method != "INVITE" {
		return nil, fmt.Errorf("setupDialog: only INVITE is dialog-initiating, got %s", req.Method)
	}
	if opts.DlgGate {
		m.dlgGate.Store(true)
	}

	from := req.From()
	if from == nil || from.URI == nil {
		return nil, fmt.Errorf("setupDialog: missing From")
	}

	to := req.To()
	if to == nil || to.URI == nil {
		return nil, fmt.Errorf("setupDialog: missing To")
	}
	if to.Tag() != "" {
		return nil, fmt.Errorf("setupDialog: request already has To-tag (not dialog-initiating)")
	}

	contacts := req.Contacts()
	var contactURI *sip.URI
	if len(contacts) > 0 && contacts[0].URI != nil {
		contactURI = contacts[0].URI.Clone()
	}

	caller := &side{
		AOR:       from.URI.Clone(),
		Tag:       from.Tag(),
		Contact:   contactURI,
		Addr:      fmt.Sprintf("%s:%d", req.SourceIP, req.SourcePort),
		Transport: req.Transport,
	}

	d := &Dialog{
		CallID:  req.CallID(),
		caller:  caller,
		dlgGate: opts.DlgGate,
		timeout: opts.timeout(),
		manager: m,
	}

	if opts.Pcap && m.pcapDir != "" {
		fname := pcapFilename(req.CallID())
		w, err := pcap.NewWriter(filepath.Join(m.pcapDir, fname))
		if err != nil {
			log.Printf("[dialog] pcap open error: %v", err)
		} else {
			d.pcap = w
		}
	}

	m.mu.Lock()
	if existing, ok := m.dialogs[d.CallID]; ok {
		m.mu.Unlock()
		return existing, nil
	}
	m.dialogs[d.CallID] = d
	m.mu.Unlock()

	if m.metrics != nil {
		m.metrics.RecordDialogCreated()
	}

	d.timer = time.AfterFunc(d.timeout, func() { m.fireTimeout(d) })

	return d, nil
}

// ConfirmFromResponse is called when a response with SDP-confirming
// status (2xx for INVITE) passes through proxy.forwardResponse. If an
// early dialog exists for the Call-ID and the response carries a
// To-tag, the dialog becomes confirmed and the callee side is filled
// in from the response.
func (m *Manager) ConfirmFromResponse(resp *sip.Message) {
	if resp.IsRequest {
		return
	}
	if resp.CSeqMethod() != "INVITE" || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}

	callID := resp.CallID()
	m.mu.RLock()
	d, ok := m.dialogs[callID]
	m.mu.RUnlock()
	if !ok || d.confirmed.Load() {
		return
	}

	to := resp.To()
	if to == nil || to.URI == nil || to.Tag() == "" {
		return
	}
	contacts := resp.Contacts()
	var contactURI *sip.URI
	if len(contacts) > 0 && contacts[0].URI != nil {
		contactURI = contacts[0].URI.Clone()
	}

	d.mu.Lock()
	d.callee = &side{
		AOR:       to.URI.Clone(),
		Tag:       to.Tag(),
		Contact:   contactURI,
		Addr:      fmt.Sprintf("%s:%d", resp.SourceIP, resp.SourcePort),
		Transport: resp.Transport,
	}
	d.mu.Unlock()
	d.confirmed.Store(true)
}

// FindFor returns the dialog matching an in-dialog request, or nil.
// Matching is by Call-ID and unordered tag pair (the request can
// flow in either direction).
func (m *Manager) FindFor(req *sip.Message) *Dialog {
	from := req.From()
	to := req.To()
	if from == nil || to == nil {
		return nil
	}
	fromTag, toTag := from.Tag(), to.Tag()

	m.mu.RLock()
	d, ok := m.dialogs[req.CallID()]
	m.mu.RUnlock()
	if !ok {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.confirmed.Load() {
		// Early dialog: only From-tag exists.
		if fromTag == d.caller.Tag {
			return d
		}
		return nil
	}
	pair := func(a, b string) bool {
		return (a == d.caller.Tag && b == d.callee.Tag) ||
			(a == d.callee.Tag && b == d.caller.Tag)
	}
	if pair(fromTag, toTag) {
		return d
	}
	return nil
}

// Terminate removes the dialog (called on BYE).
func (m *Manager) Terminate(callID string) bool {
	m.mu.Lock()
	d, ok := m.dialogs[callID]
	if ok {
		delete(m.dialogs, callID)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	if d.timer != nil {
		d.timer.Stop()
	}
	if d.pcap != nil {
		d.pcap.Close()
	}
	if m.metrics != nil {
		m.metrics.RecordDialogCompleted()
	}
	return true
}

// CapturePacket records a SIP packet to the per-dialog pcap file if
// the dialog has pcap enabled. peerIP/peerPort is the remote side of
// the wire (source if direction==in, destination if direction==out).
func (m *Manager) CapturePacket(direction string, msg *sip.Message, peerIP string, peerPort int, transportName string) {
	callID := msg.CallID()
	if callID == "" {
		return
	}
	m.mu.RLock()
	d, ok := m.dialogs[callID]
	m.mu.RUnlock()
	if !ok || d.pcap == nil {
		return
	}

	var src, dst net.IP
	var srcPort, dstPort int
	if direction == "in" {
		src = net.ParseIP(peerIP)
		srcPort = peerPort
		dst = net.ParseIP(m.localIP)
		dstPort = m.localPort
	} else {
		src = net.ParseIP(m.localIP)
		srcPort = m.localPort
		dst = net.ParseIP(peerIP)
		dstPort = peerPort
	}

	d.pcap.Capture(time.Now(), src, srcPort, dst, dstPort, msg.Serialize())
}

func (m *Manager) fireTimeout(d *Dialog) {
	m.mu.Lock()
	if _, ok := m.dialogs[d.CallID]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.dialogs, d.CallID)
	m.mu.Unlock()

	d.mu.Lock()
	caller := d.caller
	callee := d.callee
	d.mu.Unlock()

	log.Printf("[dialog] timeout firing for Call-ID %s — sending BYE to both sides", d.CallID)

	if caller != nil && callee != nil {
		baseCSeq := int(d.cseq.Add(1)) + 1_000_000
		m.sendBYE(d.CallID, caller, callee, baseCSeq)
		m.sendBYE(d.CallID, callee, caller, baseCSeq+1)
	}

	if m.mediaCleanup != nil {
		m.mediaCleanup(d.CallID)
	}

	if d.pcap != nil {
		d.pcap.Close()
	}
	if m.metrics != nil {
		m.metrics.RecordDialogTimedOut()
	}
}

// sendBYE constructs a BYE as if "from" sent it to "to" and pushes it
// onto the transport. CSeq is high (>1M) to outrank anything either
// peer is likely to have used in-dialog.
func (m *Manager) sendBYE(callID string, from, to *side, cseq int) {
	rURI := to.Contact
	if rURI == nil {
		rURI = to.AOR
	}
	if rURI == nil {
		log.Printf("[dialog] BYE: no Request-URI for callee side")
		return
	}

	bye := sip.NewRequest("BYE", rURI.Clone())

	branch := transaction.GenerateBranch()
	transport := from.Transport
	if transport == "" {
		transport = "UDP"
	}
	via := fmt.Sprintf("SIP/2.0/%s %s:%d;branch=%s;rport",
		strings.ToUpper(transport), m.localIP, m.localPort, branch)
	bye.Headers.Set("Via", via)
	bye.Headers.Set("Max-Forwards", "70")
	bye.Headers.Set("From", fmt.Sprintf("<%s>;tag=%s", from.AOR, from.Tag))
	bye.Headers.Set("To", fmt.Sprintf("<%s>;tag=%s", to.AOR, to.Tag))
	bye.Headers.Set("Call-ID", callID)
	bye.Headers.Set("CSeq", fmt.Sprintf("%d BYE", cseq))
	bye.Headers.Set("Content-Length", "0")

	dst := to.Addr
	if err := m.sender.Send(bye, dst, transport); err != nil {
		log.Printf("[dialog] BYE send error: %v", err)
	}
}

// pcapFilename returns a filesystem-safe filename for a dialog. Only
// safe characters from the Call-ID are kept; the rest become '_'.
func pcapFilename(callID string) string {
	var b strings.Builder
	b.WriteString("dialog-")
	for _, r := range callID {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '.' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() > 80 {
			break
		}
	}
	b.WriteString("-")
	b.WriteString(strconv.FormatInt(time.Now().UnixNano(), 10))
	b.WriteString(".pcap")
	return b.String()
}

// CloseAll terminates every active dialog, used at server shutdown.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	dialogs := make([]*Dialog, 0, len(m.dialogs))
	for _, d := range m.dialogs {
		dialogs = append(dialogs, d)
	}
	m.dialogs = make(map[string]*Dialog)
	m.mu.Unlock()
	for _, d := range dialogs {
		if d.timer != nil {
			d.timer.Stop()
		}
		if d.pcap != nil {
			d.pcap.Close()
		}
	}
}
