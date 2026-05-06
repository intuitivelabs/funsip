package transaction

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/funsip/pkg/metrics"
	"github.com/intuitivelabs/funsip/pkg/sip"
)

type Layer struct {
	serverTxs       map[string]*ServerTx
	clientTxs       map[string]*ClientTx
	serverToClients map[string][]string
	inviteTimers    map[string]*time.Timer
	mu              sync.RWMutex
	sendFunc        func(msg *sip.Message, dst string, transport string) error
	metrics         *metrics.Metrics

	onNewRequest RequestHandler

	inviteTimeout time.Duration

	txCreated     atomic.Int64
	txActive      atomic.Int64
	totalRespTime atomic.Int64
	respCount     atomic.Int64
}

// SetInviteTimeout configures the per-INVITE-server-transaction wall
// clock cap. A non-positive value disables the timer and INVITE
// transactions are bound only by RFC3261's state-machine timers.
// Default 3 minutes if not set explicitly.
func (l *Layer) SetInviteTimeout(d time.Duration) {
	l.inviteTimeout = d
}

func NewLayer(sendFunc func(*sip.Message, string, string) error, m *metrics.Metrics) *Layer {
	l := &Layer{
		serverTxs:       make(map[string]*ServerTx),
		clientTxs:       make(map[string]*ClientTx),
		serverToClients: make(map[string][]string),
		inviteTimers:    make(map[string]*time.Timer),
		sendFunc:        sendFunc,
		metrics:         m,
		inviteTimeout:   3 * time.Minute,
	}
	go l.gcLoop()
	return l
}

func (l *Layer) Metrics() *metrics.Metrics { return l.metrics }

func (l *Layer) SetRequestHandler(h RequestHandler) {
	l.onNewRequest = h
}

func (l *Layer) ReceiveMessage(msg *sip.Message) {
	if msg.IsRequest {
		l.receiveRequest(msg)
	} else {
		l.receiveResponse(msg)
	}
}

func (l *Layer) receiveRequest(req *sip.Message) {
	if req.Method == "ACK" {
		l.handleACK(req)
		return
	}

	if l.metrics != nil {
		l.metrics.RecordReceived()
	}

	// RFC3261 §16: a proxy that receives a request without a Max-Forwards
	// header field SHOULD insert one with a value of 70. The forward path
	// later refuses to decrement past zero, which terminates loops.
	if req.MaxForwards() < 0 {
		req.Headers.Set("Max-Forwards", "70")
	}

	if req.Method == "CANCEL" {
		inviteKey := MakeInviteKeyFromCancel(req).String()
		l.mu.RLock()
		inviteSrv, hasInvite := l.serverTxs[inviteKey]
		l.mu.RUnlock()
		if hasInvite {
			l.handleCancelMatched(req, inviteSrv, inviteKey)
			return
		}
	}

	key := MakeServerKey(req)
	keyStr := key.String()

	l.mu.RLock()
	stx, exists := l.serverTxs[keyStr]
	l.mu.RUnlock()

	if exists {
		if l.metrics != nil {
			l.metrics.RecordRetransmission()
		}
		stx.ReceiveRequest(req)
		return
	}

	var tx *ServerTx
	if req.Method == "INVITE" {
		tx = NewServerInviteTx(req, l.sendFunc)
	} else {
		tx = NewServerNonInviteTx(req, l.sendFunc)
	}

	l.mu.Lock()
	l.serverTxs[keyStr] = tx
	l.mu.Unlock()
	l.txCreated.Add(1)
	l.txActive.Add(1)

	// INVITE transactions get an additional wall-clock cap. RFC3261's
	// IST state-machine timers terminate the transaction only after a
	// final response is sent — but a UAS that is forever stuck in
	// Proceeding (no response from upstream) would otherwise live
	// indefinitely. The user-configured InviteTimeout terminates the
	// stalled transaction by 408-ing the UAC and CANCELling pending
	// branches.
	if req.Method == "INVITE" && l.inviteTimeout > 0 {
		stx := tx
		l.armInviteTimeout(keyStr, stx)
	}

	go func() {
		<-tx.Done()
		l.cancelInviteTimer(keyStr)
		l.txActive.Add(-1)
	}()

	log.Printf("[tx-layer] new %s transaction %s for %s", tx.Type(), keyStr, req.Method)

	if l.onNewRequest != nil {
		l.onNewRequest(req)
	}
}

func (l *Layer) handleACK(ack *sip.Message) {
	key := MakeServerKey(ack) // maps to INVITE key
	keyStr := key.String()

	l.mu.RLock()
	stx, exists := l.serverTxs[keyStr]
	l.mu.RUnlock()

	if exists {
		stx.ReceiveACK()
	} else {
		if l.onNewRequest != nil {
			l.onNewRequest(ack)
		}
	}
}

func (l *Layer) receiveResponse(resp *sip.Message) {
	key := MakeClientKey(resp)
	keyStr := key.String()

	l.mu.RLock()
	ctx, exists := l.clientTxs[keyStr]
	l.mu.RUnlock()

	if !exists {
		log.Printf("[tx-layer] no client tx for response %d %s (key=%s)", resp.StatusCode, resp.ReasonPhrase, keyStr)
		return
	}

	if l.metrics != nil {
		l.metrics.RecordResponseReceived(resp.StatusCode)
	}

	if resp.StatusCode >= 200 {
		elapsed := time.Since(ctx.CreatedAt())
		l.totalRespTime.Add(elapsed.Milliseconds())
		l.respCount.Add(1)
	}

	ctx.ReceiveResponse(resp)
}

func (l *Layer) NewClientTx(req *sip.Message, dest string, transport string, onResp ResponseHandler) (*ClientTx, error) {
	return l.newClientTxWithOrigin(nil, req, dest, transport, onResp)
}

// NewClientTxFor is like NewClientTx but records an association between the
// originating server transaction (derived from originReq) and the new client
// transaction. The Layer uses this association to fan CANCEL out to all
// pending branches when an out-of-dialog CANCEL arrives.
func (l *Layer) NewClientTxFor(originReq *sip.Message, fwdReq *sip.Message, dest string, transport string, onResp ResponseHandler) (*ClientTx, error) {
	return l.newClientTxWithOrigin(originReq, fwdReq, dest, transport, onResp)
}

func (l *Layer) newClientTxWithOrigin(originReq *sip.Message, fwdReq *sip.Message, dest string, transport string, onResp ResponseHandler) (*ClientTx, error) {
	var tx *ClientTx
	if fwdReq.Method == "INVITE" {
		tx = NewClientInviteTx(fwdReq, dest, transport, l.sendFunc, onResp)
	} else {
		tx = NewClientNonInviteTx(fwdReq, dest, transport, l.sendFunc, onResp)
	}

	keyStr := tx.Key().String()

	l.mu.Lock()
	l.clientTxs[keyStr] = tx
	l.mu.Unlock()
	l.txCreated.Add(1)
	l.txActive.Add(1)

	if originReq != nil {
		serverKey := MakeServerKey(originReq).String()
		l.mu.Lock()
		l.serverToClients[serverKey] = append(l.serverToClients[serverKey], keyStr)
		l.mu.Unlock()
	}

	go func() {
		<-tx.Done()
		l.txActive.Add(-1)
	}()

	log.Printf("[tx-layer] new client %s transaction %s for %s -> %s", tx.Type(), keyStr, fwdReq.Method, dest)
	return tx, nil
}

// handleCancelMatched implements RFC3261 §9.2 stateful proxy CANCEL handling.
// It is called only when a CANCEL has been matched to a server INVITE
// transaction by Via branch and sent-by.
func (l *Layer) handleCancelMatched(cancel *sip.Message, inviteSrv *ServerTx, inviteKey string) {
	cancelKey := MakeServerKey(cancel).String()

	l.mu.RLock()
	existing, dup := l.serverTxs[cancelKey]
	l.mu.RUnlock()
	if dup {
		if l.metrics != nil {
			l.metrics.RecordRetransmission()
		}
		existing.ReceiveRequest(cancel)
		return
	}

	cancelTx := NewServerNonInviteTx(cancel, l.sendFunc)
	l.mu.Lock()
	l.serverTxs[cancelKey] = cancelTx
	l.mu.Unlock()
	l.txCreated.Add(1)
	l.txActive.Add(1)
	go func() {
		<-cancelTx.Done()
		l.txActive.Add(-1)
	}()

	ok := sip.CreateResponseFromRequest(cancel, 200, "OK")
	cancelTx.Respond(ok)

	l.cancelPendingBranchesForServerKey(inviteKey)

	if inviteSrv.State() == StateProceeding {
		terminated := sip.CreateResponseFromRequest(inviteSrv.Request(), 487, "Request Terminated")
		inviteSrv.Respond(terminated)
	}
}

// CancelPendingBranches sends CANCEL on every INVITE client
// transaction this proxy has created on behalf of originReq's
// server transaction, that is still in Calling or Proceeding state.
// Used by the server's script-timeout handler to abort upstream
// branches before answering 408 to the UAC.
func (l *Layer) CancelPendingBranches(originReq *sip.Message) {
	srvKey := MakeServerKey(originReq).String()
	l.cancelPendingBranchesForServerKey(srvKey)
}

func (l *Layer) cancelPendingBranchesForServerKey(srvKey string) {
	l.mu.RLock()
	keys := append([]string(nil), l.serverToClients[srvKey]...)
	clients := make([]*ClientTx, 0, len(keys))
	for _, k := range keys {
		if c, ok := l.clientTxs[k]; ok {
			clients = append(clients, c)
		}
	}
	l.mu.RUnlock()
	for _, ct := range clients {
		if ct.Type() != TypeICT {
			continue
		}
		state := ct.State()
		if state != StateCalling && state != StateProceeding {
			continue
		}
		l.sendCancelForBranch(ct)
	}
}

// armInviteTimeout starts a single-shot timer that fires after
// l.inviteTimeout and, if the IST is still pending, sends 408 to
// the UAC and CANCEL to every upstream branch.
func (l *Layer) armInviteTimeout(srvKey string, tx *ServerTx) {
	timer := time.AfterFunc(l.inviteTimeout, func() {
		state := tx.State()
		if state != StateProceeding {
			return // already terminated/completed naturally
		}
		log.Printf("[tx-layer] INVITE %s timed out after %v — 408 + CANCEL upstream", srvKey, l.inviteTimeout)
		l.cancelPendingBranchesForServerKey(srvKey)
		resp := sip.CreateResponseFromRequest(tx.Request(), 408, "Request Timeout")
		tx.Respond(resp)
	})
	l.mu.Lock()
	l.inviteTimers[srvKey] = timer
	l.mu.Unlock()
}

func (l *Layer) cancelInviteTimer(srvKey string) {
	l.mu.Lock()
	if t, ok := l.inviteTimers[srvKey]; ok {
		t.Stop()
		delete(l.inviteTimers, srvKey)
	}
	l.mu.Unlock()
}

// sendCancelForBranch constructs and sends a CANCEL request matching the
// given client INVITE transaction (same Via branch, Call-ID, From, To, CSeq
// number and Route set) and creates a NICT for it.
func (l *Layer) sendCancelForBranch(invite *ClientTx) {
	inviteReq := invite.Request()

	cancel := sip.NewRequest("CANCEL", inviteReq.RequestURI.Clone())
	cancel.Headers.Set("Via", inviteReq.Headers.Get("Via"))
	cancel.Headers.Set("From", inviteReq.Headers.Get("From"))
	cancel.Headers.Set("To", inviteReq.Headers.Get("To"))
	cancel.Headers.Set("Call-ID", inviteReq.Headers.Get("Call-ID"))
	cancel.Headers.Set("CSeq", fmt.Sprintf("%d CANCEL", inviteReq.CSeqNum()))
	cancel.Headers.Set("Max-Forwards", "70")
	for _, route := range inviteReq.Headers.GetAll("Route") {
		cancel.Headers.Add("Route", route)
	}

	if _, err := l.NewClientTx(cancel, invite.Dest(), invite.Transport(), func(*sip.Message) {}); err != nil {
		log.Printf("[tx-layer] CANCEL send error: %v", err)
	}
}

func (l *Layer) FindServerTx(msg *sip.Message) *ServerTx {
	key := MakeServerKey(msg)
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.serverTxs[key.String()]
}

func (l *Layer) RespondToRequest(req *sip.Message, resp *sip.Message) {
	stx := l.FindServerTx(req)
	if stx != nil {
		stx.Respond(resp)
	} else {
		dst := fmt.Sprintf("%s:%d", req.SourceIP, req.SourcePort)
		if err := l.sendFunc(resp, dst, req.Transport); err != nil {
			log.Printf("[tx-layer] stateless send error: %v", err)
		}
	}
}

func (l *Layer) gcLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		l.gc()
	}
}

func (l *Layer) gc() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, tx := range l.serverTxs {
		select {
		case <-tx.Done():
			delete(l.serverTxs, k)
			delete(l.serverToClients, k)
		default:
		}
	}

	for k, tx := range l.clientTxs {
		select {
		case <-tx.Done():
			delete(l.clientTxs, k)
		default:
		}
	}

	for srvKey, clientKeys := range l.serverToClients {
		live := clientKeys[:0]
		for _, ck := range clientKeys {
			if _, ok := l.clientTxs[ck]; ok {
				live = append(live, ck)
			}
		}
		if len(live) == 0 {
			delete(l.serverToClients, srvKey)
		} else {
			l.serverToClients[srvKey] = live
		}
	}
}

type LayerStats struct {
	TotalCreated     int64
	Active           int64
	ServerTxCount    int
	ClientTxCount    int
	AvgRespTimeMs    int64
	PendingINVITE    int
	PendingNonINVITE int
}

func (l *Layer) Stats() LayerStats {
	l.mu.RLock()
	serverCount := len(l.serverTxs)
	clientCount := len(l.clientTxs)

	var pendingInvite, pendingNonInvite int
	for _, tx := range l.serverTxs {
		if tx.Type() == TypeIST {
			pendingInvite++
		} else {
			pendingNonInvite++
		}
	}
	for _, tx := range l.clientTxs {
		if tx.Type() == TypeICT {
			pendingInvite++
		} else {
			pendingNonInvite++
		}
	}
	l.mu.RUnlock()

	var avg int64
	count := l.respCount.Load()
	if count > 0 {
		avg = l.totalRespTime.Load() / count
	}

	return LayerStats{
		TotalCreated:     l.txCreated.Load(),
		Active:           l.txActive.Load(),
		ServerTxCount:    serverCount,
		ClientTxCount:    clientCount,
		AvgRespTimeMs:    avg,
		PendingINVITE:    pendingInvite,
		PendingNonINVITE: pendingNonInvite,
	}
}

func (l *Layer) ActiveTransactions() []map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []map[string]interface{}
	for k, tx := range l.serverTxs {
		result = append(result, map[string]interface{}{
			"key":    k,
			"type":   tx.Type().String(),
			"state":  tx.State().String(),
			"method": tx.Request().Method,
			"age_ms": time.Since(tx.CreatedAt()).Milliseconds(),
		})
	}
	for k, tx := range l.clientTxs {
		result = append(result, map[string]interface{}{
			"key":    k,
			"type":   tx.Type().String(),
			"state":  tx.State().String(),
			"method": tx.Request().Method,
			"age_ms": time.Since(tx.CreatedAt()).Milliseconds(),
		})
	}
	return result
}
