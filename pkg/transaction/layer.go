package transaction

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funsip/funsip/pkg/sip"
)

type Layer struct {
	serverTxs map[string]*ServerTx
	clientTxs map[string]*ClientTx
	mu        sync.RWMutex
	sendFunc  func(msg *sip.Message, dst string, transport string) error

	onNewRequest RequestHandler

	txCreated  atomic.Int64
	txActive   atomic.Int64
	totalRespTime atomic.Int64
	respCount  atomic.Int64
}

func NewLayer(sendFunc func(*sip.Message, string, string) error) *Layer {
	l := &Layer{
		serverTxs: make(map[string]*ServerTx),
		clientTxs: make(map[string]*ClientTx),
		sendFunc:  sendFunc,
	}
	go l.gcLoop()
	return l
}

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

	key := MakeServerKey(req)
	keyStr := key.String()

	l.mu.RLock()
	stx, exists := l.serverTxs[keyStr]
	l.mu.RUnlock()

	if exists {
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

	go func() {
		<-tx.Done()
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

	if resp.StatusCode >= 200 {
		elapsed := time.Since(ctx.CreatedAt())
		l.totalRespTime.Add(elapsed.Milliseconds())
		l.respCount.Add(1)
	}

	ctx.ReceiveResponse(resp)
}

func (l *Layer) NewClientTx(req *sip.Message, dest string, transport string, onResp ResponseHandler) (*ClientTx, error) {
	var tx *ClientTx
	if req.Method == "INVITE" {
		tx = NewClientInviteTx(req, dest, transport, l.sendFunc, onResp)
	} else {
		tx = NewClientNonInviteTx(req, dest, transport, l.sendFunc, onResp)
	}

	key := tx.Key()
	keyStr := key.String()

	l.mu.Lock()
	l.clientTxs[keyStr] = tx
	l.mu.Unlock()
	l.txCreated.Add(1)
	l.txActive.Add(1)

	go func() {
		<-tx.Done()
		l.txActive.Add(-1)
	}()

	log.Printf("[tx-layer] new client %s transaction %s for %s -> %s", tx.Type(), keyStr, req.Method, dest)
	return tx, nil
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
}

type LayerStats struct {
	TotalCreated  int64
	Active        int64
	ServerTxCount int
	ClientTxCount int
	AvgRespTimeMs int64
}

func (l *Layer) Stats() LayerStats {
	l.mu.RLock()
	serverCount := len(l.serverTxs)
	clientCount := len(l.clientTxs)
	l.mu.RUnlock()

	var avg int64
	count := l.respCount.Load()
	if count > 0 {
		avg = l.totalRespTime.Load() / count
	}

	return LayerStats{
		TotalCreated:  l.txCreated.Load(),
		Active:        l.txActive.Load(),
		ServerTxCount: serverCount,
		ClientTxCount: clientCount,
		AvgRespTimeMs: avg,
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
