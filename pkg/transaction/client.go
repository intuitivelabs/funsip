package transaction

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/intuitivelabs/funsip/pkg/sip"
)

type ClientTx struct {
	key       Key
	txType    Type
	request   *sip.Message
	state     State
	mu        sync.Mutex
	transport string
	dest      string
	sendFunc  func(msg *sip.Message, dst string, transport string) error
	onResp    ResponseHandler
	timers    map[string]*time.Timer
	done      chan struct{}
	createdAt time.Time
}

func NewClientInviteTx(
	req *sip.Message,
	dest string,
	transport string,
	sendFunc func(*sip.Message, string, string) error,
	onResp ResponseHandler,
) *ClientTx {
	tx := &ClientTx{
		key:       MakeClientKey(req),
		txType:    TypeICT,
		request:   req,
		state:     StateCalling,
		transport: transport,
		dest:      dest,
		sendFunc:  sendFunc,
		onResp:    onResp,
		timers:    make(map[string]*time.Timer),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	tx.key.IsClient = true

	if err := tx.sendFunc(req, dest, transport); err != nil {
		log.Printf("[ICT] send error: %v", err)
	}

	if transport == "UDP" {
		tx.startTimerA(TimerAInitial)
	}
	tx.startTimerB()

	return tx
}

func NewClientNonInviteTx(
	req *sip.Message,
	dest string,
	transport string,
	sendFunc func(*sip.Message, string, string) error,
	onResp ResponseHandler,
) *ClientTx {
	tx := &ClientTx{
		key:       MakeClientKey(req),
		txType:    TypeNICT,
		request:   req,
		state:     StateTrying,
		transport: transport,
		dest:      dest,
		sendFunc:  sendFunc,
		onResp:    onResp,
		timers:    make(map[string]*time.Timer),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	tx.key.IsClient = true

	if err := tx.sendFunc(req, dest, transport); err != nil {
		log.Printf("[NICT] send error: %v", err)
	}

	if transport == "UDP" {
		tx.startTimerE(TimerE)
	}
	tx.startTimerF()

	return tx
}

func (tx *ClientTx) Key() Key             { return tx.key }
func (tx *ClientTx) Type() Type           { return tx.txType }
func (tx *ClientTx) CreatedAt() time.Time { return tx.createdAt }
func (tx *ClientTx) Dest() string         { return tx.dest }
func (tx *ClientTx) Transport() string    { return tx.transport }

func (tx *ClientTx) State() State {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.state
}

func (tx *ClientTx) Request() *sip.Message { return tx.request }

func (tx *ClientTx) ReceiveResponse(resp *sip.Message) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.state == StateTerminated {
		return
	}

	if tx.txType == TypeICT {
		tx.ictReceiveResponse(resp)
	} else {
		tx.nictReceiveResponse(resp)
	}
}

// RFC3261 Section 17.1.1 - INVITE Client Transaction
func (tx *ClientTx) ictReceiveResponse(resp *sip.Message) {
	code := resp.StatusCode

	switch tx.state {
	case StateCalling:
		if code >= 100 && code < 200 {
			tx.state = StateProceeding
			tx.cancelTimer("A")
			tx.cancelTimer("B")
			tx.onResp(resp)
		} else if code >= 200 && code < 300 {
			tx.state = StateTerminated
			tx.cancelAllTimers()
			tx.onResp(resp)
			tx.terminate()
		} else if code >= 300 {
			tx.state = StateCompleted
			tx.cancelAllTimers()
			tx.onResp(resp)
			tx.sendACK(resp)
			if tx.transport == "UDP" {
				tx.startTimerD()
			} else {
				tx.terminate()
			}
		}

	case StateProceeding:
		if code >= 100 && code < 200 {
			tx.onResp(resp)
		} else if code >= 200 && code < 300 {
			tx.state = StateTerminated
			tx.cancelAllTimers()
			tx.onResp(resp)
			tx.terminate()
		} else if code >= 300 {
			tx.state = StateCompleted
			tx.cancelAllTimers()
			tx.onResp(resp)
			tx.sendACK(resp)
			if tx.transport == "UDP" {
				tx.startTimerD()
			} else {
				tx.terminate()
			}
		}

	case StateCompleted:
		if code >= 300 {
			tx.sendACK(resp)
		}
	}
}

// RFC3261 Section 17.1.2 - Non-INVITE Client Transaction
func (tx *ClientTx) nictReceiveResponse(resp *sip.Message) {
	code := resp.StatusCode

	switch tx.state {
	case StateTrying:
		if code >= 100 && code < 200 {
			tx.state = StateProceeding
			tx.onResp(resp)
		} else if code >= 200 {
			tx.state = StateCompleted
			tx.cancelAllTimers()
			tx.onResp(resp)
			if tx.transport == "UDP" {
				tx.startTimerK()
			} else {
				tx.terminate()
			}
		}

	case StateProceeding:
		if code >= 100 && code < 200 {
			tx.onResp(resp)
		} else if code >= 200 {
			tx.state = StateCompleted
			tx.cancelAllTimers()
			tx.onResp(resp)
			if tx.transport == "UDP" {
				tx.startTimerK()
			} else {
				tx.terminate()
			}
		}
	}
}

func (tx *ClientTx) sendACK(resp *sip.Message) {
	ack := sip.NewRequest("ACK", tx.request.RequestURI.Clone())
	ack.Headers.Set("Via", tx.request.Headers.Get("Via"))
	ack.Headers.Set("From", tx.request.Headers.Get("From"))
	ack.Headers.Set("To", resp.Headers.Get("To"))
	ack.Headers.Set("Call-ID", tx.request.Headers.Get("Call-ID"))
	ack.Headers.Set("CSeq", fmt.Sprintf("%d ACK", tx.request.CSeqNum()))
	ack.Headers.Set("Max-Forwards", "70")
	if err := tx.sendFunc(ack, tx.dest, tx.transport); err != nil {
		log.Printf("[ICT] ACK send error: %v", err)
	}
}

func (tx *ClientTx) startTimerA(d time.Duration) {
	tx.timers["A"] = time.AfterFunc(d, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		if tx.state == StateCalling {
			if err := tx.sendFunc(tx.request, tx.dest, tx.transport); err != nil {
				log.Printf("[ICT] retransmit error: %v", err)
			}
			next := d * 2
			tx.startTimerA(next)
		}
	})
}

func (tx *ClientTx) startTimerB() {
	tx.timers["B"] = time.AfterFunc(TimerB, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		if tx.state == StateCalling {
			tx.state = StateTerminated
			tx.cancelAllTimers()
			resp := sip.CreateResponseFromRequest(tx.request, 408, "Request Timeout")
			tx.onResp(resp)
			tx.terminate()
		}
	})
}

func (tx *ClientTx) startTimerD() {
	tx.timers["D"] = time.AfterFunc(TimerD, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		tx.state = StateTerminated
		tx.terminate()
	})
}

func (tx *ClientTx) startTimerE(d time.Duration) {
	tx.timers["E"] = time.AfterFunc(d, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		if tx.state == StateTrying || tx.state == StateProceeding {
			if err := tx.sendFunc(tx.request, tx.dest, tx.transport); err != nil {
				log.Printf("[NICT] retransmit error: %v", err)
			}
			next := d * 2
			if next > T2 {
				next = T2
			}
			tx.startTimerE(next)
		}
	})
}

func (tx *ClientTx) startTimerF() {
	tx.timers["F"] = time.AfterFunc(TimerF, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		if tx.state == StateTrying || tx.state == StateProceeding {
			tx.state = StateTerminated
			tx.cancelAllTimers()
			resp := sip.CreateResponseFromRequest(tx.request, 408, "Request Timeout")
			tx.onResp(resp)
			tx.terminate()
		}
	})
}

func (tx *ClientTx) startTimerK() {
	tx.timers["K"] = time.AfterFunc(TimerK, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		tx.state = StateTerminated
		tx.terminate()
	})
}

func (tx *ClientTx) cancelTimer(name string) {
	if t, ok := tx.timers[name]; ok {
		t.Stop()
		delete(tx.timers, name)
	}
}

func (tx *ClientTx) cancelAllTimers() {
	for name, t := range tx.timers {
		t.Stop()
		delete(tx.timers, name)
	}
}

func (tx *ClientTx) terminate() {
	select {
	case <-tx.done:
	default:
		close(tx.done)
	}
}

func (tx *ClientTx) Done() <-chan struct{} {
	return tx.done
}
