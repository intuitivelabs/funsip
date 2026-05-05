package transaction

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/funsip/funsip/pkg/sip"
)

type ServerTx struct {
	key          Key
	txType       Type
	request      *sip.Message
	lastResponse *sip.Message
	state        State
	mu           sync.Mutex
	transport    string
	dest         string
	sendFunc     func(msg *sip.Message, dst string, transport string) error
	timers       map[string]*time.Timer
	done         chan struct{}
	createdAt    time.Time
}

func NewServerInviteTx(
	req *sip.Message,
	sendFunc func(*sip.Message, string, string) error,
) *ServerTx {
	dest := fmt.Sprintf("%s:%d", req.SourceIP, req.SourcePort)
	tx := &ServerTx{
		key:       MakeServerKey(req),
		txType:    TypeIST,
		request:   req,
		state:     StateProceeding,
		transport: req.Transport,
		dest:      dest,
		sendFunc:  sendFunc,
		timers:    make(map[string]*time.Timer),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}

	trying := sip.CreateResponseFromRequest(req, 100, "Trying")
	tx.respond(trying)

	return tx
}

func NewServerNonInviteTx(
	req *sip.Message,
	sendFunc func(*sip.Message, string, string) error,
) *ServerTx {
	dest := fmt.Sprintf("%s:%d", req.SourceIP, req.SourcePort)
	return &ServerTx{
		key:       MakeServerKey(req),
		txType:    TypeNIST,
		request:   req,
		state:     StateTrying,
		transport: req.Transport,
		dest:      dest,
		sendFunc:  sendFunc,
		timers:    make(map[string]*time.Timer),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
}

func (tx *ServerTx) Key() Key         { return tx.key }
func (tx *ServerTx) Type() Type       { return tx.txType }
func (tx *ServerTx) Request() *sip.Message { return tx.request }
func (tx *ServerTx) CreatedAt() time.Time  { return tx.createdAt }

func (tx *ServerTx) State() State {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.state
}

func (tx *ServerTx) Respond(resp *sip.Message) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.state == StateTerminated {
		return
	}

	if tx.txType == TypeIST {
		tx.istRespond(resp)
	} else {
		tx.nistRespond(resp)
	}
}

// RFC3261 Section 17.2.1 - INVITE Server Transaction
func (tx *ServerTx) istRespond(resp *sip.Message) {
	code := resp.StatusCode

	switch tx.state {
	case StateProceeding:
		if code >= 100 && code < 200 {
			tx.respond(resp)
		} else if code >= 200 && code < 300 {
			tx.state = StateTerminated
			tx.respond(resp)
			tx.cancelAllTimers()
			tx.terminate()
		} else if code >= 300 {
			tx.state = StateCompleted
			tx.lastResponse = resp
			tx.respond(resp)
			if tx.transport == "UDP" {
				tx.startTimerG(TimerG)
			}
			tx.startTimerH()
		}

	case StateCompleted:
		// retransmissions handled by ReceiveRequest
	}
}

// RFC3261 Section 17.2.2 - Non-INVITE Server Transaction
func (tx *ServerTx) nistRespond(resp *sip.Message) {
	code := resp.StatusCode

	switch tx.state {
	case StateTrying:
		if code >= 100 && code < 200 {
			tx.state = StateProceeding
			tx.respond(resp)
		} else if code >= 200 {
			tx.state = StateCompleted
			tx.lastResponse = resp
			tx.respond(resp)
			if tx.transport == "UDP" {
				tx.startTimerJ()
			} else {
				tx.terminate()
			}
		}

	case StateProceeding:
		if code >= 100 && code < 200 {
			tx.respond(resp)
		} else if code >= 200 {
			tx.state = StateCompleted
			tx.lastResponse = resp
			tx.respond(resp)
			if tx.transport == "UDP" {
				tx.startTimerJ()
			} else {
				tx.terminate()
			}
		}
	}
}

func (tx *ServerTx) ReceiveRequest(req *sip.Message) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.txType == TypeIST {
		switch tx.state {
		case StateProceeding:
			if tx.lastResponse != nil {
				tx.respond(tx.lastResponse)
			} else {
				trying := sip.CreateResponseFromRequest(req, 100, "Trying")
				tx.respond(trying)
			}
		case StateCompleted:
			if tx.lastResponse != nil {
				tx.respond(tx.lastResponse)
			}
		}
	} else {
		switch tx.state {
		case StateProceeding, StateCompleted:
			if tx.lastResponse != nil {
				tx.respond(tx.lastResponse)
			}
		}
	}
}

func (tx *ServerTx) ReceiveACK() {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.txType == TypeIST && tx.state == StateCompleted {
		tx.state = StateConfirmed
		tx.cancelTimer("G")
		tx.cancelTimer("H")
		if tx.transport == "UDP" {
			tx.startTimerI()
		} else {
			tx.terminate()
		}
	}
}

func (tx *ServerTx) respond(resp *sip.Message) {
	if err := tx.sendFunc(resp, tx.dest, tx.transport); err != nil {
		log.Printf("[%s] send response error: %v", tx.txType, err)
	}
}

func (tx *ServerTx) startTimerG(d time.Duration) {
	tx.timers["G"] = time.AfterFunc(d, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		if tx.state == StateCompleted && tx.lastResponse != nil {
			tx.respond(tx.lastResponse)
			next := d * 2
			if next > T2 {
				next = T2
			}
			tx.startTimerG(next)
		}
	})
}

func (tx *ServerTx) startTimerH() {
	tx.timers["H"] = time.AfterFunc(TimerH, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		if tx.state == StateCompleted {
			tx.state = StateTerminated
			tx.cancelAllTimers()
			tx.terminate()
		}
	})
}

func (tx *ServerTx) startTimerI() {
	tx.timers["I"] = time.AfterFunc(TimerI, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		tx.state = StateTerminated
		tx.terminate()
	})
}

func (tx *ServerTx) startTimerJ() {
	tx.timers["J"] = time.AfterFunc(TimerJ, func() {
		tx.mu.Lock()
		defer tx.mu.Unlock()
		tx.state = StateTerminated
		tx.terminate()
	})
}

func (tx *ServerTx) cancelTimer(name string) {
	if t, ok := tx.timers[name]; ok {
		t.Stop()
		delete(tx.timers, name)
	}
}

func (tx *ServerTx) cancelAllTimers() {
	for name, t := range tx.timers {
		t.Stop()
		delete(tx.timers, name)
	}
}

func (tx *ServerTx) terminate() {
	select {
	case <-tx.done:
	default:
		close(tx.done)
	}
}

func (tx *ServerTx) Done() <-chan struct{} {
	return tx.done
}
