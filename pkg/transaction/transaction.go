package transaction

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/funsip/funsip/pkg/sip"
)

const (
	T1 = 500 * time.Millisecond
	T2 = 4 * time.Second
	T4 = 5 * time.Second

	TimerAInitial = T1
	TimerB        = 64 * T1
	TimerD        = 32 * time.Second
	TimerE        = T1
	TimerF        = 64 * T1
	TimerG        = T1
	TimerH        = 64 * T1
	TimerI        = T4
	TimerJ        = 64 * T1
	TimerK        = T4
)

type State int

const (
	StateTrying     State = iota
	StateCalling
	StateProceeding
	StateCompleted
	StateConfirmed
	StateTerminated
)

func (s State) String() string {
	switch s {
	case StateTrying:
		return "Trying"
	case StateCalling:
		return "Calling"
	case StateProceeding:
		return "Proceeding"
	case StateCompleted:
		return "Completed"
	case StateConfirmed:
		return "Confirmed"
	case StateTerminated:
		return "Terminated"
	}
	return "Unknown"
}

type Type int

const (
	TypeICT  Type = iota // INVITE Client Transaction
	TypeNICT             // Non-INVITE Client Transaction
	TypeIST              // INVITE Server Transaction
	TypeNIST             // Non-INVITE Server Transaction
)

func (t Type) String() string {
	switch t {
	case TypeICT:
		return "ICT"
	case TypeNICT:
		return "NICT"
	case TypeIST:
		return "IST"
	case TypeNIST:
		return "NIST"
	}
	return "Unknown"
}

type Key struct {
	Branch    string
	Method    string
	SentBy    string
	IsClient  bool
}

func (k Key) String() string {
	side := "server"
	if k.IsClient {
		side = "client"
	}
	return fmt.Sprintf("%s:%s:%s:%s", side, k.Method, k.Branch, k.SentBy)
}

func MakeServerKey(msg *sip.Message) Key {
	via := msg.TopVia()
	if via == nil {
		return Key{}
	}
	method := msg.Method
	if method == "ACK" {
		method = "INVITE"
	}
	return Key{
		Branch:   via.Branch(),
		Method:   method,
		SentBy:   via.SentBy(),
		IsClient: false,
	}
}

// MakeInviteKeyFromCancel returns the server transaction key of the INVITE
// that the given CANCEL request is targeting, per RFC3261 §9.2 — same Via
// branch and sent-by, method "INVITE".
func MakeInviteKeyFromCancel(cancel *sip.Message) Key {
	via := cancel.TopVia()
	if via == nil {
		return Key{}
	}
	return Key{
		Branch:   via.Branch(),
		Method:   "INVITE",
		SentBy:   via.SentBy(),
		IsClient: false,
	}
}

func MakeClientKey(msg *sip.Message) Key {
	via := msg.TopVia()
	if via == nil {
		return Key{}
	}
	return Key{
		Branch:   via.Branch(),
		Method:   msg.CSeqMethod(),
		SentBy:   via.SentBy(),
		IsClient: true,
	}
}

func GenerateBranch() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "z9hG4bK" + hex.EncodeToString(b)
}

func GenerateTag() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GenerateCallID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func IsMagicBranch(branch string) bool {
	return strings.HasPrefix(branch, "z9hG4bK")
}

type ResponseHandler func(resp *sip.Message)
type RequestHandler func(req *sip.Message)
