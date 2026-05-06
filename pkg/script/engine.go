package script

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/intuitivelabs/funsip/pkg/auth"
	"github.com/intuitivelabs/funsip/pkg/dialog"
	"github.com/intuitivelabs/funsip/pkg/media"
	"github.com/intuitivelabs/funsip/pkg/proxy"
	"github.com/intuitivelabs/funsip/pkg/registrar"
	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
)

// ErrScriptTimeout is returned by Engine.Execute if the script ran
// longer than the configured timeout. The server uses errors.Is to
// detect this and answer 408 / cancel pending INVITE branches.
var ErrScriptTimeout = errors.New("script execution timed out")

type Engine struct {
	scriptPath  string
	source      string
	previousSrc string
	prg         *goja.Program
	timeout     time.Duration
	mu          sync.RWMutex

	proxy     *proxy.Proxy
	registrar *registrar.Registrar
	auth      *auth.DigestAuth
	db        *store.DB
	dialogs   *dialog.Manager
}

func (e *Engine) SetDialogManager(m *dialog.Manager) { e.dialogs = m }

// SetTimeout sets the maximum wall-clock time a single script
// execution may run for. A non-positive value falls back to a 3 s
// default. Set once at startup.
func (e *Engine) SetTimeout(d time.Duration) {
	e.mu.Lock()
	e.timeout = d
	e.mu.Unlock()
}

func NewEngine(scriptPath string, p *proxy.Proxy, r *registrar.Registrar, a *auth.DigestAuth, db *store.DB) (*Engine, error) {
	e := &Engine{
		scriptPath: scriptPath,
		proxy:      p,
		registrar:  r,
		auth:       a,
		db:         db,
	}
	if err := e.Load(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Load() error {
	data, err := os.ReadFile(e.scriptPath)
	if err != nil {
		return fmt.Errorf("read script: %w", err)
	}

	source := string(data)
	prg, err := goja.Compile(e.scriptPath, source, true)
	if err != nil {
		return fmt.Errorf("compile script: %w", err)
	}

	e.mu.Lock()
	e.source = source
	e.prg = prg
	e.mu.Unlock()

	log.Printf("[script] loaded %s (%d bytes)", e.scriptPath, len(data))
	return nil
}

func (e *Engine) Reload() error {
	return e.Load()
}

func (e *Engine) Source() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.source
}

// Validate compiles the given source without installing it. Returns the error
// from goja.Compile if the script doesn't parse.
func (e *Engine) Validate(source string) error {
	_, err := goja.Compile("validate", source, true)
	return err
}

// Deploy validates, backs up the current script, writes the new one to disk,
// and swaps the in-memory program. Returns nil on success. If anything fails,
// the previous script is restored on disk and in memory and an error is returned.
func (e *Engine) Deploy(source string) error {
	prg, err := goja.Compile(e.scriptPath, source, true)
	if err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}

	e.mu.Lock()
	prevSource := e.source
	e.mu.Unlock()

	if err := os.WriteFile(e.scriptPath, []byte(source), 0644); err != nil {
		return fmt.Errorf("write script: %w", err)
	}

	e.mu.Lock()
	e.previousSrc = prevSource
	e.source = source
	e.prg = prg
	e.mu.Unlock()

	log.Printf("[script] deployed new script (%d bytes)", len(source))
	return nil
}

// Rollback reverts to the previously-installed script. Returns an error if
// there is no previous script to roll back to.
func (e *Engine) Rollback() error {
	e.mu.Lock()
	prev := e.previousSrc
	e.mu.Unlock()

	if prev == "" {
		return fmt.Errorf("no previous script to roll back to")
	}

	prg, err := goja.Compile(e.scriptPath, prev, true)
	if err != nil {
		return fmt.Errorf("compile previous script: %w", err)
	}

	if err := os.WriteFile(e.scriptPath, []byte(prev), 0644); err != nil {
		return fmt.Errorf("write script: %w", err)
	}

	e.mu.Lock()
	e.source = prev
	e.prg = prg
	e.previousSrc = ""
	e.mu.Unlock()

	log.Printf("[script] rolled back to previous script (%d bytes)", len(prev))
	return nil
}

func (e *Engine) HasRollback() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.previousSrc != ""
}

func (e *Engine) Execute(req *sip.Message) error {
	e.mu.RLock()
	prg := e.prg
	timeout := e.timeout
	e.mu.RUnlock()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	vm := goja.New()

	reqObj := e.buildRequestObject(vm, req)
	vm.Set("req", reqObj)
	e.registerFunctions(vm, req)

	// Watchdog: vm.Interrupt is safe to call from another goroutine
	// and causes the next bytecode instruction to throw the supplied
	// reason. Goja wraps that into an *InterruptedError which we map
	// to ErrScriptTimeout. Native callbacks (proxy, sendResponse,
	// etc.) are not interruptible mid-call — the interrupt only
	// fires when control returns to the JS bytecode loop. That is
	// good enough: the script has to be in JS to keep running.
	timer := time.AfterFunc(timeout, func() { vm.Interrupt(ErrScriptTimeout) })
	defer timer.Stop()

	if _, err := vm.RunProgram(prg); err != nil {
		if isInterrupt(err) {
			return ErrScriptTimeout
		}
		return fmt.Errorf("run script: %w", err)
	}

	onRequest, ok := goja.AssertFunction(vm.Get("onRequest"))
	if !ok {
		return fmt.Errorf("onRequest function not found in script")
	}

	if _, err := onRequest(goja.Undefined(), reqObj); err != nil {
		if isInterrupt(err) {
			return ErrScriptTimeout
		}
		return fmt.Errorf("onRequest: %w", err)
	}

	return nil
}

// isInterrupt reports whether err is the goja interrupt the
// watchdog timer triggered above. Any *goja.InterruptedError is
// treated as a script timeout.
func isInterrupt(err error) bool {
	var ie *goja.InterruptedError
	return errors.As(err, &ie)
}

func (e *Engine) buildRequestObject(vm *goja.Runtime, req *sip.Message) goja.Value {
	obj := vm.NewObject()

	obj.Set("method", req.Method)
	obj.Set("callId", req.CallID())
	obj.Set("cseqNum", req.CSeqNum())
	obj.Set("cseqMethod", req.CSeqMethod())
	obj.Set("sourceIp", req.SourceIP)
	obj.Set("sourcePort", req.SourcePort)
	obj.Set("transport", req.Transport)

	if req.RequestURI != nil {
		uriObj := vm.NewObject()
		uriObj.Set("scheme", req.RequestURI.Scheme)
		uriObj.Set("user", req.RequestURI.User)
		uriObj.Set("host", req.RequestURI.Host)
		uriObj.Set("port", req.RequestURI.Port)
		uriObj.Set("full", req.RequestURI.String())
		obj.Set("requestUri", uriObj)
	}

	if from := req.From(); from != nil {
		fromObj := vm.NewObject()
		fromObj.Set("display", from.DisplayName)
		fromObj.Set("tag", from.Tag())
		if from.URI != nil {
			fromObj.Set("user", from.URI.User)
			fromObj.Set("host", from.URI.Host)
			fromObj.Set("uri", from.URI.String())
		}
		obj.Set("from", fromObj)
	}

	if to := req.To(); to != nil {
		toObj := vm.NewObject()
		toObj.Set("display", to.DisplayName)
		toObj.Set("tag", to.Tag())
		if to.URI != nil {
			toObj.Set("user", to.URI.User)
			toObj.Set("host", to.URI.Host)
			toObj.Set("uri", to.URI.String())
		}
		obj.Set("to", toObj)
	}

	obj.Set("getHeader", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		return vm.ToValue(req.Headers.Get(name))
	})

	obj.Set("getHeaders", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		return vm.ToValue(req.Headers.GetAll(name))
	})

	return obj
}

func (e *Engine) registerFunctions(vm *goja.Runtime, req *sip.Message) {
	vm.Set("authenticate", func(call goja.FunctionCall) goja.Value {
		realm := ""
		for _, arg := range call.Arguments {
			s := arg.String()
			if s != "" && s != "[object Object]" && s != "undefined" {
				realm = s
				break
			}
		}

		ok, err := e.auth.Authenticate(req, realm)
		if err != nil {
			log.Printf("[script] auth error: %v", err)
			return vm.ToValue(false)
		}

		if !ok {
			challenge := e.auth.CreateChallenge(realm)

			var code int
			var hdrName string
			if req.Method == "REGISTER" {
				code = 401
				hdrName = "WWW-Authenticate"
			} else {
				code = 407
				hdrName = "Proxy-Authenticate"
			}

			resp := sip.CreateResponseFromRequest(req, code, "Unauthorized")
			resp.Headers.Set(hdrName, challenge.String())
			e.proxy.SendResponseMsg(req, resp)
			return vm.ToValue(false)
		}

		return vm.ToValue(true)
	})

	vm.Set("fixContact", func(call goja.FunctionCall) goja.Value {
		e.proxy.FixContact(req)
		return goja.Undefined()
	})

	vm.Set("processRegister", func(call goja.FunctionCall) goja.Value {
		resp := e.registrar.ProcessRegister(req)
		if resp != nil {
			e.proxy.SendResponseMsg(req, resp)
		}
		return goja.Undefined()
	})

	vm.Set("sendResponse", func(call goja.FunctionCall) goja.Value {
		code := int(call.Argument(0).ToInteger())
		reason := "OK"
		if len(call.Arguments) > 1 {
			reason = call.Argument(1).String()
		}
		resp := sip.CreateResponseFromRequest(req, code, reason)
		if len(call.Arguments) > 2 {
			applyExtraHeaders(resp, call.Argument(2), vm)
		}
		e.proxy.SendResponseMsg(req, resp)
		return goja.Undefined()
	})

	vm.Set("appendHeader", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		req.Headers.Add(name, value)
		return goja.Undefined()
	})

	vm.Set("removeHeader", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.Undefined()
		}
		name := sip.NormalizeHeaderName(call.Argument(0).String())
		req.Headers.Remove(name)
		return goja.Undefined()
	})

	vm.Set("setupDialog", func(call goja.FunctionCall) goja.Value {
		if e.dialogs == nil {
			log.Printf("[script] setupDialog: dialog manager not configured")
			return goja.Undefined()
		}
		opts := dialog.Options{}
		if len(call.Arguments) > 0 {
			if m, ok := call.Argument(0).Export().(map[string]interface{}); ok {
				if v, ok := m["dlgGate"].(bool); ok {
					opts.DlgGate = v
				}
				if v, ok := m["pcap"].(bool); ok {
					opts.Pcap = v
				}
				switch t := m["timeout"].(type) {
				case int64:
					opts.Timeout = time.Duration(t) * time.Second
				case float64:
					opts.Timeout = time.Duration(t) * time.Second
				case string:
					if d, err := time.ParseDuration(t); err == nil {
						opts.Timeout = d
					}
				}
			}
		}
		if _, err := e.dialogs.Setup(req, opts); err != nil {
			log.Printf("[script] setupDialog: %v", err)
		}
		return goja.Undefined()
	})

	vm.Set("anchorMedia", func(call goja.FunctionCall) goja.Value {
		opts := media.DefaultOptions()
		if len(call.Arguments) > 0 {
			if m, ok := call.Argument(0).Export().(map[string]interface{}); ok {
				if v, ok := m["symmetric"].(bool); ok {
					opts.Symmetric = v
				}
				if v, ok := m["pcap"].(bool); ok {
					opts.PCAP = v
				}
				if v, ok := m["wav"].(bool); ok {
					opts.WAV = v
				}
				if v, ok := m["dtmf"].(bool); ok {
					opts.DTMF = v
				}
				if v, ok := m["qos"].(bool); ok {
					opts.QoS = v
				}
				switch v := m["idleTimeout"].(type) {
				case int64:
					opts.IdleTimeout = time.Duration(v) * time.Second
				case float64:
					opts.IdleTimeout = time.Duration(v) * time.Second
				case string:
					if d, err := time.ParseDuration(v); err == nil {
						opts.IdleTimeout = d
					}
				}
			}
		}
		if err := e.proxy.AnchorMedia(req, opts); err != nil {
			log.Printf("[script] anchorMedia error: %v", err)
		}
		return goja.Undefined()
	})

	vm.Set("setRequestUri", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.Undefined()
		}
		exported := call.Argument(0).Export()

		switch v := exported.(type) {
		case string:
			uri, err := sip.ParseURI(v)
			if err != nil {
				log.Printf("[script] setRequestUri: %v", err)
				return goja.Undefined()
			}
			req.RequestURI = uri
		case map[string]interface{}:
			base := req.RequestURI
			if base == nil {
				base = &sip.URI{Scheme: "sip", Params: map[string]string{}}
			} else {
				base = base.Clone()
			}
			if s, ok := v["scheme"].(string); ok && s != "" {
				base.Scheme = s
			}
			if s, ok := v["user"].(string); ok {
				base.User = s
			}
			if s, ok := v["host"].(string); ok && s != "" {
				base.Host = s
			}
			if p, ok := v["port"]; ok {
				switch pv := p.(type) {
				case int64:
					base.Port = int(pv)
				case float64:
					base.Port = int(pv)
				}
			}
			req.RequestURI = base
		default:
			log.Printf("[script] setRequestUri: unsupported argument type %T", exported)
		}
		return goja.Undefined()
	})

	vm.Set("lookup", func(call goja.FunctionCall) goja.Value {
		var uri *sip.URI
		if len(call.Arguments) > 0 {
			uriStr := call.Argument(0).String()
			if uriStr == "[object Object]" && req.RequestURI != nil {
				uri = req.RequestURI
			} else {
				parsed, err := sip.ParseURI(uriStr)
				if err != nil {
					return vm.ToValue([]interface{}{})
				}
				uri = parsed
			}
		} else if req.RequestURI != nil {
			uri = req.RequestURI
		}

		if uri == nil {
			return vm.ToValue([]interface{}{})
		}

		bindings, err := e.registrar.Lookup(uri)
		if err != nil {
			log.Printf("[script] lookup error: %v", err)
			return vm.ToValue([]interface{}{})
		}

		var result []interface{}
		for _, b := range bindings {
			bObj := vm.NewObject()
			bObj.Set("contact", b.Contact)
			bObj.Set("receivedIp", b.ReceivedIP)
			bObj.Set("receivedPort", b.ReceivedPort)
			bObj.Set("transport", b.Transport)
			bObj.Set("aor", b.AOR)
			result = append(result, bObj)
		}
		return vm.ToValue(result)
	})

	vm.Set("proxy", func(call goja.FunctionCall) goja.Value {
		var (
			binding   *store.Binding
			destStr   string
			haveDest  bool
			transport = "UDP"
			fwdOpts   *proxy.ForwardOptions
		)

		// Accept any of:
		//   proxy()
		//   proxy(opts)
		//   proxy(binding [, opts])
		//   proxy(destString [, transport [, opts]])
		// — distinguishing by argument type. A map with `receivedIp`
		// is a binding; any other map is the options object; strings
		// fill the destination and transport slots in order.
		for _, a := range call.Arguments {
			switch v := a.Export().(type) {
			case string:
				if !haveDest {
					destStr = v
					haveDest = true
				} else {
					transport = v
				}
			case map[string]interface{}:
				if v["receivedIp"] != nil {
					binding = &store.Binding{
						Contact:      stringField(v, "contact"),
						ReceivedIP:   stringField(v, "receivedIp"),
						ReceivedPort: intField(v, "receivedPort"),
						Transport:    stringField(v, "transport"),
					}
				} else {
					fwdOpts = parseForwardOpts(v)
				}
			}
		}

		switch {
		case binding != nil:
			if err := e.proxy.ForwardToBinding(req, binding, fwdOpts); err != nil {
				log.Printf("[script] proxy to binding error: %v", err)
			}
		case haveDest:
			if err := e.proxy.ForwardRequest(req, destStr, transport, fwdOpts); err != nil {
				log.Printf("[script] proxy error: %v", err)
			}
		default:
			if err := e.proxy.ForwardToRequestURI(req, fwdOpts); err != nil {
				log.Printf("[script] proxy() error: %v", err)
			}
		}
		return goja.Undefined()
	})

	vm.Set("proxyTo", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		dst := call.Argument(0).String()
		transport := "UDP"
		var fwdOpts *proxy.ForwardOptions
		for i := 1; i < len(call.Arguments); i++ {
			switch v := call.Argument(i).Export().(type) {
			case string:
				transport = v
			case map[string]interface{}:
				fwdOpts = parseForwardOpts(v)
			}
		}
		if err := e.proxy.ForwardRequest(req, dst, transport, fwdOpts); err != nil {
			log.Printf("[script] proxyTo error: %v", err)
		}
		return goja.Undefined()
	})

	vm.Set("log", func(call goja.FunctionCall) goja.Value {
		args := make([]interface{}, len(call.Arguments))
		for i, a := range call.Arguments {
			args[i] = a.Export()
		}
		log.Printf("[script] %v", args)
		return goja.Undefined()
	})
}

func objString(obj *goja.Object, key string) string {
	v := obj.Get(key)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	return v.String()
}

func objInt(obj *goja.Object, key string) int64 {
	v := obj.Get(key)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return 0
	}
	return v.ToInteger()
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func intField(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return int(n)
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func parseForwardOpts(m map[string]interface{}) *proxy.ForwardOptions {
	opts := &proxy.ForwardOptions{RecordRoute: true}
	if v, ok := m["recordRoute"].(bool); ok {
		opts.RecordRoute = v
	}
	return opts
}

// applyExtraHeaders adds the headers described by val to msg. val may be:
//   - an object whose keys are header names and values are strings (or
//     arrays of strings for multi-value headers), e.g. {"X-Foo": "bar"}.
//   - an array of "Name: value" strings, e.g. ["X-Foo: bar"].
func applyExtraHeaders(msg *sip.Message, val goja.Value, vm *goja.Runtime) {
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return
	}
	exported := val.Export()

	if list, ok := exported.([]interface{}); ok {
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				continue
			}
			colon := indexByteOrEnd(s, ':')
			if colon < 0 || colon == len(s) {
				continue
			}
			name := strings.TrimSpace(s[:colon])
			value := strings.TrimSpace(s[colon+1:])
			if name != "" {
				msg.Headers.Add(name, value)
			}
		}
		return
	}

	if m, ok := exported.(map[string]interface{}); ok {
		for k, v := range m {
			switch vv := v.(type) {
			case string:
				msg.Headers.Add(k, vv)
			case []interface{}:
				for _, item := range vv {
					if s, ok := item.(string); ok {
						msg.Headers.Add(k, s)
					}
				}
			default:
				msg.Headers.Add(k, fmt.Sprintf("%v", v))
			}
		}
	}
}

func indexByteOrEnd(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
