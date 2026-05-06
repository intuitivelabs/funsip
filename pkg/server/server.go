package server

import (
	"fmt"
	"io"
	"log"

	"github.com/intuitivelabs/funsip/pkg/auth"
	"github.com/intuitivelabs/funsip/pkg/config"
	"github.com/intuitivelabs/funsip/pkg/dialog"
	"github.com/intuitivelabs/funsip/pkg/events"
	"github.com/intuitivelabs/funsip/pkg/management"
	"github.com/intuitivelabs/funsip/pkg/media"
	"github.com/intuitivelabs/funsip/pkg/metrics"
	"github.com/intuitivelabs/funsip/pkg/proxy"
	"github.com/intuitivelabs/funsip/pkg/registrar"
	"github.com/intuitivelabs/funsip/pkg/script"
	"github.com/intuitivelabs/funsip/pkg/sip"
	"github.com/intuitivelabs/funsip/pkg/store"
	"github.com/intuitivelabs/funsip/pkg/transaction"
	"github.com/intuitivelabs/funsip/pkg/transport"
)

type Server struct {
	Config    *config.Config
	DB        *store.DB
	Transport *transport.Manager
	TxLayer   *transaction.Layer
	Proxy     *proxy.Proxy
	Registrar *registrar.Registrar
	Auth      *auth.DigestAuth
	Script    *script.Engine
	Mgmt      *management.API
	Metrics   *metrics.Metrics
	Media     *media.Manager
	Dialogs   *dialog.Manager
	Events    *events.Sink
}

func New(cfg *config.Config) (*Server, error) {
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	s := &Server{Config: cfg, DB: db, Metrics: metrics.New()}

	s.Transport = transport.NewManager(cfg.ListenIP, cfg.ListenPort, func(msg *sip.Message) {
		s.TxLayer.ReceiveMessage(msg)
	})

	s.TxLayer = transaction.NewLayer(s.Transport.Send, s.Metrics)
	s.Proxy = proxy.New(s.TxLayer, cfg.ListenIP, cfg.ListenPort, cfg.Domain, s.Metrics)
	s.Media = media.NewManager(cfg.ListenIP)
	s.Proxy.SetMediaManager(s.Media)
	s.Proxy.SetMediaDir(cfg.PCAPDir)
	s.Registrar = registrar.New(db)
	s.Auth = auth.NewDigestAuth(db, cfg.Domain)
	s.Dialogs = dialog.NewManager(s.Transport, s.Metrics, cfg.ListenIP, cfg.ListenPort, cfg.PCAPDir)
	s.Events = events.NewSink(cfg.EventsURL)

	s.Proxy.SetEventSink(s.Events)
	s.Registrar.SetEventSink(s.Events)
	s.Dialogs.SetEventSink(s.Events)

	s.Proxy.SetDialogConfirm(s.Dialogs.ConfirmFromResponse)
	s.Dialogs.SetMediaCleanup(s.Proxy.CleanupMediaForCallID)
	s.Dialogs.SetMediaReporter(func(callID string) interface{} {
		r := s.Media.ReportFor(callID)
		if r == nil {
			return nil
		}
		return r
	})
	s.Transport.SetCaptureHook(s.Dialogs.CapturePacket)

	eng, err := script.NewEngine(cfg.ScriptPath, s.Proxy, s.Registrar, s.Auth, db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("load script: %w", err)
	}
	eng.SetDialogManager(s.Dialogs)
	s.Script = eng

	s.TxLayer.SetRequestHandler(func(req *sip.Message) {
		if req.Method == "ACK" {
			return
		}

		inDialog := s.Proxy.IsInDialog(req)

		if inDialog && req.Method != "REGISTER" {
			d := s.Dialogs.FindFor(req)

			if req.Method == "BYE" {
				if d != nil {
					s.Dialogs.Terminate(req.CallID(), req)
				}
				s.Proxy.CleanupMediaForCallID(req.CallID())
				if err := s.Proxy.ForwardInDialog(req); err != nil {
					log.Printf("[server] BYE forward error: %v", err)
					s.Proxy.SendResponse(req, 500, "Server Internal Error")
				}
				return
			}

			if s.Dialogs.DlgGateActive() && d == nil {
				s.Proxy.SendResponse(req, 481, "Call/Transaction Does Not Exist")
				return
			}

			if err := s.Proxy.ForwardInDialog(req); err != nil {
				log.Printf("[server] in-dialog forward error: %v", err)
				s.Proxy.SendResponse(req, 500, "Server Internal Error")
			}
			return
		}

		if err := eng.Execute(req); err != nil {
			log.Printf("[server] script error: %v", err)
			s.Proxy.SendResponse(req, 500, "Server Internal Error")
		}
	})

	s.Mgmt = management.NewAPI(s.TxLayer, s.Transport, s.Script, db, s.Metrics)

	return s, nil
}

func (s *Server) AttachLogger(extra io.Writer) {
	logBuf := s.Mgmt.LogBuffer()
	if extra != nil {
		log.SetOutput(io.MultiWriter(extra, logBuf))
	} else {
		log.SetOutput(logBuf)
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
}

func (s *Server) Start() error {
	if err := s.Transport.Start(); err != nil {
		return fmt.Errorf("start transport: %w", err)
	}

	httpAddr := fmt.Sprintf("%s:%d", s.Config.HTTPIP, s.Config.HTTPPort)
	if err := s.Mgmt.Start(httpAddr); err != nil {
		s.Transport.Stop()
		return fmt.Errorf("start management API: %w", err)
	}

	return nil
}

func (s *Server) Stop() {
	if s.Mgmt != nil {
		s.Mgmt.Stop()
	}
	if s.Dialogs != nil {
		s.Dialogs.CloseAll()
	}
	if s.Registrar != nil {
		s.Registrar.Stop()
	}
	if s.Events != nil {
		s.Events.Close()
	}
	if s.Transport != nil {
		s.Transport.Stop()
	}
	if s.DB != nil {
		s.DB.Close()
	}
}

func (s *Server) ReloadScript() error {
	return s.Script.Reload()
}
