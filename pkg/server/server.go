package server

import (
	"fmt"
	"io"
	"log"

	"github.com/funsip/funsip/pkg/auth"
	"github.com/funsip/funsip/pkg/config"
	"github.com/funsip/funsip/pkg/management"
	"github.com/funsip/funsip/pkg/metrics"
	"github.com/funsip/funsip/pkg/proxy"
	"github.com/funsip/funsip/pkg/registrar"
	"github.com/funsip/funsip/pkg/script"
	"github.com/funsip/funsip/pkg/sip"
	"github.com/funsip/funsip/pkg/store"
	"github.com/funsip/funsip/pkg/transaction"
	"github.com/funsip/funsip/pkg/transport"
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
	s.Registrar = registrar.New(db)
	s.Auth = auth.NewDigestAuth(db, cfg.Domain)

	eng, err := script.NewEngine(cfg.ScriptPath, s.Proxy, s.Registrar, s.Auth, db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("load script: %w", err)
	}
	s.Script = eng

	s.TxLayer.SetRequestHandler(func(req *sip.Message) {
		if req.Method == "ACK" {
			return
		}

		if s.Proxy.IsInDialog(req) && req.Method != "REGISTER" {
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
