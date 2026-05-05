package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/funsip/funsip/pkg/auth"
	"github.com/funsip/funsip/pkg/config"
	"github.com/funsip/funsip/pkg/management"
	"github.com/funsip/funsip/pkg/proxy"
	"github.com/funsip/funsip/pkg/registrar"
	"github.com/funsip/funsip/pkg/script"
	"github.com/funsip/funsip/pkg/sip"
	"github.com/funsip/funsip/pkg/store"
	"github.com/funsip/funsip/pkg/transaction"
	"github.com/funsip/funsip/pkg/transport"
)

func main() {
	configPath := flag.String("config", "funsip.json", "config file path")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	// Break the circular dependency: transport needs txLayer.ReceiveMessage,
	// txLayer needs transport.Send. Use a closure that captures txLayer after init.
	var txLayer *transaction.Layer

	tm := transport.NewManager(cfg.ListenIP, cfg.ListenPort, func(msg *sip.Message) {
		txLayer.ReceiveMessage(msg)
	})

	txLayer = transaction.NewLayer(tm.Send)

	p := proxy.New(txLayer, cfg.ListenIP, cfg.ListenPort, cfg.Domain)
	reg := registrar.New(db)
	digestAuth := auth.NewDigestAuth(db, cfg.Domain)

	eng, err := script.NewEngine(cfg.ScriptPath, p, reg, digestAuth, db)
	if err != nil {
		log.Fatalf("load script: %v", err)
	}

	txLayer.SetRequestHandler(func(req *sip.Message) {
		if req.Method == "ACK" {
			return
		}

		if p.IsInDialog(req) && req.Method != "REGISTER" {
			if err := p.ForwardInDialog(req); err != nil {
				log.Printf("[server] in-dialog forward error: %v", err)
				p.SendResponse(req, 500, "Server Internal Error")
			}
			return
		}

		if err := eng.Execute(req); err != nil {
			log.Printf("[server] script error: %v", err)
			p.SendResponse(req, 500, "Server Internal Error")
		}
	})

	mgmtAPI := management.NewAPI(txLayer, tm, eng, db)
	logBuf := mgmtAPI.LogBuffer()
	log.SetOutput(io.MultiWriter(os.Stderr, logBuf))
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if err := tm.Start(); err != nil {
		log.Fatalf("start transport: %v", err)
	}
	defer tm.Stop()

	httpAddr := fmt.Sprintf("%s:%d", cfg.HTTPIP, cfg.HTTPPort)
	if err := mgmtAPI.Start(httpAddr); err != nil {
		log.Fatalf("start management API: %v", err)
	}
	defer mgmtAPI.Stop()

	log.Printf("FunSIP %s started", management.Version)
	log.Printf("  SIP:    %s:%d (UDP+TCP)", cfg.ListenIP, cfg.ListenPort)
	log.Printf("  HTTP:   %s:%d", cfg.HTTPIP, cfg.HTTPPort)
	log.Printf("  Script: %s", cfg.ScriptPath)
	log.Printf("  DB:     %s", cfg.DBPath)
	log.Printf("  Domain: %s", cfg.Domain)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			log.Println("SIGHUP received, reloading script...")
			if err := eng.Reload(); err != nil {
				log.Printf("reload error: %v", err)
			} else {
				log.Println("script reloaded successfully")
			}
			continue
		}
		log.Printf("signal %v received, shutting down...", sig)
		break
	}
}
