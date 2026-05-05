package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/funsip/funsip/pkg/config"
	"github.com/funsip/funsip/pkg/management"
	"github.com/funsip/funsip/pkg/server"
)

func main() {
	configPath := flag.String("config", "funsip.json", "config file path")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("init server: %v", err)
	}
	defer srv.Stop()

	srv.AttachLogger(os.Stderr)

	if err := srv.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}

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
			if err := srv.ReloadScript(); err != nil {
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
