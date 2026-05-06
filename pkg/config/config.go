package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ListenIP   string `json:"listen_ip"`
	ListenPort int    `json:"listen_port"`
	Domain     string `json:"domain"`
	DBPath     string `json:"db_path"`
	ScriptPath string `json:"script_path"`
	HTTPIP     string `json:"http_ip"`
	HTTPPort   int    `json:"http_port"`
	LogLevel   string `json:"log_level"`
	PCAPDir    string `json:"pcap_dir"`
	// EventsURL is an optional HTTP endpoint that receives one POST
	// per emitted event (auth-failed, call-attempt, call-start,
	// call-end, reg-new, reg-del, reg-expired). Empty disables event
	// emission.
	EventsURL string `json:"events_url"`
	// ScriptTimeoutMs is the maximum wall-clock time the routing
	// script is allowed to run for one request, in milliseconds. On
	// timeout the transaction is answered with 408 and any pending
	// INVITE branches are cancelled. Default 3000.
	ScriptTimeoutMs int `json:"script_timeout_ms"`
	// InviteTimeoutMs is a hard cap on INVITE server transactions
	// that have not yet sent a final response, in milliseconds. On
	// expiry the UAC is answered with 408 and CANCEL is fanned out
	// to all pending upstream branches. Default 180000 (3 min).
	InviteTimeoutMs int `json:"invite_timeout_ms"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenIP:        "0.0.0.0",
		ListenPort:      5060,
		Domain:          "localhost",
		DBPath:          "funsip.db",
		ScriptPath:      "route.js",
		HTTPIP:          "127.0.0.1",
		HTTPPort:        8080,
		LogLevel:        "info",
		PCAPDir:         ".",
		ScriptTimeoutMs: 3000,
		InviteTimeoutMs: 180000,
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
