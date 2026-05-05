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
}

func DefaultConfig() *Config {
	return &Config{
		ListenIP:   "0.0.0.0",
		ListenPort: 5060,
		Domain:     "localhost",
		DBPath:     "funsip.db",
		ScriptPath: "route.js",
		HTTPIP:     "127.0.0.1",
		HTTPPort:   8080,
		LogLevel:   "info",
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
