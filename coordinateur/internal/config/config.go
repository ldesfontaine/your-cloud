package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const (
	DefaultDatabaseLimitBytes = 64 * 1024 * 1024
	DefaultEventRetentionDays = 30
)

// Config décrit l'écoute explicite, le stockage borné et les identités mTLS.
type Config struct {
	ListenAddress      string `json:"listen_address"`
	StateDir           string `json:"state_dir"`
	DatabaseLimitBytes int64  `json:"database_limit_bytes"`
	EventRetentionDays int    `json:"event_retention_days"`
	CertificateFile    string `json:"certificate_file"`
	PrivateKeyFile     string `json:"private_key_file"`
	ClientCAFile       string `json:"client_ca_file"`
	IdentityRegistry   string `json:"identity_registry"`
}

// Load charge la configuration stricte et refuse toute écoute non bornée.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("lire la configuration: %w", err)
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("configuration JSON invalide: %w", err)
	}
	host, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil || host == "" || port == "" {
		return Config{}, fmt.Errorf("listen_address doit contenir une adresse IP explicite et un port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return Config{}, fmt.Errorf("listen_address doit être une adresse IP locale explicite")
	}
	if cfg.StateDir == "" || !filepath.IsAbs(cfg.StateDir) {
		return Config{}, fmt.Errorf("state_dir doit être absolu")
	}
	if cfg.DatabaseLimitBytes == 0 {
		cfg.DatabaseLimitBytes = DefaultDatabaseLimitBytes
	}
	if cfg.DatabaseLimitBytes < 1024*1024 || cfg.DatabaseLimitBytes > DefaultDatabaseLimitBytes {
		return Config{}, fmt.Errorf("database_limit_bytes hors limites")
	}
	if cfg.EventRetentionDays == 0 {
		cfg.EventRetentionDays = DefaultEventRetentionDays
	}
	if cfg.EventRetentionDays < 1 || cfg.EventRetentionDays > DefaultEventRetentionDays {
		return Config{}, fmt.Errorf("event_retention_days hors limites")
	}
	for label, value := range map[string]string{
		"certificate_file":  cfg.CertificateFile,
		"private_key_file":  cfg.PrivateKeyFile,
		"client_ca_file":    cfg.ClientCAFile,
		"identity_registry": cfg.IdentityRegistry,
	} {
		if !filepath.IsAbs(value) {
			return Config{}, fmt.Errorf("%s doit être absolu", label)
		}
	}
	return cfg, nil
}
