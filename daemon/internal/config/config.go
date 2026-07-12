package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

const (
	DefaultIntervalSeconds = 60
	DefaultQueueLimitBytes = 10 * 1024 * 1024
	MaxUnits               = 32
)

var (
	machineIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	unitPattern      = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,128}$`)
)

// Config regroupe les paramètres bornés de collecte, stockage et publication.
type Config struct {
	MachineID       string        `json:"machine_id"`
	StateDir        string        `json:"state_dir"`
	IntervalSeconds int           `json:"interval_seconds"`
	QueueLimitBytes int64         `json:"queue_limit_bytes"`
	Units           []string      `json:"units"`
	Coordinators    []Coordinator `json:"coordinators"`
}

// Coordinator décrit un point de publication mTLS explicitement autorisé.
type Coordinator struct {
	URL             string `json:"url"`
	CAFile          string `json:"ca_file"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

// Load charge la configuration stricte du daemon et applique les bornes V1.
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
	if !machineIDPattern.MatchString(cfg.MachineID) {
		return Config{}, fmt.Errorf("machine_id invalide")
	}
	if cfg.StateDir == "" || cfg.StateDir[0] != '/' {
		return Config{}, fmt.Errorf("state_dir doit être absolu")
	}
	if cfg.IntervalSeconds == 0 {
		cfg.IntervalSeconds = DefaultIntervalSeconds
	}
	if cfg.IntervalSeconds < 1 || cfg.IntervalSeconds > 3600 {
		return Config{}, fmt.Errorf("interval_seconds hors limites")
	}
	if cfg.QueueLimitBytes == 0 {
		cfg.QueueLimitBytes = DefaultQueueLimitBytes
	}
	if cfg.QueueLimitBytes < 64*1024 || cfg.QueueLimitBytes > DefaultQueueLimitBytes {
		return Config{}, fmt.Errorf("queue_limit_bytes hors limites")
	}
	if len(cfg.Units) > MaxUnits {
		return Config{}, fmt.Errorf("trop d'unités systemd")
	}
	seen := make(map[string]bool)
	for _, unit := range cfg.Units {
		if !unitPattern.MatchString(unit) || seen[unit] {
			return Config{}, fmt.Errorf("unité systemd invalide ou dupliquée: %q", unit)
		}
		seen[unit] = true
	}
	if len(cfg.Coordinators) > 2 {
		return Config{}, fmt.Errorf("trop de coordinateurs autorisés")
	}
	seenURLs := make(map[string]bool)
	for _, coordinator := range cfg.Coordinators {
		endpoint, err := url.Parse(coordinator.URL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return Config{}, fmt.Errorf("URL de coordinateur invalide")
		}
		if seenURLs[coordinator.URL] {
			return Config{}, fmt.Errorf("coordinateur dupliqué")
		}
		seenURLs[coordinator.URL] = true
		for label, value := range map[string]string{
			"ca_file":          coordinator.CAFile,
			"certificate_file": coordinator.CertificateFile,
			"private_key_file": coordinator.PrivateKeyFile,
		} {
			if !filepath.IsAbs(value) {
				return Config{}, fmt.Errorf("%s du coordinateur doit être absolu", label)
			}
		}
	}
	return cfg, nil
}
