package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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

type Config struct {
	MachineID       string   `json:"machine_id"`
	StateDir        string   `json:"state_dir"`
	IntervalSeconds int      `json:"interval_seconds"`
	QueueLimitBytes int64    `json:"queue_limit_bytes"`
	Units           []string `json:"units"`
}

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
	return cfg, nil
}
