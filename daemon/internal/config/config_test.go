package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppliesContractDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(`{"machine_id":"machine-1","state_dir":"/tmp/state","units":["ssh.service"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IntervalSeconds != 60 || cfg.QueueLimitBytes != 10*1024*1024 {
		t.Fatalf("defaults inattendus: %+v", cfg)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(`{"machine_id":"machine-1","state_dir":"/tmp/state","secret":"non"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("champ inconnu accepté")
	}
}
