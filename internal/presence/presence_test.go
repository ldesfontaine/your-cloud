package presence

import (
	"strings"
	"testing"
)

func TestDecodeSignalRequiresExactFieldsOnce(t *testing.T) {
	t.Parallel()
	valid := `{"machine_id":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`
	signal, err := DecodeSignal(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("valid signal rejected: %v", err)
	}
	if signal.MachineID != "lab-machine-1" || signal.DaemonVersion != Version {
		t.Fatalf("unexpected signal: %#v", signal)
	}

	hostile := []string{
		`{"machine_id":"lab-machine-9","machine_id":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`,
		`{"Machine_ID":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`,
		`{"machine_id":"lab-machine-1","Daemon_Version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`,
		valid + `{}`,
	}
	for _, document := range hostile {
		if signal, err := DecodeSignal(strings.NewReader(document)); err == nil {
			t.Fatalf("hostile signal accepted: %q as %#v", document, signal)
		}
	}
}

func TestSignalValidate(t *testing.T) {
	t.Parallel()

	allowed := map[string]struct{}{"lab-machine-1": {}}
	valid := Signal{
		MachineID:     "lab-machine-1",
		DaemonVersion: Version,
		SentAt:        "2026-07-16T12:00:00Z",
	}

	tests := []struct {
		name   string
		mutate func(*Signal)
	}{
		{name: "missing machine id", mutate: func(signal *Signal) { signal.MachineID = "" }},
		{name: "malformed machine id", mutate: func(signal *Signal) { signal.MachineID = "../machine" }},
		{name: "unknown machine id", mutate: func(signal *Signal) { signal.MachineID = "lab-machine-2" }},
		{name: "wrong version", mutate: func(signal *Signal) { signal.DaemonVersion = "v9.9.9" }},
		{name: "missing timestamp", mutate: func(signal *Signal) { signal.SentAt = "" }},
		{name: "malformed timestamp", mutate: func(signal *Signal) { signal.SentAt = "yesterday" }},
	}

	if err := valid.Validate(allowed); err != nil {
		t.Fatalf("valid signal rejected: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signal := valid
			test.mutate(&signal)
			if err := signal.Validate(allowed); err == nil {
				t.Fatal("invalid signal accepted")
			}
		})
	}
}
