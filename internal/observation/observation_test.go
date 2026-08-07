package observation

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCollectHostHealthUsesOnlyFixedSources(t *testing.T) {
	t.Parallel()
	var paths []string
	health := CollectHostHealth(Sources{
		ReadFile: func(path string) ([]byte, error) {
			paths = append(paths, path)
			switch path {
			case uptimePath:
				return []byte("123.99 456.00\n"), nil
			case memoryPath:
				return []byte("MemTotal: 1024 kB\nMemAvailable: 512 kB\n"), nil
			default:
				return nil, errors.New("unexpected path")
			}
		},
		StatFS: func(path string) (FileSystemStats, error) {
			paths = append(paths, path)
			return FileSystemStats{BlockSize: 4096, TotalBlocks: 100, AvailableBlocks: 40}, nil
		},
	})
	if len(paths) != 3 || paths[0] != uptimePath || paths[1] != memoryPath || paths[2] != rootPath {
		t.Fatalf("unexpected collector paths: %#v", paths)
	}
	if health.Uptime.UptimeSeconds == nil || *health.Uptime.UptimeSeconds != 123 {
		t.Fatalf("unexpected uptime: %#v", health.Uptime)
	}
	if health.Memory.TotalBytes == nil || *health.Memory.TotalBytes != 1024*1024 {
		t.Fatalf("unexpected memory: %#v", health.Memory)
	}
	if health.RootFS.AvailableBytes == nil || *health.RootFS.AvailableBytes != 40*4096 {
		t.Fatalf("unexpected rootfs: %#v", health.RootFS)
	}
}

func TestCollectHostHealthContainsBoundedErrors(t *testing.T) {
	t.Parallel()
	health := CollectHostHealth(Sources{
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("secret detail") },
		StatFS:   func(string) (FileSystemStats, error) { return FileSystemStats{}, errors.New("secret detail") },
	})
	if health.Uptime.Error != errorRead || health.Memory.Error != errorRead || health.RootFS.Error != errorRead {
		t.Fatalf("source errors leaked or changed shape: %#v", health)
	}
}

func TestEnvelopeRoundTripAndHostileDocuments(t *testing.T) {
	t.Parallel()
	health := CollectHostHealth(Sources{
		ReadFile: func(path string) ([]byte, error) {
			if path == uptimePath {
				return []byte("10.0 1.0"), nil
			}
			return []byte("MemTotal: 100 kB\nMemAvailable: 50 kB\n"), nil
		},
		StatFS: func(string) (FileSystemStats, error) {
			return FileSystemStats{BlockSize: 1, TotalBlocks: 100, AvailableBlocks: 50}, nil
		},
	})
	envelope, err := NewEnvelope("lab-machine-1", 1, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC), health, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Sequence != 1 || decoded.Profile != Profile {
		t.Fatalf("round trip failed: %#v %v", decoded, err)
	}

	for _, hostile := range [][]byte{
		{},
		[]byte(`[]`),
		[]byte(`{"schema_version":1,"schema_version":1}`),
		[]byte(`{"unknown":true}`),
		append(encoded, []byte(`{}`)...),
	} {
		if value, err := Decode(hostile); err == nil {
			t.Fatalf("hostile observation accepted: %#v", value)
		}
	}
}

func TestEnvelopeRejectsUnknownProfileAndFreeCollectorData(t *testing.T) {
	t.Parallel()
	zero := uint64(0)
	validHealth := HostHealth{
		Uptime: UptimeResult{Status: statusOK, UptimeSeconds: &zero},
		Memory: MemoryResult{Status: statusOK, TotalBytes: &zero, AvailableBytes: &zero},
		RootFS: RootFSResult{Status: statusOK, TotalBytes: &zero, AvailableBytes: &zero},
	}
	value, err := NewEnvelope("lab-machine-1", 1, time.Now(), validHealth, nil)
	if err != nil {
		t.Fatal(err)
	}
	value.Profile = "shell.v1"
	if err := value.Validate(); err == nil {
		t.Fatal("unknown profile accepted")
	}

	encoded := []byte(`{"schema_version":1,"machine_id":"lab-machine-1","daemon_version":"v0.0.3","profile":"host-health.v1","sequence":1,"observed_at":"2026-07-18T12:00:00Z","health":{"uptime":{"status":"ok","uptime_seconds":1,"command":"id"},"memory":{"status":"error","error":"source_unavailable"},"rootfs":{"status":"error","error":"source_unavailable"}}}`)
	if decoded, err := Decode(encoded); err == nil {
		t.Fatalf("free collector data accepted: %#v", decoded)
	}
}

func TestEnvelopeRejectsGapAtOrAfterCurrentSequence(t *testing.T) {
	t.Parallel()
	zero := uint64(0)
	health := HostHealth{
		Uptime: UptimeResult{Status: statusOK, UptimeSeconds: &zero},
		Memory: MemoryResult{Status: statusOK, TotalBytes: &zero, AvailableBytes: &zero},
		RootFS: RootFSResult{Status: statusOK, TotalBytes: &zero, AvailableBytes: &zero},
	}
	for _, gap := range []Gap{
		{FirstSequence: 2, LastSequence: 2, DroppedCount: 1, FirstObservedAt: "2026-07-18T11:59:58Z", LastObservedAt: "2026-07-18T11:59:58Z"},
		{FirstSequence: 3, LastSequence: 4, DroppedCount: 2, FirstObservedAt: "2026-07-18T11:59:58Z", LastObservedAt: "2026-07-18T11:59:59Z"},
	} {
		envelope, err := NewEnvelope("lab-machine-1", 2, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC), health, nil)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Gaps = []Gap{gap}
		if err := envelope.Validate(); err == nil {
			t.Fatalf("gap at or after the current sequence accepted: %#v", gap)
		}
	}
}

func BenchmarkCollectHostHealth(b *testing.B) {
	sources := SystemSources()
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		result := CollectHostHealth(sources)
		if result.Uptime.Status != statusOK || result.Memory.Status != statusOK || result.RootFS.Status != statusOK {
			b.Fatalf("real host-health collection failed: %#v", result)
		}
	}
}

// TestExternalSectionIsClosedBoundedAndOptional holds the one field `#107` added
// to the wire message.
//
// The section is optional above all: a machine whose own sheet names no target
// produces exactly the bytes every machine produced before this palier, so the
// envelope `v0.0.2` proved is still the envelope such a machine sends. What the
// section may say is closed on four words, bounded, and sorted and unique on the
// port — a reader mapping a reading onto a declaration must never have to choose
// between two answers about the same port.
func TestExternalSectionIsClosedBoundedAndOptional(t *testing.T) {
	t.Parallel()
	health := validHostHealth()
	silent, err := NewEnvelope("lab-machine-1", 1, time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC), health, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := silent.Encode()
	if err != nil || strings.Contains(string(encoded), "external") {
		t.Fatalf("a machine with no declared target sent %s (%v)", encoded, err)
	}

	speaking, err := NewEnvelope("lab-machine-1", 1, time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC), health,
		[]ExternalReading{{ProbePort: 5000, Outcome: ExternalAnswered}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = speaking.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || len(decoded.External) != 1 || decoded.External[0] != speaking.External[0] {
		t.Fatalf("one reading did not survive the wire: %+v %v", decoded.External, err)
	}

	tooMany := make([]ExternalReading, MaxExternalReadings+1)
	for index := range tooMany {
		tooMany[index] = ExternalReading{ProbePort: index + 1, Outcome: ExternalAnswered}
	}
	for name, readings := range map[string][]ExternalReading{
		"an unknown outcome": {{ProbePort: 5000, Outcome: "probably_fine"}},
		"an empty outcome":   {{ProbePort: 5000}},
		"a port of zero":     {{ProbePort: 0, Outcome: ExternalAnswered}},
		"a repeated port": {
			{ProbePort: 5000, Outcome: ExternalAnswered},
			{ProbePort: 5000, Outcome: ExternalNoListener},
		},
		"unsorted ports": {
			{ProbePort: 9000, Outcome: ExternalAnswered},
			{ProbePort: 5000, Outcome: ExternalAnswered},
		},
		"more than the bound": tooMany,
	} {
		candidate := speaking
		candidate.External = readings
		if err := candidate.Validate(); err == nil {
			t.Fatalf("an envelope carrying %s was accepted", name)
		}
	}
}

func validHostHealth() HostHealth {
	value := uint64(1)
	return HostHealth{
		Uptime: UptimeResult{Status: statusOK, UptimeSeconds: &value},
		Memory: MemoryResult{Status: statusOK, TotalBytes: &value, AvailableBytes: &value},
		RootFS: RootFSResult{Status: statusOK, TotalBytes: &value, AvailableBytes: &value},
	}
}
