package observation

import (
	"errors"
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
	envelope, err := NewEnvelope("lab-machine-1", 1, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC), health)
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
	value, err := NewEnvelope("lab-machine-1", 1, time.Now(), validHealth)
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
		envelope, err := NewEnvelope("lab-machine-1", 2, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC), health)
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
