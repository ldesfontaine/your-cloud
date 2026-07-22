package controller

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func uint64Pointer(value uint64) *uint64 { return &value }

func testHealth() observation.HostHealth {
	return observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: uint64Pointer(60)},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: uint64Pointer(1_024), AvailableBytes: uint64Pointer(512)},
		RootFS: observation.RootFSResult{Status: "error", Error: "source_unavailable"},
	}
}

func testSnapshot() RelaySnapshot {
	return RelaySnapshot{
		SchemaVersion:    1,
		ControllerID:     testControllerID,
		InfrastructureID: testInfrastructureID,
		SnapshotAt:       "2026-07-19T12:00:00Z",
		Machines: []RelaySnapshotMachine{
			{
				MachineID:        "lab-machine-1",
				EnrollmentStatus: "active",
				Observation: &RelaySnapshotObservation{
					SchemaVersion: 1,
					MachineID:     "lab-machine-1",
					DaemonVersion: "v0.0.3",
					Profile:       "host-health.v1",
					Sequence:      31,
					ObservedAt:    "2026-07-19T11:59:29Z",
					ReceivedAt:    "2026-07-19T11:58:30Z",
					Gaps: []observation.Gap{
						{
							FirstSequence: 15, LastSequence: 30, DroppedCount: 16,
							FirstObservedAt: "2026-07-19T11:51:58Z", LastObservedAt: "2026-07-19T11:59:28Z",
						},
					},
					Health: testHealth(),
				},
			},
		},
	}
}

func TestRelaySnapshotStrictSchemaAndBounds(t *testing.T) {
	snapshot := testSnapshot()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRelaySnapshot(encoded, testControllerID, testInfrastructureID)
	if err != nil || len(decoded.Machines) != 1 {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	empty := snapshot
	empty.Machines = make([]RelaySnapshotMachine, 0)
	encoded, _ = json.Marshal(empty)
	if decoded, err = DecodeRelaySnapshot(encoded, testControllerID, testInfrastructureID); err != nil || decoded.Machines == nil {
		t.Fatalf("real empty snapshot rejected: %#v %v", decoded.Machines, err)
	}
	hostile := strings.Replace(string(encoded), `"machines":[]`, `"machines":[],"unknown":true`, 1)
	if _, err := DecodeRelaySnapshot([]byte(hostile), testControllerID, testInfrastructureID); err == nil {
		t.Fatal("unknown field was accepted")
	}
	empty.Machines = nil
	encoded, _ = json.Marshal(empty)
	if _, err := DecodeRelaySnapshot(encoded, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("null machines was accepted")
	}
	snapshot.Machines[0].Observation.Gaps = nil
	encoded, _ = json.Marshal(snapshot)
	if _, err := DecodeRelaySnapshot(encoded, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("null gaps was accepted")
	}
}

func TestRelaySnapshotRejectsCrossedIdentityAndNonCanonicalTime(t *testing.T) {
	snapshot := testSnapshot()
	if err := snapshot.Validate("33333333-3333-4333-8333-333333333333", testInfrastructureID); err == nil {
		t.Fatal("crossed Controller was accepted")
	}
	snapshot.SnapshotAt = "2026-07-19T14:00:00+02:00"
	if err := snapshot.Validate(testControllerID, testInfrastructureID); err == nil {
		t.Fatal("noncanonical timezone was accepted")
	}
	snapshot = testSnapshot()
	snapshot.Machines[0].Observation.ReceivedAt = "2026-07-19T12:00:00.000000000Z"
	if err := snapshot.Validate(testControllerID, testInfrastructureID); err == nil {
		t.Fatal("noncanonical fractional timestamp was accepted")
	}
}

func TestRelayCacheNonRegression(t *testing.T) {
	current := testSnapshot()
	candidate := cloneRelaySnapshot(current)
	candidate.SnapshotAt = "2026-07-19T12:00:01Z"
	candidate.Machines[0].Observation.Sequence++
	candidate.Machines[0].Observation.ReceivedAt = "2026-07-19T12:00:01Z"
	if err := allowsSnapshotTransition(current, candidate); err != nil {
		t.Fatalf("monotonic transition rejected: %v", err)
	}
	candidate.Machines[0].Observation.Gaps = make([]observation.Gap, 0)
	if err := allowsSnapshotTransition(current, candidate); err == nil {
		t.Fatal("known gap removal was accepted")
	}
	candidate = cloneRelaySnapshot(current)
	candidate.SnapshotAt = "2026-07-19T12:00:01Z"
	candidate.Machines[0].Observation = nil
	if err := allowsSnapshotTransition(current, candidate); err == nil {
		t.Fatal("observation disappearance was accepted")
	}
	candidate = cloneRelaySnapshot(current)
	candidate.Machines = make([]RelaySnapshotMachine, 0)
	if err := allowsSnapshotTransition(current, candidate); err == nil {
		t.Fatal("machine omission was accepted")
	}
}

func TestRelayCachePublicationFailureKeepsPreviousState(t *testing.T) {
	directory := privateTestDirectory(t)
	store, err := OpenRelayCacheStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	current := testSnapshot()
	if err := store.Commit(current); err != nil {
		t.Fatal(err)
	}
	store.writeState = func(RelaySnapshot) error { return os.ErrPermission }
	candidate := cloneRelaySnapshot(current)
	candidate.SnapshotAt = "2026-07-19T12:00:01Z"
	if err := store.Commit(candidate); err == nil {
		t.Fatal("cache publication failure was accepted")
	}
	persisted, err := store.Snapshot()
	if err != nil || persisted.SnapshotAt != current.SnapshotAt {
		t.Fatal("failed cache publication changed current state")
	}
}

func TestInvalidRegularCacheCanRecoverButUnsafeModeCannot(t *testing.T) {
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, relayCacheFileName)
	if err := os.WriteFile(path, []byte(`{"schema_version":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenRelayCacheStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(); err == nil {
		t.Fatal("invalid cache was exposed")
	}
	if err := store.Commit(testSnapshot()); err != nil {
		t.Fatalf("valid network snapshot did not repair safe regular cache: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRelayCacheStore(directory, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("unsafe cache mode was accepted")
	}
}

func TestProjectionFreshnessWarningGapsAndTransportFailure(t *testing.T) {
	label := "Serveur principal"
	inventory := Inventory{
		SchemaVersion: 1, ControllerID: testControllerID, InfrastructureID: testInfrastructureID,
		InventoryRevision: 2, InfrastructureLabel: &label,
		Machines: []InventoryMachine{{MachineID: "lab-machine-1", Label: label}},
	}
	snapshot := testSnapshot()
	view, err := ProjectMachines(inventory, &snapshot, RelayAvailable, 0)
	if err != nil {
		t.Fatal(err)
	}
	machine := view.Machines[0]
	if machine.ObservationStatus == nil || *machine.ObservationStatus != "recent" {
		t.Fatalf("90-second inclusive boundary is not recent: %#v", machine.ObservationStatus)
	}
	if machine.Observation == nil || !machine.Observation.ObservedTimeWarning || machine.Observation.GapSummary.DroppedCount != 16 {
		t.Fatalf("warning or gap summary is wrong: %#v", machine.Observation)
	}
	view, err = ProjectMachines(inventory, &snapshot, RelayAvailable, time.Nanosecond)
	if err != nil || *view.Machines[0].ObservationStatus != "old" {
		t.Fatal("90 seconds plus one nanosecond is not old")
	}
	view, err = ProjectMachines(inventory, &snapshot, RelayUnavailable, 0)
	if err != nil || *view.Machines[0].ObservationStatus != "untrusted" || view.Machines[0].Observation == nil {
		t.Fatal("unavailable transport did not preserve but distrust cache")
	}
	view, err = ProjectMachines(inventory, nil, RelayUnavailable, 0)
	if err != nil || view.Machines[0].EnrollmentStatus != nil || view.Machines[0].ObservationStatus != nil {
		t.Fatal("missing cache fabricated enrollment or observation status")
	}
}

func TestGapSummaryOverflowIsRefused(t *testing.T) {
	source := testSnapshot().Machines[0].Observation
	source.Gaps = []observation.Gap{
		{FirstSequence: 1, LastSequence: math.MaxUint64, DroppedCount: math.MaxUint64, FirstObservedAt: "2026-07-19T10:00:00Z", LastObservedAt: "2026-07-19T10:00:01Z"},
		{FirstSequence: math.MaxUint64, LastSequence: math.MaxUint64, DroppedCount: 1, FirstObservedAt: "2026-07-19T10:00:02Z", LastObservedAt: "2026-07-19T10:00:03Z"},
	}
	if _, err := projectObservation(source); err == nil {
		t.Fatal("gap sum overflow was accepted")
	}
}
