package relay

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func TestObservationStorePersistsAndAcceptsExactReplay(t *testing.T) {
	t.Parallel()
	directory := privateRelayDirectory(t)
	store, err := OpenObservationStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope := relayTestEnvelope(t, 1, nil)
	encoded, err := envelope.Encode()
	if err != nil {
		t.Fatal(err)
	}
	receivedAt := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	if _, already, err := store.Save("lab-machine-1", encoded, receivedAt); err != nil || already {
		t.Fatalf("new observation rejected or marked duplicate: already=%t error=%v", already, err)
	}
	if _, already, err := store.Save("lab-machine-1", encoded, receivedAt.Add(time.Second)); err != nil || !already {
		t.Fatalf("exact replay rejected: already=%t error=%v", already, err)
	}

	reopened, err := OpenObservationStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	stored, storedAt, found := reopened.Snapshot("lab-machine-1")
	if !found || stored.Sequence != 1 || storedAt != receivedAt.Format(time.RFC3339Nano) {
		t.Fatalf("durable observation missing: %#v %q %t", stored, storedAt, found)
	}
}

func TestObservationStoreRequiresGapForSkippedSequence(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	third := relayTestEnvelope(t, 3, nil)
	encoded, _ := third.Encode()
	if _, _, err := store.Save("lab-machine-1", encoded, time.Now()); err == nil {
		t.Fatal("skipped first sequence accepted without a gap")
	}
	third.Gaps = []observation.Gap{{
		FirstSequence: 1, LastSequence: 2, DroppedCount: 2,
		FirstObservedAt: "2026-07-18T11:59:58Z", LastObservedAt: "2026-07-18T11:59:59Z",
	}}
	encoded, _ = third.Encode()
	if _, _, err := store.Save("lab-machine-1", encoded, time.Now()); err != nil {
		t.Fatalf("explicitly covered gap rejected: %v", err)
	}
}

func TestObservationStoreRejectsGapsOutsideExactSkippedRange(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	first := relayTestEnvelope(t, 1, nil)
	encoded, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	receivedAt := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	if _, _, err := store.Save("lab-machine-1", encoded, receivedAt); err != nil {
		t.Fatal(err)
	}

	gap := func(first, last uint64) observation.Gap {
		return observation.Gap{
			FirstSequence: first, LastSequence: last, DroppedCount: last - first + 1,
			FirstObservedAt: "2026-07-18T11:59:58Z", LastObservedAt: "2026-07-18T11:59:59Z",
		}
	}
	tests := []struct {
		name     string
		sequence uint64
		gaps     []observation.Gap
	}{
		{name: "historical gap without a skip", sequence: 2, gaps: []observation.Gap{gap(1, 1)}},
		{name: "future gap beyond the envelope", sequence: 3, gaps: []observation.Gap{gap(2, 3)}},
		{name: "gap overlaps the durable sequence", sequence: 4, gaps: []observation.Gap{gap(1, 3)}},
		{name: "gap set leaves an internal hole", sequence: 5, gaps: []observation.Gap{gap(2, 2), gap(4, 4)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hostile := relayTestEnvelope(t, test.sequence, test.gaps)
			hostileBytes, err := json.Marshal(hostile)
			if err != nil {
				t.Fatal(err)
			}
			if _, already, err := store.Save("lab-machine-1", hostileBytes, receivedAt.Add(time.Second)); err == nil || already {
				t.Fatalf("out-of-range gaps were accepted: already=%t error=%v", already, err)
			}
			stored, _, found := store.Snapshot("lab-machine-1")
			if !found || stored.Sequence != 1 {
				t.Fatalf("refused gaps changed durable state: %#v found=%t", stored, found)
			}
		})
	}

	fourth := relayTestEnvelope(t, 4, []observation.Gap{gap(2, 3)})
	fourthBytes, err := fourth.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, already, err := store.Save("lab-machine-1", fourthBytes, receivedAt.Add(2*time.Second)); err != nil || already {
		t.Fatalf("exact skipped range was refused: already=%t error=%v", already, err)
	}
}

func TestObservationStorePreservesReceivedGapAfterNewerState(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	third := relayTestEnvelope(t, 3, []observation.Gap{{
		FirstSequence: 1, LastSequence: 2, DroppedCount: 2,
		FirstObservedAt: "2026-07-18T11:59:58Z", LastObservedAt: "2026-07-18T11:59:59Z",
	}})
	encoded, _ := third.Encode()
	if _, _, err := store.Save("lab-machine-1", encoded, time.Now()); err != nil {
		t.Fatal(err)
	}
	fourth := relayTestEnvelope(t, 4, nil)
	encoded, _ = fourth.Encode()
	if _, _, err := store.Save("lab-machine-1", encoded, time.Now()); err != nil {
		t.Fatal(err)
	}
	stored, _, found := store.Snapshot("lab-machine-1")
	if !found || len(stored.Gaps) != 1 || stored.Gaps[0].FirstSequence != 1 || stored.Gaps[0].LastSequence != 2 {
		t.Fatalf("later state erased the received gap: %#v", stored.Gaps)
	}
}

func TestObservationStoreRejectsCollisionOlderAndWrongIdentity(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	first := relayTestEnvelope(t, 1, nil)
	encoded, _ := first.Encode()
	if _, _, err := store.Save("lab-machine-1", encoded, time.Now()); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.ObservedAt = "2026-07-18T12:00:02Z"
	changedBytes, _ := changed.Encode()
	if _, _, err := store.Save("lab-machine-1", changedBytes, time.Now()); err == nil {
		t.Fatal("sequence collision accepted")
	}
	if _, _, err := store.Save("lab-coordinateur", encoded, time.Now()); err == nil {
		t.Fatal("certificate and body identity mismatch accepted")
	}
}

func TestObservationStorePersistenceFailurePublishesNoStateOrAcknowledgement(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	first := relayTestEnvelope(t, 1, nil)
	firstBytes, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	if _, already, err := store.Save("lab-machine-1", firstBytes, start); err != nil || already {
		t.Fatalf("test precondition did not persist sequence 1: already=%t error=%v", already, err)
	}

	second := relayTestEnvelope(t, 2, nil)
	secondBytes, err := second.Encode()
	if err != nil {
		t.Fatal(err)
	}
	writeState := store.writeState
	diskFailure := errors.New("simulated disk failure")
	store.writeState = func(observationStoreState) error { return diskFailure }
	if _, already, err := store.Save("lab-machine-1", secondBytes, start.Add(time.Second)); !errors.Is(err, diskFailure) || already {
		t.Fatalf("failed persistence was hidden or acknowledged: already=%t error=%v", already, err)
	}
	stored, _, found := store.Snapshot("lab-machine-1")
	if !found || stored.Sequence != 1 {
		t.Fatalf("failed persistence published sequence 2 in memory: %#v found=%t", stored, found)
	}

	store.writeState = writeState
	if _, already, err := store.Save("lab-machine-1", secondBytes, start.Add(2*time.Second)); err != nil || already {
		t.Fatalf("recovered persistence treated sequence 2 as already durable: already=%t error=%v", already, err)
	}
	if _, already, err := store.Save("lab-machine-1", secondBytes, start.Add(3*time.Second)); err != nil || !already {
		t.Fatalf("exact replay after durable save was not acknowledged: already=%t error=%v", already, err)
	}
}

func privateRelayDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func relayTestEnvelope(t *testing.T, sequence uint64, gaps []observation.Gap) observation.Envelope {
	t.Helper()
	zero := uint64(0)
	health := observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &zero},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
		RootFS: observation.RootFSResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
	}
	envelope, err := observation.NewEnvelope(
		"lab-machine-1", sequence,
		time.Date(2026, 7, 18, 12, 0, int(sequence), 0, time.UTC), health, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Gaps = gaps
	return envelope
}
