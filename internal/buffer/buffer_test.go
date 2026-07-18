package buffer

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func TestDefaultLimitsMatchMeasuredV002Contract(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	if limits.MaxBytes != 64*1024 || limits.MaxRecords != 120 || limits.MaxAge != time.Hour {
		t.Fatalf("unexpected v0.0.2 defaults: %#v", limits)
	}
}

func TestBufferPersistsOrderedDeliveryAcrossRestart(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 10, MaxAge: time.Hour}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 3; index++ {
		if _, err := queue.Enqueue("lab-machine-1", validHealth(), start.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	reopened, err := openAt(directory, limits, start.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		encoded, pendingSequence, err := reopened.Peek()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := observation.Decode(encoded)
		if err != nil || pendingSequence != sequence || decoded.Sequence != sequence {
			t.Fatalf("unexpected pending sequence: wire=%#v pending=%d error=%v", decoded, pendingSequence, err)
		}
		if err := reopened.Acknowledge(sequence, start.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := reopened.Peek(); !errors.Is(err, io.EOF) {
		t.Fatalf("drained buffer did not return EOF: %v", err)
	}
	stats, err := reopened.Stats()
	if err != nil || stats.PendingRecords != 0 || stats.PendingBytes != 0 || stats.NextSequence != 4 {
		t.Fatalf("unexpected drained stats: %#v %v", stats, err)
	}
}

func TestBufferStatsMeasureOnlyPendingObservationBytes(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	queue, err := Open(directory, Limits{MaxBytes: minimumMaxBytes, MaxRecords: 3, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	before, err := queue.Stats()
	if err != nil || before.PendingBytes != 0 {
		t.Fatalf("empty queue reported pending observation bytes: %#v %v", before, err)
	}
	envelope, err := queue.Enqueue("lab-machine-1", validHealth(), time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Encode()
	if err != nil {
		t.Fatal(err)
	}
	after, err := queue.Stats()
	if err != nil || after.PendingBytes != int64(len(encoded)) {
		t.Fatalf("pending bytes do not match the queued wire observation: got=%#v want=%d error=%v", after, len(encoded), err)
	}
}

func TestBufferSaturationPreservesCurrentAndCreatesVisibleGap(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 3, MaxAge: time.Hour}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 5; index++ {
		if _, err := queue.Enqueue("lab-machine-1", validHealth(), start.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	encoded, sequence, err := queue.Peek()
	if err != nil {
		t.Fatal(err)
	}
	first, err := observation.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 3 || len(first.Gaps) != 1 {
		t.Fatalf("saturation did not preserve the expected oldest record and gap: %#v", first)
	}
	gap := first.Gaps[0]
	if gap.FirstSequence != 1 || gap.LastSequence != 2 || gap.DroppedCount != 2 {
		t.Fatalf("unexpected gap: %#v", gap)
	}

	reopened, err := openAt(directory, limits, start.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	retried, retriedSequence, err := reopened.Peek()
	if err != nil || retriedSequence != sequence || string(retried) != string(encoded) {
		t.Fatalf("retry changed immutable payload: sequence=%d error=%v", retriedSequence, err)
	}
}

func TestBufferRejectsWrongAcknowledgementAndHostileState(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 3, MaxAge: time.Hour}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue("lab-machine-1", validHealth(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := queue.Acknowledge(2, time.Now()); err == nil {
		t.Fatal("wrong acknowledgement accepted")
	}

	path := filepath.Join(directory, stateFileName)
	if err := os.WriteFile(path, []byte(`{"schema":1,"schema":1,"next_sequence":2,"pending":[],"gaps":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(directory, limits); err == nil {
		t.Fatalf("ambiguous persisted state accepted: %#v", reopened)
	}
}

func TestInspectReadsWithoutRewritingState(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 3, MaxAge: time.Hour}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue("lab-machine-1", validHealth(), time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, stateFileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := Inspect(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Current == nil || inspection.Stats.PendingRecords != 1 || !bytes.Equal(before, after) {
		t.Fatalf("inspection mutated or omitted state: %#v", inspection)
	}
}

func TestBufferAgeLimitDropsExpiredObservation(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 10, MaxAge: time.Minute}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	if _, err := queue.Enqueue("lab-machine-1", validHealth(), start); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue("lab-machine-1", validHealth(), start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	encoded, _, err := queue.Peek()
	if err != nil {
		t.Fatal(err)
	}
	current, err := observation.Decode(encoded)
	if err != nil || current.Sequence != 2 || len(current.Gaps) != 1 || current.Gaps[0].FirstSequence != 1 {
		t.Fatalf("age eviction is not visible: %#v %v", current, err)
	}
}

func TestBufferPersistenceFailurePublishesNoSequenceAckOrDeliveryState(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 3, MaxAge: time.Hour}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	before, err := queue.Stats()
	if err != nil {
		t.Fatal(err)
	}

	writeState := queue.writeState
	diskFailure := errors.New("simulated disk failure")
	queue.writeState = func(state) error { return diskFailure }
	if _, err := queue.Enqueue("lab-machine-1", validHealth(), start); !errors.Is(err, diskFailure) {
		t.Fatalf("enqueue did not expose the persistence failure: %v", err)
	}
	after, err := queue.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("failed enqueue published candidate state: before=%#v after=%#v", before, after)
	}

	queue.writeState = writeState
	envelope, err := queue.Enqueue("lab-machine-1", validHealth(), start)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Sequence != 1 {
		t.Fatalf("failed enqueue consumed a sequence: got %d", envelope.Sequence)
	}
	encoded, sequence, err := queue.Peek()
	if err != nil {
		t.Fatal(err)
	}

	queue.writeState = func(state) error { return diskFailure }
	if err := queue.Acknowledge(sequence, start.Add(time.Minute)); !errors.Is(err, diskFailure) {
		t.Fatalf("acknowledgement did not expose the persistence failure: %v", err)
	}
	retried, retriedSequence, err := queue.Peek()
	if err != nil || retriedSequence != sequence || !bytes.Equal(retried, encoded) {
		t.Fatalf("failed acknowledgement removed or changed the pending payload: sequence=%d error=%v", retriedSequence, err)
	}
	if err := queue.SetDeliveryState("available", start.Add(time.Minute)); !errors.Is(err, diskFailure) {
		t.Fatalf("delivery transition did not expose the persistence failure: %v", err)
	}
	after, err = queue.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if after.DeliveryState != "unknown" || after.LastTransition != "" || after.PendingRecords != 1 {
		t.Fatalf("failed persistence published an acknowledgement or delivery state: %#v", after)
	}
}

func TestBufferPersistenceFailureDoesNotAttachGapInMemory(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	limits := Limits{MaxBytes: minimumMaxBytes, MaxRecords: 1, MaxAge: time.Hour}
	queue, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 2; index++ {
		if _, err := queue.Enqueue("lab-machine-1", validHealth(), start.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if len(queue.state.Gaps) != 1 || len(queue.state.Pending) != 1 || len(queue.state.Pending[0].Gaps) != 0 {
		t.Fatalf("test precondition does not contain one unattached gap: %#v", queue.state)
	}

	writeState := queue.writeState
	diskFailure := errors.New("simulated disk failure")
	queue.writeState = func(state) error { return diskFailure }
	if _, _, err := queue.Peek(); !errors.Is(err, diskFailure) {
		t.Fatalf("gap attachment did not expose the persistence failure: %v", err)
	}
	if len(queue.state.Gaps) != 1 || len(queue.state.Pending[0].Gaps) != 0 {
		t.Fatalf("failed persistence attached the gap only in memory: %#v", queue.state)
	}

	queue.writeState = writeState
	encoded, _, err := queue.Peek()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := observation.Decode(encoded)
	if err != nil || len(envelope.Gaps) != 1 || envelope.Gaps[0].FirstSequence != 1 {
		t.Fatalf("gap was not attached after persistence recovered: %#v %v", envelope, err)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func validHealth() observation.HostHealth {
	zero := uint64(0)
	return observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &zero},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
		RootFS: observation.RootFSResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
	}
}

func BenchmarkBufferEnqueueDurable(b *testing.B) {
	directory := b.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		b.Fatal(err)
	}
	queue, err := Open(directory, Limits{MaxBytes: minimumMaxBytes, MaxRecords: 1, MaxAge: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := queue.Enqueue("lab-machine-1", validHealth(), time.Now()); err != nil {
			b.Fatal(err)
		}
	}
}
