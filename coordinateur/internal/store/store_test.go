package store

import (
	"context"
	"testing"
	"time"

	telemetryv1 "github.com/ldesfontaine/yourcloud/protocole/gen/go"
)

func TestStateIsIdempotentAndRejectsCollision(t *testing.T) {
	database, err := Open(t.TempDir(), 1024*1024, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	already, err := database.Save(ctx, "machine-1", "key", telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, 1, 1, []byte("first"))
	if err != nil || already {
		t.Fatalf("première insertion: already=%v err=%v", already, err)
	}
	already, err = database.Save(ctx, "machine-1", "key", telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, 1, 1, []byte("first"))
	if err != nil || !already {
		t.Fatalf("retransmission: already=%v err=%v", already, err)
	}
	if _, err := database.Save(ctx, "machine-1", "key", telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, 1, 1, []byte("other")); err == nil {
		t.Fatal("collision de séquence acceptée")
	}
}

func TestEventsArePagedAndRetainedOnce(t *testing.T) {
	database, err := Open(t.TempDir(), 1024*1024, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	observedAt := time.Now().UTC().Unix()
	for sequence := uint64(1); sequence <= 3; sequence++ {
		if _, err := database.Save(ctx, "machine-1", "key", telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT, sequence, observedAt, []byte{byte(sequence)}); err != nil {
			t.Fatal(err)
		}
	}
	items, next, more, err := database.Events(ctx, "machine-1", 0, 2)
	if err != nil || len(items) != 2 || next != 2 || !more {
		t.Fatalf("page inattendue: len=%d next=%d more=%v err=%v", len(items), next, more, err)
	}
}
