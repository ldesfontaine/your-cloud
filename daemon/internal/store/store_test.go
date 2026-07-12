package store

import (
	"context"
	"testing"

	telemetryv1 "github.com/lucas-desfontaine/your-cloud/protocole/gen/go"
)

func TestSequencesPersistAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := Open(dir, 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := first.NextSequence(ctx, telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE)
	if err != nil || sequence != 1 {
		t.Fatalf("première séquence: %d, %v", sequence, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir, 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	sequence, err = second.NextSequence(ctx, telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE)
	if err != nil || sequence != 2 {
		t.Fatalf("séquence reprise: %d, %v", sequence, err)
	}
}

func TestEventQueueEmitsGapAndDatabaseStaysBounded(t *testing.T) {
	ctx := context.Background()
	database, err := Open(t.TempDir(), 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var gap *Gap
	for sequence := uint64(1); sequence <= 80; sequence++ {
		candidate, err := database.EnqueueEvent(ctx, sequence, 1, "test", make([]byte, 4096))
		if err != nil {
			t.Fatal(err)
		}
		if candidate != nil {
			gap = candidate
		}
	}
	if gap == nil {
		t.Fatal("aucune lacune émise après débordement")
	}
	pages, pageSize, err := database.PageUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pages*pageSize > 256*1024 {
		t.Fatalf("base hors limite: %d", pages*pageSize)
	}
}
