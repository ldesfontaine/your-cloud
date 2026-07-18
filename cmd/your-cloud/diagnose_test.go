package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/buffer"
	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func TestDiagnosticArgumentsRefuseFreeSubjectFormatAndPath(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		nil,
		{"buffer"},
		{"observation", "--format=yaml"},
		{"observation", "--path=/tmp/state"},
		{"observation", "unexpected"},
	} {
		if configuration, err := parseDiagnosticArguments(arguments); err == nil {
			t.Fatalf("unsafe diagnostic arguments accepted: %q as %#v", arguments, configuration)
		}
	}
	for _, arguments := range [][]string{{"observation"}, {"observation", "--format=json"}} {
		if _, err := parseDiagnosticArguments(arguments); err != nil {
			t.Fatalf("valid diagnostic arguments rejected: %q: %v", arguments, err)
		}
	}
}

func TestDiagnosticRendersBoundedTextAndJSONWithoutCollectorValues(t *testing.T) {
	t.Parallel()
	zero := uint64(0)
	envelope, err := observation.NewEnvelope("lab-machine-1", 7, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC), observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &zero},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
		RootFS: observation.RootFSResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
	})
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := buildObservationDiagnostic(buffer.Inspection{
		Current: &envelope,
		Stats: buffer.Stats{
			PendingRecords: 2, PendingBytes: 512, NextSequence: 8,
			GapCount: 1, LastDelivered: "2026-07-18T11:59:30Z", DeliveryState: "unavailable",
		},
	}, &x509.Certificate{NotAfter: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}

	var textOutput bytes.Buffer
	if err := renderObservationDiagnostic(&textOutput, "text", diagnostic); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOutput.String(), "delivery: unavailable") ||
		!strings.Contains(textOutput.String(), "last delivered: 2026-07-18T11:59:30Z") ||
		strings.Contains(textOutput.String(), "uptime_seconds") {
		t.Fatalf("text diagnostic widened its contract: %s", textOutput.String())
	}

	var jsonOutput bytes.Buffer
	if err := renderObservationDiagnostic(&jsonOutput, "json", diagnostic); err != nil {
		t.Fatal(err)
	}
	var rendered map[string]json.RawMessage
	if err := json.Unmarshal(jsonOutput.Bytes(), &rendered); err != nil {
		t.Fatal(err)
	}
	if _, present := rendered["health"]; present {
		t.Fatal("diagnostic exposed collector values")
	}
	if _, present := rendered["buffer"]; !present {
		t.Fatal("diagnostic omitted buffer health")
	}
}

func TestDiagnosticRequiresLocalRootAuthority(t *testing.T) {
	t.Parallel()
	if err := requireDiagnosticAdministrator(0); err != nil {
		t.Fatalf("local root authority refused: %v", err)
	}
	if err := requireDiagnosticAdministrator(1000); err == nil {
		t.Fatal("non-root diagnostic authority accepted")
	}
}
