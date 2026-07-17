package daemon

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
)

func TestSenderSendsOnlyPresenceSchema(t *testing.T) {
	t.Parallel()

	received := make(chan presence.Signal, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v0/presence" || request.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		defer request.Body.Close()
		var signal presence.Signal
		decoder := jsonNewStrictDecoder(request.Body)
		if err := decoder.Decode(&signal); err != nil {
			t.Errorf("decode signal: %v", err)
		}
		received <- signal
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sender, err := NewSender("lab-machine-1", server.URL, time.Second, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	sender.now = func() time.Time { return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC) }
	if err := sender.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	signal := <-received
	if signal.MachineID != "lab-machine-1" || signal.DaemonVersion != presence.Version || signal.SentAt != "2026-07-16T12:00:00Z" {
		t.Fatalf("unexpected signal: %#v", signal)
	}
}

func TestSenderLogsOnlyFailureAndRecoveryTransitions(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		if requests <= 2 {
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var logs bytes.Buffer
	sender, err := NewSender("lab-machine-1", server.URL, time.Second, log.New(&logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	sender.sendAndLog(context.Background())
	sender.sendAndLog(context.Background())
	sender.sendAndLog(context.Background())

	if strings.Count(logs.String(), "presence unavailable") != 1 {
		t.Fatalf("failure log was not deduplicated: %q", logs.String())
	}
	if strings.Count(logs.String(), "presence recovered") != 1 {
		t.Fatalf("recovery transition missing: %q", logs.String())
	}
}

func TestSenderRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		machineID string
		relayURL  string
		interval  time.Duration
	}{
		{name: "malformed id", machineID: "../root", relayURL: "http://127.0.0.1:8080", interval: time.Second},
		{name: "https not in contract", machineID: "lab-machine-1", relayURL: "https://127.0.0.1:8080", interval: time.Second},
		{name: "relay path", machineID: "lab-machine-1", relayURL: "http://127.0.0.1:8080/admin", interval: time.Second},
		{name: "relay userinfo", machineID: "lab-machine-1", relayURL: "http://admin@127.0.0.1:8080", interval: time.Second},
		{name: "relay query", machineID: "lab-machine-1", relayURL: "http://127.0.0.1:8080?target=other", interval: time.Second},
		{name: "relay empty query", machineID: "lab-machine-1", relayURL: "http://127.0.0.1:8080?", interval: time.Second},
		{name: "relay fragment", machineID: "lab-machine-1", relayURL: "http://127.0.0.1:8080#other", interval: time.Second},
		{name: "zero interval", machineID: "lab-machine-1", relayURL: "http://127.0.0.1:8080", interval: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSender(test.machineID, test.relayURL, test.interval, log.New(io.Discard, "", 0)); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestSenderReportsRelayRefusal(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "refused", http.StatusBadRequest)
	}))
	defer server.Close()
	sender, err := NewSender("lab-machine-1", server.URL, time.Second, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendOnce(context.Background()); err == nil {
		t.Fatal("Relay refusal was ignored")
	}
}
