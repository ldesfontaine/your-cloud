package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
)

func TestHandlerRecentThenOld(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	handler := newTestHandler()
	handler.now = func() time.Time { return now }
	server := httptest.NewServer(handler)
	defer server.Close()

	postSignal(t, server.URL, validSignal("lab-machine-1"), http.StatusNoContent)
	states := fetchStates(t, server.URL)
	if states[0].MachineID != "lab-coordinateur" || states[0].Status != "absent" || states[1].MachineID != "lab-machine-1" || states[1].Status != "recent" {
		t.Fatalf("unexpected states after signal: %#v", states)
	}

	now = now.Add(presence.StaleAfter)
	states = fetchStates(t, server.URL)
	if states[0].Status != "absent" || states[1].Status != "old" {
		t.Fatalf("unexpected states after threshold: %#v", states)
	}
}

func TestHandlerRejectsHostileBodiesAndStaysAvailable(t *testing.T) {
	t.Parallel()

	handler := newTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
	}{
		{name: "missing id", body: `{"daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "malformed id", body: `{"machine_id":"../root","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "unknown id", body: `{"machine_id":"lab-machine-9","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "duplicate id", body: `{"machine_id":"lab-machine-9","machine_id":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "wrong field case", body: `{"Machine_ID":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"machine_id":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z","command":"id"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "second object", body: `{"machine_id":"lab-machine-1","daemon_version":"v0.0.1","sent_at":"2026-07-16T12:00:00Z"}{}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "wrong content type", body: `{}`, contentType: "text/plain", wantStatus: http.StatusBadRequest},
		{name: "oversized", body: strings.Repeat("x", int(presence.MaxBodyBytes)+1), contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, server.URL+"/v0/presence", strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", test.contentType)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status=%d body=%s", response.StatusCode, body)
			}

			postSignal(t, server.URL, validSignal("lab-coordinateur"), http.StatusNoContent)
		})
	}
}

func TestHandlerRejectsWrongMethods(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(newTestHandler())
	defer server.Close()
	for _, endpoint := range []string{"/v0/presence", "/v0/machines"} {
		request, err := http.NewRequest(http.MethodDelete, server.URL+endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s returned %d", endpoint, response.StatusCode)
		}
	}
}

func TestQueryMachinesRequiresTheExactV001Query(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(newTestHandler())
	defer server.Close()

	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
	}{
		{name: "empty object", body: `{}`, contentType: "application/json", wantStatus: http.StatusOK},
		{name: "missing content type", body: `{}`, wantStatus: http.StatusBadRequest},
		{name: "unsupported content type", body: `{}`, contentType: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "future filter", body: `{"machine_id":"lab-machine-1"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "null", body: `null`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "second object", body: `{}{}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "oversized", body: strings.Repeat(" ", int(maxQueryBodyBytes)+1), contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest("QUERY", server.URL+"/v0/machines", strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status=%d body=%s", response.StatusCode, body)
			}
			if response.Header.Get("Accept-Query") != `"application/json"` {
				t.Fatalf("Accept-Query=%q", response.Header.Get("Accept-Query"))
			}
		})
	}
}

func newTestHandler() *Handler {
	allowed := presence.AllowedMachineIDs()
	return NewHandler(NewStore(allowed), allowed, log.New(io.Discard, "", 0))
}

func validSignal(machineID string) presence.Signal {
	return presence.Signal{
		MachineID:     machineID,
		DaemonVersion: presence.Version,
		SentAt:        "2026-07-16T12:00:00Z",
	}
}

func postSignal(t *testing.T, serverURL string, signal presence.Signal, wantStatus int) {
	t.Helper()
	body, err := json.Marshal(signal)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(serverURL+"/v0/presence", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		responseBody, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, responseBody)
	}
}

func fetchStates(t *testing.T, serverURL string) []MachineState {
	t.Helper()
	request, err := http.NewRequest("QUERY", serverURL+"/v0/machines", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Machines []MachineState `json:"machines"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Machines
}
