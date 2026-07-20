package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func snapshotResponse(t *testing.T, snapshot RelaySnapshot) *http.Response {
	t.Helper()
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func TestRelayReaderSendsExactRequestReusesAndForcesFreshRead(t *testing.T) {
	directory := privateTestDirectory(t)
	cache, err := OpenRelayCacheStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		if request.Method != http.MethodGet || request.URL.String() != "https://relay-reader."+testInfrastructureID+".v0-0-3.your-cloud.test:8444/v0/snapshot" ||
			request.Host != "relay-reader."+testInfrastructureID+".v0-0-3.your-cloud.test:8444" || request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != "" {
			t.Fatalf("unexpected reader request: %#v", request)
		}
		return snapshotResponse(t, testSnapshot()), nil
	})}
	host := "relay-reader." + testInfrastructureID + ".v0-0-3.your-cloud.test:8444"
	reader, err := NewRelayReader(client, host, testControllerID, testInfrastructureID, cache)
	if err != nil {
		t.Fatal(err)
	}
	reader.sample = func() clockSample { return clockSample{civil: base, monotonic: base} }
	if _, status, err := reader.Read(context.Background(), time.Time{}); err != nil || status != RelayAvailable {
		t.Fatalf("nominal read failed: %s %v", status, err)
	}
	if _, status, err := reader.Read(context.Background(), time.Time{}); err != nil || status != RelayAvailable {
		t.Fatalf("five-second reuse failed: %s %v", status, err)
	}
	if _, status, err := reader.Read(context.Background(), base.Add(time.Nanosecond)); err != nil || status != RelayAvailable {
		t.Fatalf("forced fresh read failed: %s %v", status, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected one reused and one forced request, got %d network calls", calls)
	}
}

func TestRelayReaderRejectsHostileResponseWithoutReplacingCache(t *testing.T) {
	directory := privateTestDirectory(t)
	cache, err := OpenRelayCacheStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	current := testSnapshot()
	if err := cache.Commit(current); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema_version":1}`)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}, "Cache-Control": {"no-store"}},
			Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
		}, nil
	})}
	host := "relay-reader." + testInfrastructureID + ".v0-0-3.your-cloud.test:8444"
	reader, _ := NewRelayReader(client, host, testControllerID, testInfrastructureID, cache)
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	reader.sample = func() clockSample { return clockSample{civil: base, monotonic: base} }
	got, status, err := reader.Read(context.Background(), time.Time{})
	if err == nil || status != RelayUnavailable || got == nil || got.SnapshotAt != current.SnapshotAt {
		t.Fatalf("hostile response did not preserve distrusted cache: status=%s err=%v snapshot=%#v", status, err, got)
	}
}

func TestFreshnessUsesUTCWallAndMonotonicDurations(t *testing.T) {
	snapshot := testSnapshot()
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	if err := validateFreshness(
		clockSample{civil: base, monotonic: base},
		clockSample{civil: base.Add(time.Second), monotonic: base.Add(time.Second)},
		snapshot,
	); err != nil {
		t.Fatalf("stable clock rejected: %v", err)
	}
	if err := validateFreshness(
		clockSample{civil: base, monotonic: base},
		clockSample{civil: base.Add(2 * time.Second), monotonic: base},
		snapshot,
	); err == nil {
		t.Fatal("civil clock correction over one second was accepted")
	}
	snapshot.SnapshotAt = base.Add(30*time.Second + time.Nanosecond).Format(time.RFC3339Nano)
	if err := validateFreshness(
		clockSample{civil: base, monotonic: base},
		clockSample{civil: base, monotonic: base},
		snapshot,
	); err == nil {
		t.Fatal("snapshot beyond the inclusive 30-second bound was accepted")
	}
}

func TestRelayErrorEnvelopeIsClosedAndBounded(t *testing.T) {
	requestID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))
	body := []byte(`{"schema_version":1,"error_code":"rate_limited","request_id":"` + requestID + `"}`)
	response := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header: http.Header{
			"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "Retry-After": {"2"},
		},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}
	if err := validateRelayProblem(response); err != nil {
		t.Fatalf("valid Relay problem rejected: %v", err)
	}
	body = []byte(`{"schema_version":1,"error_code":"other","request_id":"` + requestID + `"}`)
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	if err := validateRelayProblem(response); err == nil {
		t.Fatal("unknown error code was accepted")
	}
}
