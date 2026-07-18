package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/buffer"
	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func TestCollectorPersistsFixedHostHealth(t *testing.T) {
	t.Parallel()
	localBuffer := daemonTestBuffer(t)
	collector, err := NewCollector("lab-machine-1", localBuffer, observation.Sources{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/proc/uptime" {
				return []byte("10.0 2.0"), nil
			}
			return []byte("MemTotal: 100 kB\nMemAvailable: 50 kB\n"), nil
		},
		StatFS: func(string) (observation.FileSystemStats, error) {
			return observation.FileSystemStats{BlockSize: 1, TotalBlocks: 100, AvailableBlocks: 50}, nil
		},
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	collector.now = func() time.Time { return time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC) }
	if err := collector.CollectOnce(); err != nil {
		t.Fatal(err)
	}
	encoded, sequence, err := localBuffer.Peek()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := observation.Decode(encoded)
	if err != nil || sequence != 1 || envelope.Profile != observation.Profile {
		t.Fatalf("fixed profile was not persisted: %#v sequence=%d error=%v", envelope, sequence, err)
	}
}

func TestPublisherRemovesOnlyAnExactlyAcknowledgedObservation(t *testing.T) {
	t.Parallel()
	localBuffer := daemonTestBuffer(t)
	if _, err := localBuffer.Enqueue("lab-machine-1", daemonHealth(), time.Now()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != ApprovedRelayOrigin+observationPath || request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %s %s %#v", request.Method, request.URL, request.Header)
		}
		return jsonResponse(http.StatusOK, encodeAck("lab-machine-1", 1, false)), nil
	})}
	publisher, err := NewPublisher("lab-machine-1", ApprovedRelayOrigin, localBuffer, client, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := localBuffer.Peek(); !errors.Is(err, io.EOF) {
		t.Fatalf("acknowledged observation remained pending: %v", err)
	}
}

func TestPublisherKeepsObservationAfterHostileAcknowledgement(t *testing.T) {
	t.Parallel()
	for _, body := range [][]byte{
		encodeAck("lab-machine-1", 2, false),
		encodeAck("lab-coordinateur", 1, false),
		[]byte(`{"schema":1,"machine_id":"lab-machine-1","sequence":1,"already_present":false,"command":"id"}`),
		bytes.Repeat([]byte("x"), maxAckBytes+1),
	} {
		localBuffer := daemonTestBuffer(t)
		if _, err := localBuffer.Enqueue("lab-machine-1", daemonHealth(), time.Now()); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, body), nil
		})}
		publisher, err := NewPublisher("lab-machine-1", ApprovedRelayOrigin, localBuffer, client, log.New(io.Discard, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := publisher.SendOnce(context.Background()); err == nil {
			t.Fatalf("hostile acknowledgement accepted: %s", body)
		}
		if _, sequence, err := localBuffer.Peek(); err != nil || sequence != 1 {
			t.Fatalf("pending observation was removed: sequence=%d error=%v", sequence, err)
		}
	}
}

func TestPublisherRejectsEveryOtherEndpoint(t *testing.T) {
	t.Parallel()
	localBuffer := daemonTestBuffer(t)
	for _, endpoint := range []string{
		"http://relay.v0-0-2.your-cloud.test:8443",
		"https://relay.v0-0-2.your-cloud.test",
		"https://relay.v0-0-2.your-cloud.test:9443",
		"https://admin@relay.v0-0-2.your-cloud.test:8443",
		"https://relay.v0-0-2.your-cloud.test:8443/path",
		"https://relay.v0-0-2.your-cloud.test:8443?query=x",
		"https://relay.v0-0-2.your-cloud.test:8443#fragment",
	} {
		if publisher, err := NewPublisher("lab-machine-1", endpoint, localBuffer, &http.Client{}, log.New(io.Discard, "", 0)); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q as %#v", endpoint, publisher)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}

func daemonTestBuffer(t *testing.T) *buffer.Buffer {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := buffer.Open(directory, buffer.Limits{MaxBytes: 16 * 1024, MaxRecords: 10, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func daemonHealth() observation.HostHealth {
	zero := uint64(0)
	return observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &zero},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
		RootFS: observation.RootFSResult{Status: "ok", TotalBytes: &zero, AvailableBytes: &zero},
	}
}
