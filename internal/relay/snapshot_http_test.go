package relay

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/enrollment"
	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/readeridentity"
)

const (
	snapshotInfrastructureID = "11111111-1111-4111-8111-111111111111"
	snapshotControllerID     = "22222222-2222-4222-8222-222222222222"
	snapshotHost             = "relay-reader.11111111-1111-4111-8111-111111111111.your-cloud.test:8444"
)

func TestSnapshotHandlerRendersEmptyAndObservedMachines(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy checks require the isolated root LAB runner")
	}
	handler, observationStore, readerCertificate := testSnapshotHandler(t, true)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return now }

	emptyResponse := performSnapshotRequest(handler, readerCertificate, http.MethodGet, "/v0/snapshot", snapshotHost, "application/json", "")
	if emptyResponse.Code != http.StatusOK || !strings.Contains(emptyResponse.Body.String(), `"machines":[{"machine_id":"lab-machine-1","enrollment_status":"active","observation":null}]`) {
		t.Fatalf("empty machine observation was not rendered exactly: status=%d body=%s", emptyResponse.Code, emptyResponse.Body.String())
	}

	up := uint64(42)
	total := uint64(1024)
	available := uint64(512)
	envelope, err := observation.NewEnvelope("lab-machine-1", 1, now.Add(-time.Second), observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &up},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: &total, AvailableBytes: &available},
		RootFS: observation.RootFSResult{Status: "error", Error: "source_unavailable"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := observationStore.Save("lab-machine-1", encoded, now); err != nil {
		t.Fatal(err)
	}
	observedResponse := performSnapshotRequest(handler, readerCertificate, http.MethodGet, "/v0/snapshot", snapshotHost, "application/json", "")
	if observedResponse.Code != http.StatusOK || !strings.Contains(observedResponse.Body.String(), `"received_at":"2026-07-19T12:00:00Z","gaps":[]`) {
		t.Fatalf("observed machine was not rendered exactly: status=%d body=%s", observedResponse.Code, observedResponse.Body.String())
	}
}

func TestSnapshotHandlerRejectsClosedSurface(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy checks require the isolated root LAB runner")
	}
	handler, _, certificate := testSnapshotHandler(t, false)
	tests := []struct {
		name   string
		method string
		path   string
		host   string
		accept string
		body   string
		status int
		code   string
	}{
		{name: "wrong host", method: http.MethodGet, path: "/v0/snapshot", host: "other:8444", accept: "application/json", status: 421, code: "origin_mismatch"},
		{name: "wrong method", method: http.MethodPost, path: "/v0/snapshot", host: snapshotHost, accept: "application/json", status: 405, code: "method_not_allowed"},
		{name: "wrong route", method: http.MethodGet, path: "/v0/other", host: snapshotHost, accept: "application/json", status: 404, code: "route_not_found"},
		{name: "empty query", method: http.MethodGet, path: "/v0/snapshot?", host: snapshotHost, accept: "application/json", status: 400, code: "invalid_request"},
		{name: "wrong accept", method: http.MethodGet, path: "/v0/snapshot", host: snapshotHost, accept: "*/*", status: 406, code: "not_acceptable"},
		{name: "body", method: http.MethodGet, path: "/v0/snapshot", host: snapshotHost, accept: "application/json", body: "x", status: 413, code: "request_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performSnapshotRequest(handler, certificate, test.method, test.path, test.host, test.accept, test.body)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"error_code":"`+test.code+`"`) {
				t.Fatalf("unexpected refusal: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSnapshotHandlerLimitsAuthenticatedRequestStarts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy checks require the isolated root LAB runner")
	}
	handler, _, certificate := testSnapshotHandler(t, false)
	for index := 0; index < 12; index++ {
		response := performSnapshotRequest(handler, certificate, http.MethodGet, "/v0/snapshot", snapshotHost, "application/json", "")
		if response.Code != http.StatusOK {
			t.Fatalf("request %d inside rate bound failed: %d %s", index+1, response.Code, response.Body.String())
		}
	}
	response := performSnapshotRequest(handler, certificate, http.MethodGet, "/v0/snapshot", snapshotHost, "application/json", "")
	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), `"error_code":"rate_limited"`) {
		t.Fatalf("thirteenth authenticated request was not bounded: %d %s", response.Code, response.Body.String())
	}
}

func TestSnapshotHandlerAbortsWhenRequestIDRandomnessFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy checks require the isolated root LAB runner")
	}
	handler, _, certificate := testSnapshotHandler(t, false)
	handler.random = bytes.NewReader(nil)
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("randomness failure did not abort the HTTP response: %#v", recovered)
		}
	}()
	_ = performSnapshotRequest(handler, certificate, http.MethodGet, "/wrong", snapshotHost, "application/json", "")
}

func testSnapshotHandler(t *testing.T, withMachine bool) (*SnapshotHandler, *ObservationStore, *x509.Certificate) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	readerCertificate := snapshotReaderCertificate(t)
	readerDigest := sha256.Sum256(readerCertificate.Raw)
	manifestPath := filepath.Join(directory, "relay-reader.json")
	manifest := fmt.Sprintf(
		`{"schema_version":1,"controller_id":"%s","infrastructure_id":"%s","uri":"%s","certificate_serial":"2a","certificate_sha256":"%s","status":"active"}`,
		snapshotControllerID,
		snapshotInfrastructureID,
		readeridentity.URI(snapshotInfrastructureID, snapshotControllerID),
		hex.EncodeToString(readerDigest[:]),
	)
	writeRootPolicy(t, manifestPath, manifest)
	readers, err := readeridentity.OpenStore(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	machines := "[]"
	if withMachine {
		machines = `[{"machine_id":"lab-machine-1","certificate_serial":"2b","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"active"}]`
	}
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	writeRootPolicy(t, enrollmentPath, fmt.Sprintf(`{"schema":2,"infrastructure_id":"%s","machines":%s}`, snapshotInfrastructureID, machines))
	enrollments, err := enrollment.OpenStore(enrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := OpenObservationStore(filepath.Join(directory, "observations"))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewSnapshotHandler(enrollments, observations, readers, snapshotHost, &sync.RWMutex{})
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }
	return handler, observations, readerCertificate
}

func snapshotReaderCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	identity, err := url.Parse(readeridentity.URI(snapshotInfrastructureID, snapshotControllerID))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	return &x509.Certificate{
		Raw:          []byte("snapshot reader certificate"),
		SerialNumber: big.NewInt(42),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identity},
	}
}

func performSnapshotRequest(handler *SnapshotHandler, certificate *x509.Certificate, method, path, host, accept, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	request.Host = host
	request.Header.Set("Accept", accept)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func writeRootPolicy(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSnapshotCarriesTheDeclaredReadingsWithoutReadingThem is the Relay's half of
// `#107`'s transport, and the Relay's half is to carry and nothing else.
//
// It neither asks for a reading, nor interprets one, nor answers a Daemon about
// one: the section it received is the section the Controller receives, and a
// machine that declared no target adds no field at all to the snapshot every
// previous palier proved.
func TestSnapshotCarriesTheDeclaredReadingsWithoutReadingThem(t *testing.T) {
	t.Parallel()
	up := uint64(42)
	readings := []observation.ExternalReading{{ProbePort: 5000, Outcome: observation.ExternalAnswered}}
	envelope, err := observation.NewEnvelope("lab-machine-1", 1,
		time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC), observation.HostHealth{
			Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &up},
			Memory: observation.MemoryResult{Status: "ok", TotalBytes: &up, AvailableBytes: &up},
			RootFS: observation.RootFSResult{Status: "ok", TotalBytes: &up, AvailableBytes: &up},
		}, readings)
	if err != nil {
		t.Fatal(err)
	}
	stored := ObservationSnapshot{Envelope: envelope, ReceivedAt: "2026-08-07T10:00:01Z"}
	carried, err := canonicalSnapshotObservation(stored)
	if err != nil || len(carried.External) != 1 || carried.External[0] != readings[0] {
		t.Fatalf("the Relay did not carry the readings unchanged: %+v %v", carried, err)
	}
	encoded, err := json.Marshal(carried)
	if err != nil || !strings.Contains(string(encoded), `"external":[{"probe_port":5000,"outcome":"answered"}]`) {
		t.Fatalf("the carried section is not what the Controller decodes: %s %v", encoded, err)
	}

	stored.Envelope.External = nil
	silent, err := canonicalSnapshotObservation(stored)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(silent)
	if err != nil || strings.Contains(string(encoded), "external") {
		t.Fatalf("a machine with no declared target changed the snapshot: %s %v", encoded, err)
	}
}
