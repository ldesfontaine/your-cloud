package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/enrollment"
	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/readeridentity"
)

const (
	maxSnapshotBytes = 2 * 1024 * 1024
	maxErrorBytes    = 1024
	maxReaderHeaders = 8 * 1024
	maxSnapshotGaps  = 8192
)

// SnapshotHandler serves the one read-only Controller-to-Relay route.
type SnapshotHandler struct {
	enrollments   *enrollment.Store
	observations  *ObservationStore
	readers       *readeridentity.Store
	host          string
	now           func() time.Time
	requestSlot   chan struct{}
	rateMu        sync.Mutex
	requestStarts []time.Time
	stateLock     *sync.RWMutex
	random        io.Reader
}

type snapshotDocument struct {
	SchemaVersion    int               `json:"schema_version"`
	InfrastructureID string            `json:"infrastructure_id"`
	ControllerID     string            `json:"controller_id"`
	SnapshotAt       string            `json:"snapshot_at"`
	Machines         []snapshotMachine `json:"machines"`
}

type snapshotMachine struct {
	MachineID        string               `json:"machine_id"`
	EnrollmentStatus string               `json:"enrollment_status"`
	Observation      *snapshotObservation `json:"observation"`
}

type snapshotObservation struct {
	SchemaVersion int                    `json:"schema_version"`
	MachineID     string                 `json:"machine_id"`
	DaemonVersion string                 `json:"daemon_version"`
	Profile       string                 `json:"profile"`
	Sequence      uint64                 `json:"sequence"`
	ObservedAt    string                 `json:"observed_at"`
	ReceivedAt    string                 `json:"received_at"`
	Gaps          []observation.Gap      `json:"gaps"`
	Health        observation.HostHealth `json:"health"`
}

type readerProblem struct {
	SchemaVersion int    `json:"schema_version"`
	ErrorCode     string `json:"error_code"`
	RequestID     string `json:"request_id"`
}

// NewSnapshotHandler requires all three authorities and the exact Host value.
func NewSnapshotHandler(
	enrollments *enrollment.Store,
	observations *ObservationStore,
	readers *readeridentity.Store,
	host string,
	stateLock *sync.RWMutex,
) (*SnapshotHandler, error) {
	if enrollments == nil || observations == nil || readers == nil || stateLock == nil {
		return nil, errors.New("enrollment, observation, reader and state lock are required")
	}
	if host == "" || strings.ContainsAny(host, "/?#@") {
		return nil, errors.New("exact reader Host is required")
	}
	return &SnapshotHandler{
		enrollments:  enrollments,
		observations: observations,
		readers:      readers,
		host:         host,
		now:          time.Now,
		requestSlot:  make(chan struct{}, 1),
		stateLock:    stateLock,
		random:       rand.Reader,
	}, nil
}

// ServeHTTP applies the closed method, origin, header and body surface.
func (handler *SnapshotHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Host != handler.host {
		handler.writeProblem(response, http.StatusMisdirectedRequest, "origin_mismatch", false)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		handler.writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", false)
		return
	}
	if request.URL.Path != "/v0/snapshot" {
		handler.writeProblem(response, http.StatusNotFound, "route_not_found", false)
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Transfer-Encoding") != "" {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", false)
		return
	}
	if request.Header.Get("Content-Type") != "" {
		handler.writeProblem(response, http.StatusUnsupportedMediaType, "unsupported_media_type", false)
		return
	}
	if request.Header.Get("Accept") != "application/json" {
		handler.writeProblem(response, http.StatusNotAcceptable, "not_acceptable", false)
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", false)
		return
	}
	oneBodyByte, err := io.ReadAll(io.LimitReader(request.Body, 1))
	if err != nil || len(oneBodyByte) != 0 {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", false)
		return
	}
	if estimatedHeaderBytes(request.Header) > maxReaderHeaders {
		handler.writeProblem(response, http.StatusRequestHeaderFieldsTooLarge, "headers_too_large", false)
		return
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		handler.writeProblem(response, http.StatusForbidden, "reader_forbidden", false)
		return
	}
	handler.stateLock.RLock()
	defer handler.stateLock.RUnlock()
	if handler.readers.Authorize(request.TLS.PeerCertificates[0], handler.now()) != nil {
		handler.writeProblem(response, http.StatusForbidden, "reader_forbidden", false)
		return
	}
	if !handler.enterRequest(handler.now()) {
		handler.writeProblem(response, http.StatusTooManyRequests, "rate_limited", true)
		return
	}
	defer handler.leaveRequest()
	encoded, err := handler.snapshot()
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "snapshot_unavailable", false)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *SnapshotHandler) enterRequest(now time.Time) bool {
	handler.rateMu.Lock()
	cutoff := now.Add(-time.Minute)
	firstCurrent := 0
	for firstCurrent < len(handler.requestStarts) && handler.requestStarts[firstCurrent].Before(cutoff) {
		firstCurrent++
	}
	handler.requestStarts = append(handler.requestStarts[:0], handler.requestStarts[firstCurrent:]...)
	if len(handler.requestStarts) >= 12 {
		handler.rateMu.Unlock()
		return false
	}
	handler.requestStarts = append(handler.requestStarts, now)
	handler.rateMu.Unlock()
	select {
	case handler.requestSlot <- struct{}{}:
		return true
	default:
		return false
	}
}

func (handler *SnapshotHandler) leaveRequest() {
	<-handler.requestSlot
}

func (handler *SnapshotHandler) snapshot() ([]byte, error) {
	registry, registryErr := handler.enrollments.Snapshot()
	manifest, manifestErr := handler.readers.Snapshot()
	states := handler.observations.SnapshotAll()
	snapshotAt := handler.now().UTC()
	if registryErr != nil || manifestErr != nil || !registry.ReaderReady() {
		return nil, errors.New("snapshot authorities are unavailable")
	}
	if registry.InfrastructureID != manifest.InfrastructureID {
		return nil, errors.New("snapshot infrastructure identities diverge")
	}
	document := snapshotDocument{
		SchemaVersion:    1,
		InfrastructureID: registry.InfrastructureID,
		ControllerID:     manifest.ControllerID,
		SnapshotAt:       snapshotAt.Format(time.RFC3339Nano),
		Machines:         make([]snapshotMachine, 0, len(registry.Machines)),
	}
	totalGaps := 0
	for _, entry := range registry.Machines {
		machine := snapshotMachine{MachineID: entry.MachineID, EnrollmentStatus: entry.Status}
		stored, found := states[entry.MachineID]
		if found {
			observationView, err := canonicalSnapshotObservation(stored)
			if err != nil {
				return nil, err
			}
			totalGaps += len(observationView.Gaps)
			if totalGaps > maxSnapshotGaps {
				return nil, errors.New("snapshot contains too many gaps")
			}
			machine.Observation = observationView
		}
		document.Machines = append(document.Machines, machine)
	}
	sort.Slice(document.Machines, func(left, right int) bool {
		return document.Machines[left].MachineID < document.Machines[right].MachineID
	})
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > maxSnapshotBytes {
		return nil, errors.New("snapshot cannot be encoded within its bound")
	}
	return encoded, nil
}

func canonicalSnapshotObservation(stored ObservationSnapshot) (*snapshotObservation, error) {
	if err := stored.Envelope.Validate(); err != nil {
		return nil, err
	}
	observedAt, err := time.Parse(time.RFC3339Nano, stored.Envelope.ObservedAt)
	if err != nil {
		return nil, err
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, stored.ReceivedAt)
	if err != nil {
		return nil, err
	}
	gaps := make([]observation.Gap, len(stored.Gaps))
	copy(gaps, stored.Gaps)
	for index := range gaps {
		first, firstErr := time.Parse(time.RFC3339Nano, gaps[index].FirstObservedAt)
		last, lastErr := time.Parse(time.RFC3339Nano, gaps[index].LastObservedAt)
		if firstErr != nil || lastErr != nil {
			return nil, errors.New("snapshot gap contains an invalid timestamp")
		}
		gaps[index].FirstObservedAt = first.UTC().Format(time.RFC3339Nano)
		gaps[index].LastObservedAt = last.UTC().Format(time.RFC3339Nano)
	}
	return &snapshotObservation{
		SchemaVersion: stored.Envelope.SchemaVersion,
		MachineID:     stored.Envelope.MachineID,
		DaemonVersion: stored.Envelope.DaemonVersion,
		Profile:       stored.Envelope.Profile,
		Sequence:      stored.Envelope.Sequence,
		ObservedAt:    observedAt.UTC().Format(time.RFC3339Nano),
		ReceivedAt:    receivedAt.UTC().Format(time.RFC3339Nano),
		Gaps:          gaps,
		Health:        stored.Envelope.Health,
	}, nil
}

func estimatedHeaderBytes(header http.Header) int {
	total := 0
	for name, values := range header {
		total += len(name) + 4
		for _, value := range values {
			total += len(value) + 2
		}
	}
	return total
}

func (handler *SnapshotHandler) writeProblem(response http.ResponseWriter, status int, code string, retry bool) {
	requestIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(handler.random, requestIDBytes); err != nil {
		panic(http.ErrAbortHandler)
	}
	problem := readerProblem{
		SchemaVersion: 1,
		ErrorCode:     code,
		RequestID:     base64.RawURLEncoding.EncodeToString(requestIDBytes),
	}
	encoded, err := json.Marshal(problem)
	if err != nil || len(encoded) > maxErrorBytes {
		panic(http.ErrAbortHandler)
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Connection", "close")
	if retry {
		response.Header().Set("Retry-After", "1")
	}
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}
