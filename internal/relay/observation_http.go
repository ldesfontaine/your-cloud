package relay

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

const maxAckBytes = 256

// ClientAuthorizer rechecks the current enrollment for every HTTP request.
type ClientAuthorizer func(*x509.Certificate) (string, error)

// ObservationHandler exposes only the Daemon-to-Relay write route.
type ObservationHandler struct {
	store     *ObservationStore
	authorize ClientAuthorizer
	now       func() time.Time
	routes    *http.ServeMux
	stateLock *sync.RWMutex
}

type observationAck struct {
	Schema         int    `json:"schema"`
	MachineID      string `json:"machine_id"`
	Sequence       uint64 `json:"sequence"`
	AlreadyPresent bool   `json:"already_present"`
}

// NewObservationHandler assembles the exact authenticated observation boundary.
func NewObservationHandler(store *ObservationStore, authorize ClientAuthorizer) (*ObservationHandler, error) {
	return NewObservationHandlerWithStateLock(store, authorize, &sync.RWMutex{})
}

// NewObservationHandlerWithStateLock coordinates ingestion with snapshots and reloads.
func NewObservationHandlerWithStateLock(store *ObservationStore, authorize ClientAuthorizer, stateLock *sync.RWMutex) (*ObservationHandler, error) {
	if store == nil || authorize == nil || stateLock == nil {
		return nil, errors.New("observation store, client authorizer and state lock are required")
	}
	handler := &ObservationHandler{store: store, authorize: authorize, now: time.Now, stateLock: stateLock}
	handler.routes = http.NewServeMux()
	handler.routes.HandleFunc("POST /v0/observations", handler.receive)
	return handler, nil
}

// ServeHTTP delegates to the method-aware route without adding a read API.
func (handler *ObservationHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.routes.ServeHTTP(response, request)
}

func (handler *ObservationHandler) receive(response http.ResponseWriter, request *http.Request) {
	handler.stateLock.Lock()
	defer handler.stateLock.Unlock()
	if hasURIQuery(request) {
		writeProblem(response, http.StatusBadRequest, "URI query is not supported")
		return
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		writeProblem(response, http.StatusForbidden, "authenticated client certificate is required")
		return
	}
	machineID, err := handler.authorize(request.TLS.PeerCertificates[0])
	if err != nil {
		writeProblem(response, http.StatusForbidden, "client certificate is not enrolled")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if request.ContentLength > observation.MaxMessageBytes {
		writeProblem(response, http.StatusRequestEntityTooLarge, "observation body is too large")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, observation.MaxMessageBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeProblem(response, http.StatusRequestEntityTooLarge, "observation body is too large")
		return
	}
	envelope, alreadyPresent, err := handler.store.Save(machineID, body, handler.now())
	if err != nil {
		writeProblem(response, http.StatusUnprocessableEntity, "observation was refused")
		return
	}
	handler.writeAck(response, observationAck{
		Schema: 1, MachineID: machineID, Sequence: envelope.Sequence, AlreadyPresent: alreadyPresent,
	})
}

func (handler *ObservationHandler) writeAck(response http.ResponseWriter, ack observationAck) {
	encoded, err := json.Marshal(ack)
	if err != nil || len(encoded) > maxAckBytes {
		writeProblem(response, http.StatusInternalServerError, "acknowledgement is unavailable")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func hasURIQuery(request *http.Request) bool {
	return request.URL.RawQuery != "" || request.URL.ForceQuery
}

func writeProblem(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": message})
}
