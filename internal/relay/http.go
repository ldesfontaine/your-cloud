package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
)

// Handler owns the network boundary of the Relay. It accepts only the fixed
// v0.0.1 schema and sends accepted data to the in-memory Store.
type Handler struct {
	store           *Store
	allowedMachines map[string]struct{}
	logger          *log.Logger
	now             func() time.Time
	routes          *http.ServeMux
}

const maxQueryBodyBytes int64 = 32

// NewHandler builds a Relay handler for the exact synthetic LAB machines.
func NewHandler(store *Store, allowedMachines []string, logger *log.Logger) *Handler {
	allowed := make(map[string]struct{}, len(allowedMachines))
	for _, machineID := range allowedMachines {
		allowed[machineID] = struct{}{}
	}
	handler := &Handler{
		store:           store,
		allowedMachines: allowed,
		logger:          logger,
		now:             time.Now,
	}
	handler.routes = http.NewServeMux()
	handler.routes.HandleFunc("POST /v0/presence", handler.receivePresence)
	handler.routes.HandleFunc("QUERY /v0/machines", handler.queryMachines)
	return handler
}

// ServeHTTP delegates to Go's method-aware router. The route patterns make the
// write boundary (POST) and the safe, idempotent query (QUERY) explicit.
func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.routes.ServeHTTP(response, request)
}

func (handler *Handler) receivePresence(response http.ResponseWriter, request *http.Request) {
	if hasURIQuery(request) {
		writeProblem(response, http.StatusBadRequest, "URI query is not supported in v0.0.1")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}
	if request.ContentLength > presence.MaxBodyBytes {
		writeProblem(response, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", presence.MaxBodyBytes))
		return
	}

	request.Body = http.MaxBytesReader(response, request.Body, presence.MaxBodyBytes)
	signal, err := presence.DecodeSignal(request.Body)
	if err != nil {
		writeDecodeProblem(response, err, presence.MaxBodyBytes, "presence")
		return
	}
	if err := signal.Validate(handler.allowedMachines); err != nil {
		writeProblem(response, http.StatusBadRequest, err.Error())
		return
	}

	receivedAt := handler.now()
	handler.store.Record(signal, receivedAt)
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) queryMachines(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Accept-Query", `"application/json"`)
	response.Header().Set("Cache-Control", "no-store")
	if hasURIQuery(request) {
		writeProblem(response, http.StatusBadRequest, "URI query is not supported in v0.0.1")
		return
	}
	contentType := request.Header.Get("Content-Type")
	if contentType == "" {
		writeProblem(response, http.StatusBadRequest, "Content-Type is required for QUERY")
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		writeProblem(response, http.StatusUnsupportedMediaType, "QUERY supports application/json")
		return
	}
	if request.ContentLength > maxQueryBodyBytes {
		writeProblem(response, http.StatusRequestEntityTooLarge, fmt.Sprintf("query body exceeds %d bytes", maxQueryBodyBytes))
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxQueryBodyBytes)
	decoder := json.NewDecoder(request.Body)
	var query map[string]json.RawMessage
	if err := decoder.Decode(&query); err != nil {
		writeDecodeProblem(response, err, maxQueryBodyBytes, "query")
		return
	}
	if query == nil || len(query) != 0 {
		writeProblem(response, http.StatusBadRequest, "v0.0.1 QUERY body must be an empty JSON object")
		return
	}
	if err := requireJSONEnd(decoder); err != nil {
		writeDecodeProblem(response, err, maxQueryBodyBytes, "query")
		return
	}

	now := handler.now()
	payload := struct {
		GeneratedAt string         `json:"generated_at"`
		StaleAfter  string         `json:"stale_after"`
		Machines    []MachineState `json:"machines"`
	}{
		GeneratedAt: now.UTC().Format(time.RFC3339Nano),
		StaleAfter:  presence.StaleAfter.String(),
		Machines:    handler.store.Snapshot(now),
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(payload); err != nil {
		handler.logger.Printf("render machines: %v", err)
	}
}

// hasURIQuery rejects both a non-empty query and a trailing question mark.
// v0.0.1 carries the complete QUERY contract in the bounded JSON body.
func hasURIQuery(request *http.Request) bool {
	return request.URL.RawQuery != "" || request.URL.ForceQuery
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("body must contain one JSON object")
	}
	return err
}

func writeDecodeProblem(response http.ResponseWriter, err error, maxBytes int64, schemaName string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeProblem(response, http.StatusRequestEntityTooLarge, fmt.Sprintf("%s body exceeds %d bytes", schemaName, maxBytes))
		return
	}
	writeProblem(response, http.StatusBadRequest, fmt.Sprintf("body does not match the %s schema", schemaName))
}

func writeProblem(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": message})
}
