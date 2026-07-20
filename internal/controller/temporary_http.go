package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

type temporarySourceAttempts struct {
	starts []time.Time
}

// TemporaryHandler exists only while a locally opened enrollment or recovery
// window exists. It deliberately shares no business or session routes.
type TemporaryHandler struct {
	pairing    *PairingManager
	mode       string
	host       string
	now        func() time.Time
	random     io.Reader
	onComplete func()
	request    chan struct{}

	rateMu   sync.Mutex
	attempts map[string]*temporarySourceAttempts
}

func NewTemporaryHandler(pairing *PairingManager, mode, host string, onComplete func()) (*TemporaryHandler, error) {
	if pairing == nil || mode != "enrollment" && mode != "recovery" || host == "" || strings.ContainsAny(host, "/?#@") {
		return nil, errors.New("temporary Controller handler configuration is invalid")
	}
	if onComplete == nil {
		onComplete = func() {}
	}
	return &TemporaryHandler{
		pairing: pairing, mode: mode, host: host, now: time.Now, random: rand.Reader,
		onComplete: onComplete, request: make(chan struct{}, 1), attempts: make(map[string]*temporarySourceAttempts),
	}, nil
}

func (handler *TemporaryHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Host != handler.host {
		handler.writeProblem(response, http.StatusForbidden, "scope_forbidden", 0)
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" ||
		len(request.TransferEncoding) != 0 || request.Header.Get("Transfer-Encoding") != "" {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	if controllerHeaderBytes(request.Header) > maxControllerHeaderBytes {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return
	}
	if request.Header.Get("Accept") != "application/json" {
		handler.writeProblem(response, http.StatusNotAcceptable, "not_acceptable", 0)
		return
	}
	challengePath := "/v0/" + handler.mode + "/challenge"
	completionPath := "/v0/" + handler.mode
	expectedMethod := ""
	switch request.URL.Path {
	case challengePath:
		expectedMethod = http.MethodPost
	case completionPath:
		expectedMethod = http.MethodPut
	default:
		handler.writeProblem(response, http.StatusNotFound, "route_not_found", 0)
		return
	}
	if request.Method != expectedMethod {
		response.Header().Set("Allow", expectedMethod)
		handler.writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", 0)
		return
	}
	select {
	case handler.request <- struct{}{}:
		defer func() { <-handler.request }()
	default:
		handler.writeProblem(response, http.StatusTooManyRequests, "rate_limited", time.Second)
		return
	}
	if request.URL.Path == challengePath {
		handler.serveChallenge(response, request)
		return
	}
	handler.serveCompletion(response, request)
}

func (handler *TemporaryHandler) serveChallenge(response http.ResponseWriter, request *http.Request) {
	var body IdentityChallengeRequest
	if !handler.readJSON(response, request, &body) {
		return
	}
	if !handler.pairing.WindowCredentialsValid(handler.mode, body.WindowID, body.WindowCode) {
		if retry, allowed := handler.allowInvalidSource(sourceIP(request.RemoteAddr), handler.now()); !allowed {
			handler.writeProblem(response, http.StatusTooManyRequests, "rate_limited", retry)
			return
		}
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		return
	}
	result, err := handler.pairing.Begin(handler.mode, body)
	if err != nil {
		status, code := http.StatusBadRequest, "invalid_request"
		if strings.Contains(err.Error(), "conflict") {
			status, code = http.StatusConflict, "state_conflict"
		}
		handler.writeProblem(response, status, code, 0)
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *TemporaryHandler) serveCompletion(response http.ResponseWriter, request *http.Request) {
	var body IdentityCompletionRequest
	if !handler.readJSON(response, request, &body) {
		return
	}
	result, err := handler.pairing.Complete(handler.mode, body)
	if err != nil {
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		if !handler.pairing.WindowOpen(handler.mode) {
			handler.onComplete()
		}
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 8*1024 {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	handler.writeEncodedJSON(response, http.StatusOK, encoded)
	handler.onComplete()
}

func (handler *TemporaryHandler) readJSON(response http.ResponseWriter, request *http.Request, destination any) bool {
	if request.Header.Get("Content-Type") != "application/json" {
		handler.writeProblem(response, http.StatusUnsupportedMediaType, "unsupported_media_type", 0)
		return false
	}
	if request.ContentLength <= 0 || request.ContentLength > maxControllerRequestBytes || len(request.TransferEncoding) != 0 {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxControllerRequestBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength || int64(len(body)) > maxControllerRequestBytes {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return false
	}
	if strictjson.Decode(body, destination) != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return false
	}
	return true
}

func (handler *TemporaryHandler) allowInvalidSource(source string, now time.Time) (time.Duration, bool) {
	handler.rateMu.Lock()
	defer handler.rateMu.Unlock()
	state := handler.attempts[source]
	if state == nil {
		state = &temporarySourceAttempts{}
		handler.attempts[source] = state
	}
	cutoff := now.Add(-time.Minute)
	state.starts = retainAfter(state.starts, cutoff)
	if len(state.starts) >= 5 {
		return boundedRetry(state.starts[0].Add(time.Minute).Sub(now)), false
	}
	if len(state.starts) > 0 && now.Sub(state.starts[len(state.starts)-1]) < time.Second {
		return boundedRetry(time.Second - now.Sub(state.starts[len(state.starts)-1])), false
	}
	state.starts = append(state.starts, now)
	return 0, true
}

func (handler *TemporaryHandler) writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 8*1024 {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	handler.writeEncodedJSON(response, status, encoded)
}

func (handler *TemporaryHandler) writeEncodedJSON(response http.ResponseWriter, status int, encoded []byte) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func (handler *TemporaryHandler) writeProblem(response http.ResponseWriter, status int, code string, retry time.Duration) {
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(handler.random, requestID); err != nil {
		panic(http.ErrAbortHandler)
	}
	encoded, err := json.Marshal(controllerProblem{
		SchemaVersion: 1, ErrorCode: code, RequestID: base64.RawURLEncoding.EncodeToString(requestID),
	})
	if err != nil || len(encoded) > maxControllerErrorBytes {
		panic(http.ErrAbortHandler)
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Connection", "close")
	if retry > 0 {
		response.Header().Set("Retry-After", strconv.Itoa(int(boundedRetry(retry).Seconds())))
	}
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func sourceIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil || net.ParseIP(host) == nil {
		return "invalid"
	}
	return host
}
