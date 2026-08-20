package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	maxControllerRequestBytes  = int64(4 * 1024)
	maxControllerResponseBytes = 128 * 1024
	maxControllerErrorBytes    = 1024
	maxControllerHeaderBytes   = 8 * 1024
	maxDeviceRequests          = 4
)

type controllerProblem struct {
	SchemaVersion int    `json:"schema_version"`
	ErrorCode     string `json:"error_code"`
	RequestID     string `json:"request_id"`
}

type infrastructureMutationRequest struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	Label            string `json:"label"`
}

type machineMutationRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Label         string `json:"label"`
}

type identityActivationRequest struct {
	SchemaVersion int `json:"schema_version"`
}

type deviceRotationRequest struct {
	SchemaVersion  int    `json:"schema_version"`
	RotationID     string `json:"rotation_id"`
	DeviceCSR      string `json:"device_csr"`
	ChallengeID    string `json:"challenge_id"`
	HumanSignature string `json:"human_signature"`
}

type deviceRotationCore struct {
	SchemaVersion int    `json:"schema_version"`
	RotationID    string `json:"rotation_id"`
	DeviceCSR     string `json:"device_csr"`
}

type recoveryKeyRequest struct {
	SchemaVersion            int    `json:"schema_version"`
	OperationID              string `json:"operation_id"`
	NextRecoveryEpoch        uint64 `json:"next_recovery_epoch"`
	NextRecoverySalt         string `json:"next_recovery_salt"`
	NextRecoveryPublicKey    string `json:"next_recovery_public_key"`
	ChallengeID              string `json:"challenge_id"`
	HumanSignature           string `json:"human_signature"`
	CurrentRecoverySignature string `json:"current_recovery_signature"`
	NextRecoverySignature    string `json:"next_recovery_signature"`
}

// RelaySnapshotSource is what the handler reads the Relay through — the live
// bounded reader when the anchor exists, the dormant one when the Relay of a
// freshly created infrastructure does not exist yet. Exported so the serve
// path can hold either without naming a concrete type.
type RelaySnapshotSource interface {
	Read(context.Context, time.Time) (*RelaySnapshot, RelayStatus, error)
}

// ControllerHandler exposes the closed private API. TLS authenticates the
// device transport; this handler rechecks the live device authority on every
// request and independently authenticates the human session where required.
type ControllerHandler struct {
	authority   *AuthorityStore
	pairing     *PairingManager
	sessions    *SessionManager
	inventory   *InventoryStore
	external    *ExternalStore
	definitions *ServiceDefinitionStore
	dispatches  *DispatchRegistryStore
	// dispatcher is nil until AttachAuxiliaryDispatcher names one. Nil is not
	// a degraded mode: it closes the two routes of the command trajectory.
	dispatcher auxiliaryDispatcher
	relay      RelaySnapshotSource
	host       string
	now        func() time.Time
	random     io.Reader
	sleep      func(context.Context, time.Duration) error

	requestMu sync.Mutex
	active    map[string]uint8
	stateMu   sync.RWMutex
}

func NewControllerHandler(
	authority *AuthorityStore,
	pairing *PairingManager,
	sessions *SessionManager,
	inventory *InventoryStore,
	external *ExternalStore,
	definitions *ServiceDefinitionStore,
	dispatches *DispatchRegistryStore,
	relay RelaySnapshotSource,
	host string,
) (*ControllerHandler, error) {
	if authority == nil || pairing == nil || sessions == nil || inventory == nil || external == nil ||
		definitions == nil || dispatches == nil || relay == nil || host == "" || strings.ContainsAny(host, "/?#@") {
		return nil, errors.New("Controller HTTP dependencies and exact Host are required")
	}
	state := authority.Snapshot()
	inventoryState := inventory.Snapshot()
	externalState := external.Snapshot()
	definitionState := definitions.Snapshot()
	dispatchState := dispatches.Snapshot()
	if inventoryState.ControllerID != state.ControllerID || inventoryState.InfrastructureID != state.InfrastructureID ||
		externalState.ControllerID != state.ControllerID || externalState.InfrastructureID != state.InfrastructureID ||
		definitionState.ControllerID != state.ControllerID || definitionState.InfrastructureID != state.InfrastructureID ||
		dispatchState.ControllerID != state.ControllerID || dispatchState.InfrastructureID != state.InfrastructureID {
		return nil, errors.New("Controller HTTP authorities do not describe the same installation")
	}
	return &ControllerHandler{
		authority: authority, pairing: pairing, sessions: sessions, inventory: inventory,
		external: external, definitions: definitions, dispatches: dispatches,
		relay: relay, host: host,
		now: time.Now, random: rand.Reader, active: make(map[string]uint8),
		sleep: func(ctx context.Context, delay time.Duration) error {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}, nil
}

func (handler *ControllerHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !handler.validEnvelope(response, request) {
		return
	}
	certificate := peerCertificate(request)
	if mode, transactionID, activation := activationRoute(request.URL.Path); activation {
		handler.stateMu.Lock()
		defer handler.stateMu.Unlock()
		handler.serveActivation(response, request, certificate, mode, transactionID)
		return
	}
	_, rotation := deviceRotationRoute(request.URL.Path)
	if rotation || request.URL.Path == "/v0/recovery-key" {
		handler.stateMu.Lock()
		defer handler.stateMu.Unlock()
	} else {
		handler.stateMu.RLock()
		defer handler.stateMu.RUnlock()
	}
	device, err := handler.authority.AuthorizeActive(certificate, handler.now())
	if err != nil {
		handler.writeProblem(response, http.StatusForbidden, "scope_forbidden", 0)
		return
	}
	if !handler.enterDevice(device.DeviceID) {
		handler.writeProblem(response, http.StatusTooManyRequests, "rate_limited", time.Second)
		return
	}
	defer handler.leaveDevice(device.DeviceID)

	// The two routes of the command trajectory exist only beside the engine
	// that can actually launch (`AttachAuxiliaryDispatcher`). A Controller
	// without one does not serve a door that would spend a human approval and
	// reach nothing; it serves no such path at all.
	if handler.dispatcher == nil && commandTrajectoryRoute(request.URL.Path) {
		handler.writeProblem(response, http.StatusNotFound, "route_not_found", 0)
		return
	}

	switch request.URL.Path {
	case "/v0/session/challenge":
		handler.serveSessionChallenge(response, request, certificate)
	case "/v0/session":
		handler.serveSession(response, request, certificate)
	case "/v0/infrastructure":
		handler.serveInfrastructure(response, request, certificate)
	case "/v0/machines":
		handler.serveMachines(response, request, certificate)
	case "/v0/external-elements":
		handler.serveExternalElements(response, request, certificate)
	case "/v0/external-element-withdrawals":
		handler.serveExternalElementWithdrawals(response, request, certificate)
	case "/v0/service-definitions":
		handler.serveServiceDefinitions(response, request, certificate)
	case "/v0/recovery-key":
		handler.serveRecoveryKey(response, request, certificate)
	case "/v0/probe-plans":
		handler.serveProbePlans(response, request, certificate)
	case "/v0/service-plans":
		handler.serveWebServicePlans(response, request, certificate)
	case "/v0/entrypoint-plans":
		handler.serveEntrypointPlans(response, request, certificate)
	case "/v0/route-plans":
		handler.serveRoutePlans(response, request, certificate)
	case "/v0/link-plans":
		handler.serveLinkPlans(response, request, certificate)
	case "/v0/listener-peer-plans":
		handler.serveListenerPeerPlans(response, request, certificate)
	case "/v0/initiator-peer-plans":
		handler.serveInitiatorPeerPlans(response, request, certificate)
	case "/v0/private-service-plans":
		handler.servePrivateServicePlans(response, request, certificate)
	case "/v0/link-route-plans":
		handler.serveLinkRoutePlans(response, request, certificate)
	case "/v0/snapshot-plans":
		handler.serveSnapshotPlans(response, request, certificate)
	case "/v0/restore-plans":
		handler.serveRestorePlans(response, request, certificate)
	case "/v0/user-service-plans":
		handler.serveUserServicePlans(response, request, certificate)
	case "/v0/plan-approvals":
		handler.servePlanApprovals(response, request, certificate)
	case "/v0/plan-dispatches":
		handler.servePlanDispatches(response, request, certificate)
	default:
		if rotationID, ok := deviceRotationRoute(request.URL.Path); ok {
			handler.serveDeviceRotation(response, request, certificate, rotationID)
			return
		}
		if machineID, ok := machineRoute(request.URL.Path); ok {
			handler.serveMachine(response, request, certificate, machineID)
			return
		}
		handler.writeProblem(response, http.StatusNotFound, "route_not_found", 0)
	}
}

func (handler *ControllerHandler) validEnvelope(response http.ResponseWriter, request *http.Request) bool {
	if request.Host != handler.host {
		handler.writeProblem(response, http.StatusForbidden, "scope_forbidden", 0)
		return false
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" ||
		request.Header.Get("Transfer-Encoding") != "" || len(request.TransferEncoding) != 0 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return false
	}
	if controllerHeaderBytes(request.Header) > maxControllerHeaderBytes {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return false
	}
	if request.Header.Get("Accept") != "application/json" {
		handler.writeProblem(response, http.StatusNotAcceptable, "not_acceptable", 0)
		return false
	}
	expected, known := handler.routeMethods(request.URL.Path)
	if known && !containsMethod(expected, request.Method) {
		response.Header().Set("Allow", strings.Join(expected, ", "))
		handler.writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", 0)
		return false
	}
	return true
}

func (handler *ControllerHandler) serveSessionChallenge(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	var body SessionChallengeRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	var current *SessionContext
	if body.Purpose != "open_session" {
		context, err := handler.sessions.Authenticate(certificate, request.Header.Get("Authorization"))
		if err != nil {
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
			return
		}
		current = &context
	}
	result, err := handler.sessions.Challenge(certificate, body, current)
	if err != nil {
		status, code := http.StatusBadRequest, "invalid_request"
		if strings.Contains(err.Error(), "rate") {
			status, code = http.StatusTooManyRequests, "rate_limited"
		} else if strings.Contains(err.Error(), "already active") {
			status, code = http.StatusConflict, "state_conflict"
		} else if strings.Contains(err.Error(), "active session") {
			status, code = http.StatusUnauthorized, "authentication_failed"
		}
		handler.writeProblem(response, status, code, retryFor(status))
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *ControllerHandler) serveSession(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	if request.Method == http.MethodDelete {
		if !handler.requireEmptyBody(response, request) {
			return
		}
		if err := handler.sessions.Logout(certificate, request.Header.Get("Authorization")); err != nil {
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
			return
		}
		handler.writeJSON(response, http.StatusOK, struct {
			SchemaVersion int    `json:"schema_version"`
			Status        string `json:"status"`
		}{SchemaVersion: 1, Status: "logged_out"})
		return
	}
	var body SessionOpenRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	result, err := handler.sessions.Open(certificate, body)
	if err != nil {
		var delayed AuthenticationDelayError
		if errors.As(err, &delayed) {
			if delayed.Delay > 16*time.Second {
				handler.writeProblem(response, http.StatusTooManyRequests, "rate_limited", boundedRetry(delayed.Delay))
				return
			}
			if handler.sleep(request.Context(), delayed.Delay) != nil {
				return
			}
		}
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *ControllerHandler) serveInfrastructure(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		if !handler.requireEmptyBody(response, request) {
			return
		}
		handler.writeAccepted(response, context, http.StatusOK, handler.inventory.Infrastructure())
		return
	}
	var body infrastructureMutationRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != 1 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	var view InfrastructureView
	var changed bool
	var mutationError error
	err := handler.sessions.Accept(context, func() error {
		view, changed, mutationError = handler.inventory.PutInfrastructure(body.InfrastructureID, body.Label)
		return mutationError
	})
	if err != nil {
		if mutationError == nil {
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
			return
		}
		status, code := http.StatusConflict, "state_conflict"
		if _, labelErr := CanonicalLabel(body.Label); labelErr != nil {
			status, code = http.StatusUnprocessableEntity, "label_invalid"
		}
		handler.writeProblem(response, status, code, 0)
		return
	}
	status := http.StatusOK
	if changed {
		status = http.StatusCreated
	}
	handler.writeJSON(response, status, view)
}

func (handler *ControllerHandler) serveMachines(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	if !handler.requireEmptyBody(response, request) {
		return
	}
	now := handler.now()
	snapshot, status, _ := handler.relay.Read(request.Context(), time.Time{})
	age := cacheAge(now, snapshot)
	view, err := ProjectMachines(handler.inventory.Snapshot(), snapshot, status, age)
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "projection_unavailable", 0)
		return
	}
	// The command position is a second authority and is filled after the
	// projection rather than inside it: the projection answers for the
	// inventory and the observation chain, the registry answers for what a
	// machine reported having consumed, and merging the two readers would make
	// one of them look like a source of the other. No new route: the Console
	// learns the successor it must sign where it already reads its machines.
	for index := range view.Machines {
		sequence, certain := handler.dispatches.CommandPosition(view.Machines[index].MachineID)
		view.Machines[index].CommandPosition = ProjectedCommandPosition{
			LastReportedSequence: sequence, Certain: certain,
		}
	}
	encoded, err := EncodeMachinesView(view)
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "projection_unavailable", 0)
		return
	}
	if handler.sessions.Touch(context) != nil {
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		return
	}
	handler.writeEncodedJSON(response, http.StatusOK, encoded)
}

func (handler *ControllerHandler) serveMachine(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate, machineID string) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body machineMutationRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != 1 || machineid.Validate(machineID) != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	if _, err := CanonicalLabel(body.Label); err != nil {
		handler.writeProblem(response, http.StatusUnprocessableEntity, "label_invalid", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	exists := false
	for _, machine := range inventory.Machines {
		if machine.MachineID == machineID {
			exists = true
			break
		}
	}
	allowNew := false
	if !exists {
		authenticatedAt := handler.now()
		snapshot, status, err := handler.relay.Read(request.Context(), authenticatedAt)
		if err != nil || status != RelayAvailable || snapshot == nil {
			handler.writeProblem(response, http.StatusServiceUnavailable, "relay_unavailable", 0)
			return
		}
		for _, machine := range snapshot.Machines {
			if machine.MachineID == machineID && machine.EnrollmentStatus == "active" {
				allowNew = true
				break
			}
		}
		if !allowNew {
			handler.writeProblem(response, http.StatusUnprocessableEntity, "machine_not_active", 0)
			return
		}
	}
	var view MachineMutationView
	var changed bool
	var mutationError error
	err := handler.sessions.Accept(context, func() error {
		view, changed, mutationError = handler.inventory.PutMachine(machineID, body.Label, allowNew)
		return mutationError
	})
	if err != nil {
		if mutationError == nil {
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
			return
		}
		// `state_conflict` seul, et c'est un fait de lecture plutôt qu'un choix :
		// une machine absente de l'inventaire n'arrive jamais ici sans que le
		// Relay l'ait rapportée `active`, puisque le cas contraire a déjà répondu
		// `422 machine_not_active` plus haut et retourné. Le couple
		// `(409, machine_not_active)` est donc impossible sur cette voie, et
		// `known_problem` côté Console ne le connaît pas — correctement.
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	}
	status := http.StatusOK
	if !exists && changed {
		status = http.StatusCreated
	}
	handler.writeJSON(response, status, view)
}

func (handler *ControllerHandler) serveActivation(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate, mode, transactionID string) {
	if request.Method != http.MethodPut {
		response.Header().Set("Allow", http.MethodPut)
		handler.writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", 0)
		return
	}
	var body identityActivationRequest
	encoded, ok := handler.readJSON(response, request, &body)
	if !ok {
		return
	}
	if body.SchemaVersion != 1 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	digest := sha256.Sum256(encoded)
	result, err := handler.pairing.ActivateForMode(mode, transactionID, certificate, digest)
	if err != nil {
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	}
	if mode == "recovery" || mode == "rotation" {
		handler.sessions.InvalidateAll()
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *ControllerHandler) serveDeviceRotation(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate, rotationID string) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body deviceRotationRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	core := deviceRotationCore{SchemaVersion: body.SchemaVersion, RotationID: body.RotationID, DeviceCSR: body.DeviceCSR}
	if core.SchemaVersion != 1 || core.RotationID != rotationID || !canonicalRawURLBytes(rotationID, 16) {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	digest := sha256.Sum256(mustJSON(core))
	if replay, found, err := handler.pairing.DeviceRotationCandidate(rotationID, digest); err != nil {
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	} else if found {
		handler.writeAccepted(response, context, http.StatusOK, replay)
		return
	}
	if !handler.verifySensitive(response, request, certificate, context, "rotate_device", digest, body.ChallengeID, body.HumanSignature) {
		return
	}
	result, err := handler.pairing.PrepareDeviceRotation(rotationID, body.DeviceCSR, digest)
	if err != nil {
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	}
	handler.writeAccepted(response, context, http.StatusCreated, result)
}

func (handler *ControllerHandler) serveRecoveryKey(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body recoveryKeyRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	mutation := RecoveryKeyMutation{
		SchemaVersion: body.SchemaVersion, OperationID: body.OperationID,
		NextRecoveryEpoch: body.NextRecoveryEpoch, NextRecoverySalt: body.NextRecoverySalt,
		NextRecoveryPublicKey: body.NextRecoveryPublicKey,
	}
	digest := sha256.Sum256(mustJSON(mutation))
	if replay, found, err := handler.authority.RecoveryKeyReceipt(body.OperationID, digest, handler.now()); err != nil {
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	} else if found {
		handler.writeAccepted(response, context, http.StatusOK, replay)
		return
	}
	if !handler.verifySensitive(response, request, certificate, context, "rotate_recovery_key", digest, body.ChallengeID, body.HumanSignature) {
		return
	}
	result, err := handler.authority.RotateRecoveryKey(mutation, digest, body.CurrentRecoverySignature, body.NextRecoverySignature, handler.now())
	if err != nil {
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	}
	handler.writeAccepted(response, context, http.StatusOK, result)
}

func (handler *ControllerHandler) verifySensitive(
	response http.ResponseWriter,
	request *http.Request,
	certificate *x509.Certificate,
	context SessionContext,
	purpose string,
	digest [32]byte,
	challengeID string,
	signature string,
) bool {
	err := handler.sessions.VerifySensitive(certificate, context, purpose, digest, challengeID, signature)
	if err == nil {
		return true
	}
	var delayed AuthenticationDelayError
	if errors.As(err, &delayed) {
		if delayed.Delay > 16*time.Second {
			handler.writeProblem(response, http.StatusTooManyRequests, "rate_limited", boundedRetry(delayed.Delay))
			return false
		}
		if handler.sleep(request.Context(), delayed.Delay) != nil {
			return false
		}
	}
	handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
	return false
}

func (handler *ControllerHandler) authenticateSession(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) (SessionContext, bool) {
	context, err := handler.sessions.Authenticate(certificate, request.Header.Get("Authorization"))
	if err != nil {
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		return SessionContext{}, false
	}
	return context, true
}

func (handler *ControllerHandler) writeAccepted(response http.ResponseWriter, context SessionContext, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxControllerResponseBytes {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	if handler.sessions.Touch(context) != nil {
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		return
	}
	handler.writeEncodedJSON(response, status, encoded)
}

func (handler *ControllerHandler) decodeJSON(response http.ResponseWriter, request *http.Request, destination any) bool {
	_, ok := handler.readJSON(response, request, destination)
	return ok
}

// decodeJSONWithin is the same read under a bound one named route announces for
// itself. It exists because one document of the product — the service definition
// — is bounded above the common request bound by its own contract, and a route
// that could not receive a document the contract admits would be a bound decided
// by an oversight. Every other route keeps the common bound by construction: the
// wider one has to be passed in, one call at a time.
func (handler *ControllerHandler) decodeJSONWithin(response http.ResponseWriter, request *http.Request, destination any, maximum int64) bool {
	_, ok := handler.readJSONWithin(response, request, destination, maximum)
	return ok
}

func (handler *ControllerHandler) readJSON(response http.ResponseWriter, request *http.Request, destination any) ([]byte, bool) {
	return handler.readJSONWithin(response, request, destination, maxControllerRequestBytes)
}

func (handler *ControllerHandler) readJSONWithin(response http.ResponseWriter, request *http.Request, destination any, maximum int64) ([]byte, bool) {
	if request.Header.Get("Content-Type") != "application/json" {
		handler.writeProblem(response, http.StatusUnsupportedMediaType, "unsupported_media_type", 0)
		return nil, false
	}
	if request.ContentLength <= 0 || request.ContentLength > maximum || len(request.TransferEncoding) != 0 {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil || int64(len(body)) != request.ContentLength || int64(len(body)) > maximum {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return nil, false
	}
	if strictjson.Decode(body, destination) != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return nil, false
	}
	return body, true
}

func (handler *ControllerHandler) requireEmptyBody(response http.ResponseWriter, request *http.Request) bool {
	if request.Header.Get("Content-Type") != "" {
		handler.writeProblem(response, http.StatusUnsupportedMediaType, "unsupported_media_type", 0)
		return false
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1))
	if err != nil || len(body) != 0 {
		handler.writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", 0)
		return false
	}
	return true
}

func (handler *ControllerHandler) writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxControllerResponseBytes {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	handler.writeEncodedJSON(response, status, encoded)
}

func (handler *ControllerHandler) writeEncodedJSON(response http.ResponseWriter, status int, encoded []byte) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func (handler *ControllerHandler) writeProblem(response http.ResponseWriter, status int, code string, retry time.Duration) {
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

func (handler *ControllerHandler) enterDevice(deviceID string) bool {
	handler.requestMu.Lock()
	defer handler.requestMu.Unlock()
	if handler.active[deviceID] >= maxDeviceRequests {
		return false
	}
	handler.active[deviceID]++
	return true
}

func (handler *ControllerHandler) leaveDevice(deviceID string) {
	handler.requestMu.Lock()
	defer handler.requestMu.Unlock()
	if handler.active[deviceID] <= 1 {
		delete(handler.active, deviceID)
		return
	}
	handler.active[deviceID]--
}

// routeMethods answers for the surface this Controller actually serves. The
// two routes of the command trajectory are unknown here until an engine is
// attached, so the `Allow` header and the routing read the same one field and
// cannot drift into announcing a door that does not open.
func (handler *ControllerHandler) routeMethods(path string) ([]string, bool) {
	if handler.dispatcher == nil && commandTrajectoryRoute(path) {
		return nil, false
	}
	return controllerRouteMethods(path)
}

func controllerRouteMethods(path string) ([]string, bool) {
	switch path {
	case "/v0/session/challenge":
		return []string{http.MethodPost}, true
	case "/v0/session":
		return []string{http.MethodPost, http.MethodDelete}, true
	case "/v0/infrastructure":
		return []string{http.MethodGet, http.MethodPut}, true
	case "/v0/machines":
		return []string{http.MethodGet}, true
	// The declared inventory reads and grows here and retreats on its own route.
	// There is no DELETE: the business surface of the contract exposes none, and
	// an element the product does not own is the last thing a DELETE should be
	// invented for.
	case "/v0/external-elements":
		return []string{http.MethodGet, http.MethodPost}, true
	case "/v0/external-element-withdrawals":
		return []string{http.MethodPost}, true
	// The frozen definitions read and grow, and nothing else. There is no DELETE
	// and no PUT: a revision is a new freeze that coexists with the previous ones,
	// so a method that replaced or removed one would be a method for an act this
	// palier does not have.
	case "/v0/service-definitions":
		return []string{http.MethodGet, http.MethodPost}, true
	case "/v0/recovery-key":
		return []string{http.MethodPut}, true
	case "/v0/probe-plans", "/v0/service-plans", "/v0/entrypoint-plans", "/v0/route-plans",
		"/v0/link-plans", "/v0/listener-peer-plans", "/v0/initiator-peer-plans",
		"/v0/private-service-plans", "/v0/link-route-plans", "/v0/snapshot-plans", "/v0/restore-plans",
		"/v0/user-service-plans":
		return []string{http.MethodPost}, true
	// The one route of the product whose effect leaves the Controller's
	// machine, and it is deliberately alone: a second launching route would be
	// a second policy to hold, and the first thing a reader must be able to
	// count is the number of doors. It stands apart from the construction
	// block above because it is not a construction: those routes freeze bytes
	// and keep nothing, this one spends an authority durably.
	case "/v0/plan-approvals":
		return []string{http.MethodPost}, true
	// The history reads and mutates nothing. There is no DELETE, no retry and
	// no resume: recovery after an unknown result is an observation then a new
	// signed plan, and a route pretending better would be a route that lies.
	case "/v0/plan-dispatches":
		return []string{http.MethodGet}, true
	}
	if _, ok := machineRoute(path); ok {
		return []string{http.MethodPut}, true
	}
	if _, _, ok := activationRoute(path); ok {
		return []string{http.MethodPut}, true
	}
	if _, ok := deviceRotationRoute(path); ok {
		return []string{http.MethodPut}, true
	}
	return nil, false
}

func machineRoute(path string) (string, bool) {
	const prefix = "/v0/machines/"
	if !strings.HasPrefix(path, prefix) || strings.Contains(strings.TrimPrefix(path, prefix), "/") {
		return "", false
	}
	id := strings.TrimPrefix(path, prefix)
	return id, id != ""
}

func activationRoute(path string) (string, string, bool) {
	for _, mode := range []string{"enrollment", "recovery"} {
		prefix := "/v0/" + mode + "/"
		suffix := "/activation"
		if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, suffix) {
			id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
			if canonicalRawURLBytes(id, 16) {
				return mode, id, true
			}
		}
	}
	const rotationPrefix = "/v0/device-rotations/"
	const activationSuffix = "/activation"
	if strings.HasPrefix(path, rotationPrefix) && strings.HasSuffix(path, activationSuffix) {
		id := strings.TrimSuffix(strings.TrimPrefix(path, rotationPrefix), activationSuffix)
		if canonicalRawURLBytes(id, 16) {
			return "rotation", id, true
		}
	}
	return "", "", false
}

func deviceRotationRoute(path string) (string, bool) {
	const prefix = "/v0/device-rotations/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	id := strings.TrimPrefix(path, prefix)
	if strings.Contains(id, "/") || !canonicalRawURLBytes(id, 16) {
		return "", false
	}
	return id, true
}

func containsMethod(methods []string, method string) bool {
	for _, allowed := range methods {
		if method == allowed {
			return true
		}
	}
	return false
}

func peerCertificate(request *http.Request) *x509.Certificate {
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		return nil
	}
	return request.TLS.PeerCertificates[0]
}

func controllerHeaderBytes(header http.Header) int {
	total := 0
	for name, values := range header {
		total += len(name) + 4
		for _, value := range values {
			total += len(value) + 2
		}
	}
	return total
}

func cacheAge(now time.Time, snapshot *RelaySnapshot) time.Duration {
	if snapshot == nil {
		return 0
	}
	snapshotAt, err := parseCanonicalUTC(snapshot.SnapshotAt)
	if err != nil || now.Before(snapshotAt) {
		return 0
	}
	return now.Sub(snapshotAt)
}

func retryFor(status int) time.Duration {
	if status == http.StatusTooManyRequests {
		return time.Second
	}
	return 0
}

func boundedRetry(delay time.Duration) time.Duration {
	seconds := int(delay.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

// ControllerListener independently bounds source addresses and concurrent TCP
// connections before TLS. nftables remains the first network boundary.
type ControllerListener struct {
	net.Listener
	allowed netip.Addr
	active  chan struct{}
}

func NewControllerListener(listener net.Listener, allowedCIDR string) (*ControllerListener, error) {
	if listener == nil {
		return nil, errors.New("Controller listener is required")
	}
	prefix, err := netip.ParsePrefix(allowedCIDR)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() != 32 || prefix.Masked() != prefix {
		return nil, errors.New("Controller source must be one exact canonical private IPv4 /32")
	}
	return &ControllerListener{Listener: listener, allowed: prefix.Addr(), active: make(chan struct{}, 16)}, nil
}

func (listener *ControllerListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		tcp, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = connection.Close()
			continue
		}
		remote, parsed := netip.AddrFromSlice(tcp.IP)
		if !parsed || remote.Unmap() != listener.allowed {
			_ = connection.Close()
			continue
		}
		select {
		case listener.active <- struct{}{}:
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			return &trackedControllerConnection{Conn: connection, release: func() { <-listener.active }}, nil
		default:
			_ = connection.Close()
		}
	}
}

type trackedControllerConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *trackedControllerConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}
