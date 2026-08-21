package controller

import (
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/machineid"
)

// The two requests below are everything the App may choose about the
// declared inventory, one closed schema per act.
//
// Neither of them produces a plan, and neither could. There is no operation
// field to name, no document to freeze, no digest to carry and no envelope to
// sign: this palier teaches the product to show without acting, and the way a
// route cannot act is by having nothing in its schema that describes an act.
//
// externalDeclarationRequest carries exactly the five closed fields of the
// contract. It has no field for an image, a version, a digest, a command or an
// address: the product installs nothing here, and pretending to know the version
// of a service it did not place would be the one lie this inventory exists to
// avoid. `machine_id` is the point of view a future reading is taken from, and
// `probe_port` is a loopback port on that machine — never a host, never a route,
// never a third party to reach across the network.
type externalDeclarationRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Label         string `json:"label"`
	Kind          string `json:"kind"`
	ProbePort     int    `json:"probe_port"`
}

// externalWithdrawalRequest names the one declaration to withdraw.
//
// A withdrawal is a POST to its own route rather than a DELETE on the element,
// and that is a decision, not an oversight. The business surface of the contract
// exposes no DELETE, and this palier is the worst possible place to open one: a
// DELETE says the product is removing the resource it owns, and the product owns
// nothing here. Withdrawing removes the declaration; the thing keeps running,
// keeps its data and keeps listening, and the route's own name says so.
type externalWithdrawalRequest struct {
	SchemaVersion int    `json:"schema_version"`
	ElementID     string `json:"element_id"`
}

// ExternalDeclarationView is what the App receives for one declaration,
// carrying the same projected shape a listing carries so that what a human sees
// after declaring and what they see afterwards are the same object.
type ExternalDeclarationView struct {
	SchemaVersion    int                      `json:"schema_version"`
	ExternalRevision uint64                   `json:"external_revision"`
	Element          ProjectedExternalElement `json:"element"`
}

// ExternalWithdrawalView states which declaration is gone and nothing more. The
// sentence about the thing that keeps existing is the App's, from the
// context of this route: a Controller that could send a user-facing text could
// send a reassuring one.
type ExternalWithdrawalView struct {
	SchemaVersion    int    `json:"schema_version"`
	ExternalRevision uint64 `json:"external_revision"`
	ElementID        string `json:"element_id"`
}

// serveExternalElements reads and extends the declared inventory.
//
// It borrows the same session authority as every other business route and adds
// no error code: a machine outside the managed inventory receives the existing
// `422 machine_not_active`, a refused label the existing `422 label_invalid`, a
// declaration that repeats one already held the existing `409 state_conflict`.
func (handler *ControllerHandler) serveExternalElements(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		if !handler.requireEmptyBody(response, request) {
			return
		}
		// The readings of the machines are taken in before the inventory is
		// projected, from the same Relay read `GET /v0/machines` already makes and
		// with the same bounds, caching and backoff. A Relay this Controller could
		// not read leaves the declared inventory exactly as it was: a transport this
		// Controller is blind through is its own failure and never a fact about a
		// machine, so nothing is recorded and the last constats go on ageing
		// honestly. A failure to record is not a failure to answer either — the
		// projection is what the human asked for.
		snapshot, status, _ := handler.relay.Read(request.Context(), time.Time{})
		if status == RelayAvailable {
			_ = handler.external.AbsorbSnapshot(snapshot)
		}
		view, err := ProjectExternalElements(handler.external.Snapshot(), handler.now())
		if err != nil {
			handler.writeProblem(response, http.StatusServiceUnavailable, "projection_unavailable", 0)
			return
		}
		encoded, err := EncodeExternalElementsView(view)
		if err != nil {
			handler.writeProblem(response, http.StatusServiceUnavailable, "projection_unavailable", 0)
			return
		}
		if handler.sessions.Touch(context) != nil {
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
			return
		}
		handler.writeEncodedJSON(response, http.StatusOK, encoded)
		return
	}
	var body externalDeclarationRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != externalSchema || machineid.Validate(body.MachineID) != nil ||
		(body.Kind != ExternalKindService && body.Kind != ExternalKindPassage) ||
		body.ProbePort < 1 || body.ProbePort > 65535 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	if _, err := CanonicalExternalLabel(body.Label); err != nil {
		handler.writeProblem(response, http.StatusUnprocessableEntity, "label_invalid", 0)
		return
	}
	// The managed inventory is the only place this Controller knows an enrolled
	// machine by name, and a declaration must name one: the machine is the point
	// of view the reading will be taken from, so a declaration aimed at a machine
	// the product never enrolled describes a viewpoint nobody holds. Membership
	// here is the same past proof of enrolment the plan routes rely on.
	if !attachedMachine(handler.inventory.Snapshot(), body.MachineID) {
		handler.writeProblem(response, http.StatusUnprocessableEntity, "machine_not_active", 0)
		return
	}
	declaration := ExternalDeclaration{
		MachineID: body.MachineID, Label: body.Label, Kind: body.Kind, ProbePort: body.ProbePort,
	}
	var element ExternalElement
	var revision uint64
	var mutationError error
	if err := handler.sessions.Accept(context, func() error {
		element, revision, mutationError = handler.external.Declare(declaration, true, handler.now())
		return mutationError
	}); err != nil {
		if mutationError == nil {
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
			return
		}
		handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		return
	}
	projected, err := projectExternalElement(element, handler.now())
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "projection_unavailable", 0)
		return
	}
	handler.writeJSON(response, http.StatusCreated, ExternalDeclarationView{
		SchemaVersion: 1, ExternalRevision: revision, Element: projected,
	})
}

// serveExternalElementWithdrawals removes one declaration and nothing else.
//
// An unknown identifier receives `404 resource_not_found` rather than a silent
// success: a withdrawal that pretended to have removed something it never held
// would let an App report a retreat that did not happen.
func (handler *ControllerHandler) serveExternalElementWithdrawals(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body externalWithdrawalRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != externalSchema || !canonicalRawURLBytes(body.ElementID, 16) {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	var revision uint64
	var mutationError error
	if err := handler.sessions.Accept(context, func() error {
		_, revision, mutationError = handler.external.Withdraw(body.ElementID)
		return mutationError
	}); err != nil {
		switch {
		case mutationError == nil:
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		case errors.Is(mutationError, errExternalElementUnknown):
			handler.writeProblem(response, http.StatusNotFound, "resource_not_found", 0)
		default:
			handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		}
		return
	}
	handler.writeJSON(response, http.StatusOK, ExternalWithdrawalView{
		SchemaVersion: 1, ExternalRevision: revision, ElementID: body.ElementID,
	})
}
