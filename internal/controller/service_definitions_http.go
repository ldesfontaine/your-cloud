package controller

import (
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

// maxServiceDefinitionRequestBytes bounds a submission, and is the one route of
// this Controller whose request bound is not the common one.
//
// It has to be its own: the contract bounds a definition at its own eight
// kilobytes, the document travels inside a JSON string, and a canonical
// definition is printable ASCII in which only the quote and the backslash are
// escaped — so a document at its bound arrives as at most twice its bytes, plus
// the two other fields of the envelope. Deriving the bound from the document's
// own rather than picking a round number is what keeps a definition the contract
// admits from being one this route could never receive. Every other route keeps
// the common four kilobytes: this one is wider because one named document is
// wider, not because requests in general are.
const maxServiceDefinitionRequestBytes = int64(2*servicedefinition.MaxDefinitionBytes + 512)

// serviceDefinitionRequest is everything the Console may choose about a freeze,
// and it is the one transport form a definition has: its exact canonical bytes as
// a JSON string, beside the digest they hash to.
//
// The bytes arrive as a string rather than as a nested object on purpose. What is
// frozen must be a document the Console can hash itself, display whole and hand
// to a signature later; a nested object would be re-encoded by every transport it
// crossed, and the human would be approving a shape rather than bytes.
//
// The digest is not an authority and is never stored as received: it is the
// Console's own answer, computed by its own encoder, and this Controller refuses
// the submission when its own answer differs. That is the cross-check between the
// two implementations of one canonical encoding, done at the moment a definition
// enters the product rather than the day a plan pins it — and it is the reason
// the field is required rather than optional. What is kept afterwards is this
// Controller's spelling of the digest, never the caller's.
//
// There is no field for a machine, an account, a host path, a port of a host, an
// operation or a date. Freezing a definition touches no machine, so a submission
// that could name one would be a submission whose refusal had to be written
// somewhere; here there is nothing to refuse, because there is nothing to say.
type serviceDefinitionRequest struct {
	SchemaVersion      int    `json:"schema_version"`
	DefinitionDocument string `json:"definition_document"`
	DefinitionSHA256   string `json:"definition_sha256"`
}

// ServiceDefinitionView is what the Console receives for one freeze: the
// definition exactly as a listing carries it, and the revision of the inventory
// it now belongs to.
type ServiceDefinitionView struct {
	SchemaVersion      int                    `json:"schema_version"`
	DefinitionRevision uint64                 `json:"definition_revision"`
	Definition         ServiceDefinitionEntry `json:"definition"`
}

// serveServiceDefinitions freezes definitions and reads them back, and holds no
// power beyond that.
//
// It borrows the same session authority as every other business route and adds no
// error code: bytes that are not a definition of the contract, or a digest that
// does not name them, receive the existing `400 invalid_request`; an inventory
// that cannot take the revision receives the existing `409 state_conflict`. There
// is no `422 machine_not_active` on this route and there is nothing for one to
// mean: a definition is an inventory of infrastructure and names no machine, so
// this handler never reads the managed inventory and never asks the Relay
// anything.
//
// Freezing is the whole of the effect. No plan is built here — this file imports
// nothing that could build one — no resource is created and no machine is
// contacted; the definition becomes something a human may later pin from a plan
// route, and that plan is where the first effect of this palier is born.
func (handler *ControllerHandler) serveServiceDefinitions(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		if !handler.requireEmptyBody(response, request) {
			return
		}
		// The listing carries every frozen definition, and a listing that cannot be
		// encoded whole is an error rather than a shorter listing: the contract says
		// this reading omits none, and a Console silently missing one revision would
		// let a human believe a definition was never frozen.
		view, err := ProjectServiceDefinitions(handler.definitions.Snapshot())
		if err != nil {
			handler.writeProblem(response, http.StatusServiceUnavailable, "projection_unavailable", 0)
			return
		}
		encoded, err := EncodeServiceDefinitionsView(view)
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
	var body serviceDefinitionRequest
	if !handler.decodeJSONWithin(response, request, &body, maxServiceDefinitionRequestBytes) {
		return
	}
	if body.SchemaVersion != serviceDefinitionSchema {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	var frozen FrozenServiceDefinition
	var revision uint64
	var created bool
	var mutationError error
	if err := handler.sessions.Accept(context, func() error {
		frozen, revision, created, mutationError = handler.definitions.Freeze(
			[]byte(body.DefinitionDocument), body.DefinitionSHA256, handler.now())
		return mutationError
	}); err != nil {
		switch {
		case mutationError == nil:
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		case errors.Is(mutationError, errServiceDefinitionRefused):
			handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		default:
			handler.writeProblem(response, http.StatusConflict, "state_conflict", 0)
		}
		return
	}
	// A first freeze created a revision; a repeated one found the revision it
	// already held and moved nothing. The two are told apart by the status alone —
	// the body is identical, because the definition is identical — so a Console
	// that submits the same bytes twice reads the same answer twice and learns that
	// nothing was duplicated.
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	handler.writeJSON(response, status, ServiceDefinitionView{
		SchemaVersion: 1, DefinitionRevision: revision, Definition: serviceDefinitionEntry(frozen),
	})
}
