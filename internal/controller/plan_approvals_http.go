package controller

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

// This file is the one file of the package the approval surface is open to.
// Freezing a definition and declaring an external element still cannot reach
// `internal/plan`, `internal/approval` or `internal/auxiliary` — their guards
// stand unchanged — and a guard of the same kind holds that no other file of
// this package imports the approval package. The strongest way to say "the
// submission route is the only door" is that no other code can reach what it
// opens (docs/architecture/TRAJET-DE-COMMANDE.md).

// maxPlanApprovalRequestBytes bounds a submission, derived from the documents
// it carries rather than picked round: a signed approval at its own kilobyte,
// two plan documents at their four, a definition at its eight — each of them
// travelling inside a JSON string whose canonical bytes escape at most the
// quote and the backslash, hence the doubling — plus the envelope's own
// fields. The same terms bound the Auxiliary's standard input; they are
// summed here from the packages that own them, never copied as a number.
const maxPlanApprovalRequestBytes = int64(2*(approval.MaxSignedApprovalBytes+
	2*plan.MaxPlanBytes+
	servicedefinition.MaxDefinitionBytes) + 512)

const planApprovalSchema = 1

// planApprovalRequest is everything the Console may submit: the approval's
// exact signed bytes, the pair those bytes sign, and the definition exactly
// when the operation's door pins one. The Console names no address, no port,
// no host key and no identity — it names a machine inside the envelope it
// signed, and everything else is a fact of enrolment this Controller reads on
// its own disk.
//
// The documents travel as their exact canonical bytes inside JSON strings,
// the one transport form this product gives a document: this Controller
// recanonises and rehashes them itself, and believes neither the Console nor
// its own earlier freeze.
type planApprovalRequest struct {
	SchemaVersion      int             `json:"schema_version"`
	SignedApproval     json.RawMessage `json:"signed_approval"`
	PlanDocument       string          `json:"plan_document"`
	RollbackDocument   string          `json:"rollback_document"`
	DefinitionDocument string          `json:"definition_document"`
}

// PlanDispatchEntry is one dispatch as the Console reads it: state, instants,
// digests, and what the machine reported or answered — nothing mutated, and
// nothing omitted that the registry holds.
type PlanDispatchEntry struct {
	ApprovalSHA256        string `json:"approval_sha256"`
	MachineID             string `json:"machine_id"`
	Operation             string `json:"operation"`
	ApprovalEpoch         uint64 `json:"approval_epoch"`
	Sequence              uint64 `json:"sequence"`
	PlanSHA256            string `json:"plan_sha256"`
	RollbackSHA256        string `json:"rollback_sha256"`
	State                 string `json:"state"`
	AcceptedAtUnix        uint64 `json:"accepted_at_unix"`
	FinishedAtUnix        uint64 `json:"finished_at_unix"`
	ExpiresAtUnix         uint64 `json:"expires_at_unix"`
	MachineSentence       string `json:"machine_sentence"`
	ControllerObservation string `json:"controller_observation"`
	DefinitionSlug        string `json:"definition_slug"`
	DefinitionSHA256      string `json:"definition_sha256"`
	ReportedChanged       bool   `json:"reported_changed"`
	ReportedOutcome       string `json:"reported_outcome"`
}

// PlanDispatchesView is the bounded history, oldest first, every machine
// together: the Console filters, this Controller does not choose for it.
type PlanDispatchesView struct {
	SchemaVersion int                 `json:"schema_version"`
	Dispatches    []PlanDispatchEntry `json:"dispatches"`
}

// PlanDispatchAcceptedView answers a submission: the record as it stands when
// the answer is written, which at this palier is its conclusion.
type PlanDispatchAcceptedView struct {
	SchemaVersion int               `json:"schema_version"`
	Dispatch      PlanDispatchEntry `json:"dispatch"`
}

// auxiliaryDispatcher is the seam the launch enters through (#126). It runs
// after the dispatch record is durably `in_flight`: everything it is handed
// is an authority already spent on this Controller, and nothing it returns
// can un-spend it.
//
// The wrapper bytes are the exact standard input of the machine's forced
// command; the returned state is one of the registry's terminal states, with
// the machine's own sentence when one was read and the Controller's own
// observation otherwise.
type auxiliaryDispatcher interface {
	Dispatch(record DispatchRecord, wrapper []byte) DispatchConclusion
}

// DispatchConclusion is everything one launch established, and nothing more.
// It is one value rather than a list of returns because the registry writes
// them together or not at all: a state without what a report carried, or a
// report without the state it concluded, would be a record that half happened.
type DispatchConclusion struct {
	State                 string
	MachineSentence       string
	ControllerObservation string
	ReportedChanged       bool
	ReportedOutcome       string
}

// AttachAuxiliaryDispatcher installs the one engine of this product whose
// effects leave the Controller's machine, and it is the structural reason no
// approval can ever be spent for nothing.
//
// Until an engine is attached, the two routes of the command trajectory **do
// not exist**: `ServeHTTP` and the methods table both read this one field, so
// the surface a reader counts and the surface the Controller serves cannot say
// different things. A Controller that received an approval it had no way to
// launch would durably spend a human authority and reach nothing — the
// contract allows that outcome for a host key that changed, which this
// Controller *observed*, never as the standing condition of a build.
//
// It refuses a second attachment for the same reason the registry refuses a
// second conclusion: one engine, once, named at startup.
func (handler *ControllerHandler) AttachAuxiliaryDispatcher(dispatcher auxiliaryDispatcher) error {
	if dispatcher == nil {
		return errors.New("an auxiliary dispatcher is attached or the command routes stay closed")
	}
	if handler.dispatcher != nil {
		return errors.New("this Controller already holds its one dispatch engine")
	}
	handler.dispatcher = dispatcher
	return nil
}

// commandTrajectoryRoute names the two routes that exist only beside an engine.
func commandTrajectoryRoute(path string) bool {
	return path == "/v0/plan-approvals" || path == "/v0/plan-dispatches"
}

// approvalRefusals is the closed list of this route. Every name carries a
// sentence in the Console; none carries another's status. The statuses tell
// the classes apart the way the package already does: a malformed request is
// 400, a machine this Controller does not manage is the existing 422, an
// authority that fails its own verification is 422, and signed bytes already
// spent are the one conflict a durable state can answer, 409.
const (
	refusalApprovalSignature  = "approval_signature_invalid"
	refusalApprovalExpired    = "approval_expired"
	refusalPairMismatch       = "approval_pair_mismatch"
	refusalDefinitionMismatch = "approval_definition_mismatch"
	refusalAlreadyDispatched  = "approval_already_dispatched"
	refusalSequenceInvalid    = "approval_sequence_invalid"
)

// servePlanApprovals receives one signed approval with its pair, reverifies
// everything, consumes the dispatch durably, then hands the launch to the
// dispatcher. The order of effects is the contract, top to bottom: nothing is
// written by a refused submission, and the durable write precedes any
// connection so that a restart between the two replays nothing.
func (handler *ControllerHandler) servePlanApprovals(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body planApprovalRequest
	if !handler.decodeJSONWithin(response, request, &body, maxPlanApprovalRequestBytes) {
		return
	}
	if body.SchemaVersion != planApprovalSchema {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}

	// The signed bytes are decoded and validated whole before any authority
	// question is asked; their digest — the registry's index — is taken over
	// the exact bytes received, never over a re-encoding.
	signed, err := approval.DecodeSigned([]byte(body.SignedApproval))
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	approvalDigest := hex.EncodeToString(func() []byte {
		sum := sha256.Sum256([]byte(body.SignedApproval))
		return sum[:]
	}())
	envelope := &signed.Envelope

	// The machine must be attached to this Controller's inventory, and the
	// envelope must name this installation: an approval for another
	// infrastructure is not an authority here, whoever signed it.
	inventory := handler.inventory.Snapshot()
	if envelope.InfrastructureID != inventory.InfrastructureID ||
		!attachedMachine(inventory, envelope.MachineID) {
		handler.writeProblem(response, http.StatusUnprocessableEntity, "machine_not_active", 0)
		return
	}

	// The signature is verified under the human approval key of this
	// association — the key the Console's native core signs with — read from
	// this Controller's own authority store, never from the document.
	device, err := handler.authority.AuthorizeActive(certificate, handler.now())
	if err != nil {
		handler.writeProblem(response, http.StatusForbidden, "scope_forbidden", 0)
		return
	}
	humanKey, err := decodeHumanApprovalKey(device.HumanPublicKey)
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	if err := signed.VerifySignature(humanKey); err != nil {
		handler.writeProblem(response, http.StatusUnprocessableEntity, refusalApprovalSignature, 0)
		return
	}

	// The clock window is the envelope's own; expired authority is refused
	// before any byte of the pair is even parsed.
	now := uint64(handler.now().Unix())
	if now < envelope.IssuedAtUnix || now >= envelope.ExpiresAtUnix {
		handler.writeProblem(response, http.StatusUnprocessableEntity, refusalApprovalExpired, 0)
		return
	}

	// The pair is recanonised and rehashed here, and the definition's two
	// rules — it travels exactly with its door, and it renders the digest the
	// plan pins — are held a second time. This Controller does not believe
	// its own earlier freeze.
	wrapper, pinned, err := handler.verifyApprovedPair(envelope, &body)
	if err != nil {
		code := refusalPairMismatch
		if _, definition := err.(*definitionMismatchError); definition {
			code = refusalDefinitionMismatch
		}
		handler.writeProblem(response, http.StatusUnprocessableEntity, code, 0)
		return
	}

	// The sequence is judged on what this Controller can attest — the highest
	// position a machine itself reported — and on nothing more. A Controller
	// that knows nothing refuses nothing here: the machine stays the
	// authority, and a disagreement is reported, never resolved locally.
	if attested := handler.dispatches.HighestReportedSequence(envelope.MachineID); attested >= envelope.Sequence {
		handler.writeProblem(response, http.StatusUnprocessableEntity, refusalSequenceInvalid, 0)
		return
	}

	// One submission per signed bytes, durably. The check and the write sit on
	// either side of the session gate below so a refused submission leaves no
	// trace, while an accepted one is spent before any connection exists —
	// spent by being submitted, not by reaching a machine.
	if handler.dispatches.AlreadySpent(approvalDigest) {
		handler.writeProblem(response, http.StatusConflict, refusalAlreadyDispatched, 0)
		return
	}

	record := DispatchRecord{
		ApprovalSHA256:   approvalDigest,
		MachineID:        envelope.MachineID,
		Operation:        envelope.Operation,
		ApprovalEpoch:    envelope.ApprovalEpoch,
		Sequence:         envelope.Sequence,
		PlanSHA256:       envelope.PlanSHA256,
		RollbackSHA256:   envelope.RollbackSHA256,
		State:            DispatchInFlight,
		AcceptedAtUnix:   now,
		ExpiresAtUnix:    envelope.ExpiresAtUnix,
		DefinitionSlug:   pinned.slug,
		DefinitionSHA256: pinned.digest,
	}
	var acceptError error
	if err := handler.sessions.Accept(context, func() error {
		acceptError = handler.dispatches.Accept(record)
		return acceptError
	}); err != nil {
		switch {
		case acceptError == nil:
			handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		default:
			// A second submission of the same bytes raced this one to the
			// registry: the durable state answered first, and the answer is
			// the same conflict it would have named a moment later.
			handler.writeProblem(response, http.StatusConflict, refusalAlreadyDispatched, 0)
		}
		return
	}

	// From here the authority is spent whatever happens, and the launch is
	// the dispatcher's. Its conclusion is written durably before the answer:
	// an answer that outran its own state would let a Console read a history
	// this Controller had not written yet.
	conclusion := handler.dispatcher.Dispatch(record, wrapper)
	finished := uint64(handler.now().Unix())
	if err := handler.dispatches.Conclude(approvalDigest, conclusion, finished); err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	concluded := record
	concluded.State = conclusion.State
	concluded.MachineSentence = conclusion.MachineSentence
	concluded.ControllerObservation = conclusion.ControllerObservation
	concluded.ReportedChanged = conclusion.ReportedChanged
	concluded.ReportedOutcome = conclusion.ReportedOutcome
	concluded.FinishedAtUnix = finished
	handler.writeAccepted(response, context, http.StatusOK, PlanDispatchAcceptedView{
		SchemaVersion: planApprovalSchema,
		Dispatch:      dispatchEntryOf(concluded),
	})
}

// servePlanDispatches reads the bounded history. It mutates nothing and omits
// nothing the registry holds: the bound lives where the records are kept,
// never in the reading.
func (handler *ControllerHandler) servePlanDispatches(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	if !handler.requireEmptyBody(response, request) {
		return
	}
	registry := handler.dispatches.Snapshot()
	view := PlanDispatchesView{
		SchemaVersion: planApprovalSchema,
		Dispatches:    make([]PlanDispatchEntry, 0, len(registry.Records)),
	}
	for index := range registry.Records {
		view.Dispatches = append(view.Dispatches, dispatchEntryOf(registry.Records[index]))
	}
	if handler.sessions.Touch(context) != nil {
		handler.writeProblem(response, http.StatusUnauthorized, "authentication_failed", 0)
		return
	}
	handler.writeJSON(response, http.StatusOK, view)
}

func dispatchEntryOf(record DispatchRecord) PlanDispatchEntry {
	return PlanDispatchEntry{
		ApprovalSHA256:        record.ApprovalSHA256,
		MachineID:             record.MachineID,
		Operation:             record.Operation,
		ApprovalEpoch:         record.ApprovalEpoch,
		Sequence:              record.Sequence,
		PlanSHA256:            record.PlanSHA256,
		RollbackSHA256:        record.RollbackSHA256,
		State:                 record.State,
		AcceptedAtUnix:        record.AcceptedAtUnix,
		FinishedAtUnix:        record.FinishedAtUnix,
		ExpiresAtUnix:         record.ExpiresAtUnix,
		MachineSentence:       record.MachineSentence,
		ControllerObservation: record.ControllerObservation,
		DefinitionSlug:        record.DefinitionSlug,
		DefinitionSHA256:      record.DefinitionSHA256,
		ReportedChanged:       record.ReportedChanged,
		ReportedOutcome:       record.ReportedOutcome,
	}
}

// definitionMismatchError tells the definition's refusals apart from the
// pair's without carrying any document content into an error message.
type definitionMismatchError struct{ reason error }

func (err *definitionMismatchError) Error() string { return err.reason.Error() }
func (err *definitionMismatchError) Unwrap() error { return err.reason }

// verifyApprovedPair recanonises the carried pair against the two digests the
// envelope signs, holds the definition to its door in both directions, and
// assembles the wrapper — the exact standard input of the machine's forced
// command — from the bytes it just verified and from nothing else.
// pinnedRevision is the frozen revision an approved plan pins, empty for the
// doors that pin none.
type pinnedRevision struct {
	slug   string
	digest string
}

func (handler *ControllerHandler) verifyApprovedPair(
	envelope *approval.Envelope, body *planApprovalRequest,
) ([]byte, pinnedRevision, error) {
	var pinned pinnedRevision
	planBytes := []byte(body.PlanDocument)
	rollbackBytes := []byte(body.RollbackDocument)
	if envelope.PlanSHA256 == envelope.RollbackSHA256 {
		return nil, pinnedRevision{}, fmt.Errorf("the approval names one digest as both the plan and its rollback")
	}
	if err := requireDigest(planBytes, envelope.PlanSHA256, "plan"); err != nil {
		return nil, pinnedRevision{}, err
	}
	if err := requireDigest(rollbackBytes, envelope.RollbackSHA256, "rollback"); err != nil {
		return nil, pinnedRevision{}, err
	}

	// The definition travels exactly with its door. Both directions are
	// refused by name, the same rule as the Auxiliary's entry — this
	// Controller holds it a second time rather than believing its transport.
	definitionRequired := envelope.Operation == approval.OperationDeployUserService ||
		envelope.Operation == approval.OperationRemoveUserService
	if !definitionRequired && body.DefinitionDocument != "" {
		return nil, pinnedRevision{}, &definitionMismatchError{fmt.Errorf(
			"a service definition travelled beside %q, which pins none", envelope.Operation)}
	}
	if definitionRequired {
		if body.DefinitionDocument == "" {
			return nil, pinnedRevision{}, &definitionMismatchError{fmt.Errorf(
				"the approved plan pins a service definition and none travelled with it")}
		}
		document, err := userServiceDocumentOf(planBytes)
		if err != nil {
			return nil, pinnedRevision{}, &definitionMismatchError{err}
		}
		// The revision is taken from the plan this Controller just parsed, never
		// from the request: what is recorded is what the approval binds.
		pinned = pinnedRevision{slug: document.DefinitionSlug, digest: document.DefinitionDigest}
		definition, err := servicedefinition.Verify([]byte(body.DefinitionDocument), document.DefinitionDigest)
		if err != nil {
			return nil, pinnedRevision{}, &definitionMismatchError{err}
		}
		if err := plan.RequireDefinitionAgreement(*document, definition); err != nil {
			return nil, pinnedRevision{}, &definitionMismatchError{err}
		}
	}

	wrapper := struct {
		SignedApproval json.RawMessage `json:"signed_approval"`
		Plan           string          `json:"plan"`
		Rollback       string          `json:"rollback"`
		Definition     string          `json:"definition"`
	}{
		SignedApproval: body.SignedApproval,
		Plan:           body.PlanDocument,
		Rollback:       body.RollbackDocument,
		Definition:     body.DefinitionDocument,
	}
	encoded, err := json.Marshal(wrapper)
	if err != nil {
		return nil, pinnedRevision{}, fmt.Errorf("wrapper: %w", err)
	}
	return encoded, pinned, nil
}

// requireDigest recanonises one carried document by its declared schema and
// holds the digest rebuilt from the parsed fields — never from the received
// bytes — against the one the envelope signs. It is the pair discipline of
// the Auxiliary's entry, written on the Controller's side of the trajectory.
func requireDigest(document []byte, signedDigest, role string) error {
	if len(document) == 0 || len(document) > plan.MaxPlanBytes {
		return fmt.Errorf("carried %s: plan document must contain 1..%d bytes", role, plan.MaxPlanBytes)
	}
	var declared struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(document, &declared); err != nil || declared.SchemaVersion == nil {
		return fmt.Errorf("carried %s: no plan schema version is declared", role)
	}
	var digest string
	var err error
	switch *declared.SchemaVersion {
	case plan.SchemaVersion:
		var parsed *plan.Document
		if parsed, err = plan.Decode(document); err == nil {
			digest, err = parsed.SHA256()
		}
	case plan.SchemaVersionV2:
		var parsed plan.V2Document
		if parsed, err = plan.DecodeV2(document); err == nil {
			digest, err = parsed.SHA256()
		}
	case plan.SchemaVersionV3:
		var parsed plan.V3Document
		if parsed, err = plan.DecodeV3(document); err == nil {
			digest, err = parsed.SHA256()
		}
	default:
		return fmt.Errorf("carried %s: plan schema %d is not one this Controller reads", role, *declared.SchemaVersion)
	}
	if err != nil {
		return fmt.Errorf("carried %s: %w", role, err)
	}
	if digest != signedDigest {
		return fmt.Errorf("carried %s does not render the digest the approval signs", role)
	}
	return nil
}

// userServiceDocumentOf returns the user-service plan the deploy and remove
// doors pin their definition through, or the reason the carried plan is not
// one.
func userServiceDocumentOf(document []byte) (*plan.UserServiceDocument, error) {
	parsed, err := plan.DecodeV2(document)
	if err != nil {
		return nil, err
	}
	subject, ok := parsed.(plan.UserServiceDocument)
	if !ok {
		return nil, fmt.Errorf("the approved operation pins a definition, but the plan is not a user-service document")
	}
	return &subject, nil
}

func decodeHumanApprovalKey(encoded string) (ed25519.PublicKey, error) {
	key, err := decodeFixed(encoded, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(key), nil
}
