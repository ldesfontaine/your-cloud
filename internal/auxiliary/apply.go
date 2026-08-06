package auxiliary

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	// ServiceStateActive and ServiceStateAbsent are the only two states this
	// palier announces. There is no third one on purpose: a probe that is
	// neither running nor gone is a state this Auxiliary reports as a failure by
	// name, never as a status.
	ServiceStateActive = "active"
	ServiceStateAbsent = "absent"
)

// The conclusions this Auxiliary is able to reach, named so that no reader has
// to infer one from the shape of an error.
//
// Two further conclusions exist and carry none of these words on purpose. A
// refusal — a document that was not signed, a plan aimed
// elsewhere, a machine that cannot run the flow — is an ordinary error with no
// outcome at all, because nothing happened and there is nothing to undo; that is
// what keeps a refusal from ever reading as a rollback. And a cut in the middle
// of a mutation produces no conclusion whatsoever: the process that would have
// written one is dead, the sequence it spent stays spent, and the absence of an
// answer is the answer — the result is unknown until something observes the
// machine.
const (
	// OutcomeApplied is the machine holding the approved state, whether reaching
	// it changed anything or found it already true.
	OutcomeApplied = "applied"
	// OutcomeRolledBack is a controlled failure whose approved rollback was
	// attempted and reached the state that rollback describes.
	OutcomeRolledBack = "rolled_back_after_controlled_failure"
	// OutcomePartial is a controlled failure whose approved rollback was
	// attempted and failed in its turn. It claims nothing about the machine
	// beyond what a read could still establish.
	OutcomePartial = "partial_state_after_failed_rollback"
)

// The closed vocabulary an Observation is written in. Each word is a fact or the
// admission that the fact could not be obtained; none of them is the output of a
// command, and none of them means "fine".
const (
	observedUnknown  = "unknown"
	observedPresent  = "present"
	observedAbsent   = "absent"
	observedActive   = "active"
	observedInactive = "inactive"
	observedPinned   = "pinned"
	observedOther    = "other"
	observedNone     = "none"
)

// Application is what one applied plan leaves behind on the machine.
//
// It says what the machine now holds, not what the plan asked for. Changed is
// computed from what was observed before acting and never announced in advance:
// it is the one field a reader uses to tell an operation that did something from
// an operation that found the approved state already there.
// The three fields below the operation name the instance that was applied, and
// which of them are filled is decided by what kind of instance it was: a managed
// service names its loopback port and its sheet, an entrypoint names its sheet
// alone, and a route names the declared host and the one fragment file that host
// owns. Nothing here carries a certificate, a key or any content of a file.
type Application struct {
	Operation    string
	LocalPort    int
	UnitPath     string
	RouteHost    string
	FragmentPath string
	ServiceState string
	Changed      bool
}

// Observation is what read-only calls could still establish about this machine
// after a rollback had itself failed.
//
// It is written in the closed vocabulary above and never in the words of a
// command: a reader learns what was seen, or that it could not be seen at all.
// It is deliberately incapable of saying that the machine is in a known state,
// because a failed rollback is precisely the moment that ceased to be true.
type Observation struct {
	Account   string `json:"account"`
	UnitFile  string `json:"unit_file"`
	Service   string `json:"service"`
	Container string `json:"container"`
	// Fragment is filled only while the instance that was being applied is a
	// route, because it is the only instance whose state is a fragment file. It
	// is omitted rather than reported empty everywhere else: an observation says
	// what was seen, and a word about something the operation never touched would
	// be neither a fact nor an admission.
	Fragment string `json:"fragment,omitempty"`
}

// ControlledFailure is a failure that happened after this machine had already
// been changed, together with what was done about it.
//
// It exists so that the two failures of this palier can never be read as one
// another. A refusal is an ordinary error and carries none of these fields,
// because a run that touched nothing has nothing to undo. This value only
// exists once a mutating effect was attempted, and it always means the same
// three things: the operation failed, the approved rollback — the second signed
// document, verified byte for byte and proven the exact inverse of the plan —
// was attempted through the same path as an ordinary operation, and that
// attempt either reached the state it describes or did not.
//
// Nothing else was tried. There is no retry of the failed operation, no second
// rollback and no cleanup this Auxiliary invented for itself: what a human
// approved is the whole of what may run here.
type ControlledFailure struct {
	// Operation, LocalPort, UnitPath, RouteHost and FragmentPath name the
	// instance that was being applied, so that a failure names an instance as
	// exactly as a success does, and by the same rule: whichever of them the kind
	// of instance actually has.
	Operation    string
	LocalPort    int
	UnitPath     string
	RouteHost    string
	FragmentPath string

	// Outcome is OutcomeRolledBack or OutcomePartial, and never anything else.
	Outcome string

	// Cause is the failure that stopped the operation. Rollback is the failure
	// of the rollback itself, and is nil while the rollback succeeded.
	Cause    error
	Rollback error

	// Observed is filled only when the rollback failed, and only from read-only
	// calls made after it did.
	Observed *Observation
}

func (failure *ControlledFailure) Error() string {
	if failure.Outcome == OutcomeRolledBack || failure.Observed == nil {
		return fmt.Sprintf(
			"%s failed after this machine was changed (%v): the approved rollback was attempted and this machine now holds the state that rollback describes",
			failure.Operation, failure.Cause,
		)
	}
	return fmt.Sprintf(
		"%s failed after this machine was changed (%v): the approved rollback was attempted and failed in its turn (%v): "+
			"this machine is left in a partial state, observed as account %s, unit file %s, service %s, container %s",
		failure.Operation, failure.Cause, failure.Rollback,
		failure.Observed.Account, failure.Observed.UnitFile,
		failure.Observed.Service, failure.Observed.Container,
	)
}

// Unwrap keeps the failure that stopped the operation reachable, so a caller
// that wants to know why this machine was being changed at all does not have to
// read a sentence.
func (failure *ControlledFailure) Unwrap() error { return failure.Cause }

// instanceKind is which of the three shapes an approved instance has, and it is
// read from the operation rather than guessed from which fields happen to be
// filled. It is what keeps a route from ever being applied through the sheet
// path, and an entrypoint from ever being applied through the service one.
type instanceKind int

const (
	kindWebService instanceKind = iota + 1
	kindEntrypoint
	kindRoute
)

// instance is one thing this Auxiliary has been approved to act on, once the
// schema its two documents were written in has stopped mattering.
//
// It is what dispatch produces and what every effect below consumes: which kind
// of thing it is, the state asked for, where that state lives on this machine,
// and the one, two or zero bounded values the plan of that kind is allowed to
// choose. Nothing else of a document travels past dispatch. The image in
// particular does not: it is the profile's or the entrypoint's pin, and the
// document's own copy of it has already been required to be exactly that pin.
//
// A route carries the entrypoint's placement rather than one of its own. It has
// no account, no sheet and no container: it is one file inside the directory the
// entry reads, so the placement it names is the entry it is served by, and the
// two fields below are what a route actually is.
type instance struct {
	kind        instanceKind
	operation   string
	placement   placement
	localPort   int
	routeHost   string
	backendPort int
}

// reportedUnitPath and reportedFragmentPath are how one instance names itself in
// a conclusion, each answering only for the kind that has such a thing.
func (subject instance) reportedUnitPath() string {
	if subject.kind == kindRoute {
		return ""
	}
	return subject.placement.unitPath()
}

func (subject instance) reportedFragmentPath() string {
	if subject.kind != kindRoute {
		return ""
	}
	return routeFragmentPath(subject.routeHost)
}

// Apply performs one approved mutating operation, in the one order the contract
// fixes and with no partial effect before it is complete.
//
// The order is the whole security argument, so it is written once, here:
//
//  1. the approval itself is already accepted by the caller — signature against
//     the root-owned anchor, target, epoch, expiry, exact privileges, and the
//     sequence durably consumed. A run interrupted after that point has spent
//     its sequence and will never be replayed;
//  2. the schema the two carried documents declare is read, and the two are
//     required to declare the same one: a pair written in two schemas is not a
//     pair, and neither decoder is allowed to cover for the other. A schema this
//     package does not read is refused here by name, with nothing decoded —
//     schema 3, the private passage, is exactly that until the issues that own
//     its application land;
//  3. the two received documents are held against the two digests that
//     approval signed, through the transcript of their own schema, so a
//     Controller that reindented them carries the same plan and a Controller
//     that changed one value carries none;
//  4. the plan targets this machine and this infrastructure, as the machine's
//     own anchor names them and not as the document claims;
//  5. the plan's content stays inside the contract — the plan package refuses a
//     document that leaves it before its digest is even computed — and the
//     operation is one this Auxiliary actually performs. Every operation of the
//     two schemas this package reads is now performed, so what this step still
//     refuses, by name and with nothing read, is a document whose operation
//     belongs to no shape this package places;
//  6. the machine is capable of the flow at all, and a machine that is not is
//     refused here, with nothing written.
//
// Only then does anything change. What happens if a change fails halfway is
// decided in one place, by concluded below: everything that fails before the
// first effect stays a refusal, and everything that fails after it attempts
// exactly the rollback a human signed beside the plan.
func Apply(executor Executor, accepted *approval.Acceptance, input *Input) (*Application, error) {
	if executor == nil || accepted == nil || accepted.Envelope == nil || accepted.State == nil || input == nil {
		return nil, errors.New("applying a plan requires an executor and an accepted approval")
	}
	if input.Kind != KindApply {
		return nil, errors.New("an applied operation requires the plan and the rollback the approval signed")
	}

	requested, rollback, err := approvedInstances(accepted, input)
	if err != nil {
		return nil, err
	}

	capabilities, err := executor.Capabilities(requested.placement.account)
	if err != nil {
		return nil, fmt.Errorf("observe this machine's capabilities: %w", err)
	}
	if err := requireCapableMachine(capabilities, requested.placement); err != nil {
		return nil, err
	}

	switch requested.operation {
	case plan.OperationDeployOCIProbe, plan.OperationDeployWebService:
		application, touched, err := deploy(executor, capabilities, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRemoveOCIProbe, plan.OperationRemoveWebService:
		application, touched, err := remove(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationDeployEntrypoint:
		application, touched, err := deployEntrypoint(executor, capabilities, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRemoveEntrypoint:
		application, touched, err := removeEntrypoint(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationPublishRoute:
		application, touched, err := publishRoute(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRetireRoute:
		application, touched, err := retireRoute(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	default:
		// Unreachable while dispatch and this switch agree on the same closed
		// list, and kept as a refusal rather than a panic so that a disagreement
		// between them is a refusal to act.
		return nil, fmt.Errorf("operation %q is not one this Auxiliary applies", requested.operation)
	}
}

// approvedInstances turns the two carried documents into the two instances the
// effects below act on, or refuses before this machine is read at all.
//
// The schema is chosen by what the documents declare and never by trying each
// decoder in turn, and both documents must declare the same one. That single
// rule is what keeps the two schemas from covering for one another: a schema 1
// plan cannot be undone by a schema 2 rollback, and a schema 2 plan cannot be
// smuggled past the older contract by a rollback written in the older schema.
func approvedInstances(accepted *approval.Acceptance, input *Input) (instance, instance, error) {
	planSchema, err := declaredSchema(input.PlanDocument, "plan")
	if err != nil {
		return instance{}, instance{}, err
	}
	rollbackSchema, err := declaredSchema(input.RollbackDocument, "rollback")
	if err != nil {
		return instance{}, instance{}, err
	}
	if planSchema != rollbackSchema {
		return instance{}, instance{}, fmt.Errorf(
			"the approved plan is written in plan schema %d and its rollback in plan schema %d: a pair written in two schemas is not a pair",
			planSchema, rollbackSchema,
		)
	}
	switch planSchema {
	case plan.SchemaVersion:
		return probeInstances(accepted, input)
	case plan.SchemaVersionV2:
		return serviceInstances(accepted, input)
	default:
		return instance{}, instance{}, fmt.Errorf(
			"the approved documents declare plan schema %d, which this Auxiliary does not read", planSchema)
	}
}

// declaredSchema reads only the schema version of a carried document, and
// decides from it alone which decoder will hold that document against its whole
// contract.
//
// It is the same principle as the discriminator of the standard input and as the
// plan package's own operation selector: the shape is read in the document
// rather than guessed by trying each decoder in turn. Nothing is decided here —
// this pass selects a decoder, and the strict decoding that follows is the whole
// of the authority, including the duplicate keys and the unknown fields this
// pass deliberately does not look at.
func declaredSchema(document []byte, role string) (int, error) {
	if len(document) == 0 || len(document) > plan.MaxPlanBytes {
		return 0, fmt.Errorf("carried %s: plan document must contain 1..%d bytes", role, plan.MaxPlanBytes)
	}
	var declared struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(document, &declared); err != nil || declared.SchemaVersion == nil {
		return 0, fmt.Errorf("carried %s: no plan schema version is declared", role)
	}
	return *declared.SchemaVersion, nil
}

// probeInstances holds one schema 1 pair against the approval that carries it.
//
// It is the path `#14` proved, unchanged: the same digests, the same target, the
// same exact inverse, and the probe's own placement, which no document names and
// no document can move.
func probeInstances(accepted *approval.Acceptance, input *Input) (instance, instance, error) {
	envelope := accepted.Envelope
	requested, err := documentMatching(input.PlanDocument, envelope.PlanSHA256, "plan")
	if err != nil {
		return instance{}, instance{}, err
	}
	rollback, err := documentMatching(input.RollbackDocument, envelope.RollbackSHA256, "rollback")
	if err != nil {
		return instance{}, instance{}, err
	}
	if err := requireApprovedTarget(accepted, requested.InfrastructureID, requested.MachineID, requested.Operation); err != nil {
		return instance{}, instance{}, err
	}
	if !rollback.IsExactInverseOf(requested) {
		return instance{}, instance{}, errors.New("the approved rollback does not undo exactly the approved plan")
	}
	return instance{
			kind: kindWebService, operation: requested.Operation,
			placement: probePlacement, localPort: requested.LocalPort,
		},
		instance{
			kind: kindWebService, operation: rollback.Operation,
			placement: probePlacement, localPort: rollback.LocalPort,
		},
		nil
}

// serviceInstances holds one schema 2 pair against the approval that carries it,
// and turns it into the two instances the effects act on.
//
// The three document shapes of schema 2 become the three instance kinds here,
// and this is the only place that mapping exists. Until `#91` landed, the four
// entrypoint and route operations were refused at this exact point by name; they
// are performed now, so what remains is the one refusal that outlives them — a
// document shape this package has no placement for is refused before any effect,
// because there is nowhere for it to be placed.
func serviceInstances(accepted *approval.Acceptance, input *Input) (instance, instance, error) {
	envelope := accepted.Envelope
	requested, err := v2DocumentMatching(input.PlanDocument, envelope.PlanSHA256, "plan")
	if err != nil {
		return instance{}, instance{}, err
	}
	rollback, err := v2DocumentMatching(input.RollbackDocument, envelope.RollbackSHA256, "rollback")
	if err != nil {
		return instance{}, instance{}, err
	}
	target := requested.Target()
	if err := requireApprovedTarget(accepted, target.InfrastructureID, target.MachineID, requested.OperationName()); err != nil {
		return instance{}, instance{}, err
	}
	if !rollback.IsExactInverseOf(requested) {
		return instance{}, instance{}, errors.New("the approved rollback does not undo exactly the approved plan")
	}

	// The rollback is already known to be the exact inverse of the plan, which
	// compares the two documents whole and therefore across their types. Reading
	// each of them as its own shape again costs one assertion apiece and removes
	// the need to trust that.
	switch subject := requested.(type) {
	case plan.WebServiceDocument:
		undoing, paired := rollback.(plan.WebServiceDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		where, err := placementFor(subject)
		if err != nil {
			return instance{}, instance{}, err
		}
		return instance{
				kind: kindWebService, operation: subject.Operation,
				placement: where, localPort: subject.LocalPort,
			},
			instance{
				kind: kindWebService, operation: undoing.Operation,
				placement: where, localPort: undoing.LocalPort,
			},
			nil
	case plan.EntrypointDocument:
		undoing, paired := rollback.(plan.EntrypointDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		if err := requireEntrypointImage(subject); err != nil {
			return instance{}, instance{}, err
		}
		return instance{
				kind: kindEntrypoint, operation: subject.Operation,
				placement: entrypointPlacement,
			},
			instance{
				kind: kindEntrypoint, operation: undoing.Operation,
				placement: entrypointPlacement,
			},
			nil
	case plan.RouteDocument:
		undoing, paired := rollback.(plan.RouteDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		// The name has to be one this machine can hold as a single file, and that
		// is decided here rather than at the moment the fragment is written: a
		// route this machine could not name is refused before any effect and
		// before the machine is read at all.
		if err := requireHoldableFragmentName(subject.RouteHost); err != nil {
			return instance{}, instance{}, err
		}
		return instance{
				kind: kindRoute, operation: subject.Operation,
				placement: entrypointPlacement,
				routeHost: subject.RouteHost, backendPort: subject.BackendPort,
			},
			instance{
				kind: kindRoute, operation: undoing.Operation,
				placement: entrypointPlacement,
				routeHost: undoing.RouteHost, backendPort: undoing.BackendPort,
			},
			nil
	default:
		// Unreachable while the plan package's closed interface holds exactly the
		// three shapes above, and kept as a refusal rather than a panic so that a
		// fourth shape added there without a placement here is refused instead of
		// placed by accident.
		return instance{}, instance{}, fmt.Errorf(
			"the approved plan describes %q, which this Auxiliary has no placement for",
			requested.OperationName(),
		)
	}
}

// errMismatchedPair is unreachable while the exact-inverse check above compares
// the two documents whole, and is kept so that a disagreement between that check
// and these assertions refuses rather than acts on half a pair.
var errMismatchedPair = errors.New("the approved rollback is not a document of the same shape as the plan it undoes")

// requireEntrypointImage is the second place the entrypoint's image is required
// to be exactly the pin of the contract.
//
// It is the entrypoint's spelling of what placementFor does for a profile, and
// it exists for the same reason: the sheet is written from the constant and not
// from the document, and a validation that ever stopped enforcing the equality
// would be caught here, before any effect, rather than deployed.
func requireEntrypointImage(document plan.EntrypointDocument) error {
	if document.ImageReference+"@"+document.ImageDigest != entrypointPlacement.image {
		return errors.New("the approved plan names another image than the entrypoint of this palier pins")
	}
	return nil
}

// requireApprovedTarget holds one document against this machine's own anchor and
// against the approval that carries it, whatever the document's schema.
//
// The anchor decides which machine this is. Comparing against the accepted state
// rather than against the envelope is what keeps a plan from being aimed at
// another installation by a Controller that also wrote the envelope it travels
// with.
func requireApprovedTarget(accepted *approval.Acceptance, infrastructureID, machineID, operation string) error {
	if infrastructureID != accepted.State.InfrastructureID {
		return errors.New("the approved plan targets another infrastructure than this machine's anchor")
	}
	if machineID != accepted.State.MachineID {
		return errors.New("the approved plan targets another machine than this one")
	}
	if operation != accepted.Envelope.Operation {
		return fmt.Errorf(
			"the approved plan describes %q while the approval names %q",
			operation, accepted.Envelope.Operation,
		)
	}
	return nil
}

// placementFor is where one approved service profile lives on this machine, and
// the second place its image is required to be exactly the profile's pin.
//
// The plan package already refuses a document naming another couple, so nothing
// here parses a policy: the check is an equality against the profile's own pin,
// restated at the moment the sheet is about to be written from that pin rather
// than from the document. A validation that ever stopped enforcing it would be
// caught here, before any effect, rather than deployed.
func placementFor(document plan.WebServiceDocument) (placement, error) {
	where, known := profilePlacements[document.ServiceProfile]
	if !known {
		return placement{}, fmt.Errorf(
			"plan service_profile %q is not one this Auxiliary places", document.ServiceProfile)
	}
	if document.ImageReference+"@"+document.ImageDigest != where.image {
		return placement{}, fmt.Errorf(
			"the approved plan names another image than the %s profile pins", document.ServiceProfile)
	}
	return where, nil
}

// documentMatching returns the schema 1 plan a digest names, or a refusal.
//
// The document is validated before it is hashed because the digest is rebuilt
// from the parsed fields and not from the received bytes. That is not trust: a
// document that fails validation is refused without ever being compared, and a
// document that passes it is still refused unless a human signed exactly it.
func documentMatching(document []byte, signedDigest, role string) (*plan.Document, error) {
	parsed, err := plan.Decode(document)
	if err != nil {
		return nil, fmt.Errorf("carried %s: %w", role, err)
	}
	if err := requireSignedDigest(parsed, signedDigest, role); err != nil {
		return nil, err
	}
	return parsed, nil
}

// v2DocumentMatching returns the schema 2 plan a digest names, or a refusal. It
// is the same procedure as its schema 1 counterpart, over the other transcript.
func v2DocumentMatching(document []byte, signedDigest, role string) (plan.V2Document, error) {
	parsed, err := plan.DecodeV2(document)
	if err != nil {
		return nil, fmt.Errorf("carried %s: %w", role, err)
	}
	if err := requireSignedDigest(parsed, signedDigest, role); err != nil {
		return nil, err
	}
	return parsed, nil
}

// requireSignedDigest holds one validated document against the digest a human
// signed for it, and is the one place either schema does so.
//
// The digest is rebuilt from the parsed fields and never from the received
// bytes, which is why validation comes first: a document that fails it is
// refused without ever being compared, and a document that passes it is still
// refused unless a human signed exactly it.
func requireSignedDigest(parsed interface{ SHA256() (string, error) }, signedDigest, role string) error {
	digest, err := parsed.SHA256()
	if err != nil {
		return fmt.Errorf("carried %s: %w", role, err)
	}
	if digest != signedDigest {
		return fmt.Errorf("the carried %s is not the document the approval signed", role)
	}
	return nil
}

// requireCapableMachine refuses a machine that cannot run the flow, while that
// machine is still untouched.
//
// Quadlet has no fallback and this product does not invent one: without systemd
// or without a unified cgroup hierarchy there is no unit to write, and writing
// one anyway would leave a file describing a service that will never exist.
func requireCapableMachine(capabilities Capabilities, where placement) error {
	if !capabilities.Systemd {
		return errors.New("this machine is not run by systemd: the managed OCI deployment is refused before any write")
	}
	if !capabilities.UnifiedCgroupHierarchy {
		return errors.New("this machine has no cgroup v2 unified hierarchy: the managed OCI deployment is refused before any write")
	}
	if !capabilities.PodmanPresent {
		return errors.New("this machine has no Podman: the managed OCI deployment is refused before any write")
	}
	if capabilities.AccountPresent && !capabilities.RootlessPodman {
		return fmt.Errorf(
			"the account %s cannot run Podman rootless: the managed OCI deployment is refused before any write",
			where.account,
		)
	}
	return nil
}

// concluded turns what one operation left behind into one of this palier's
// conclusions, and there are only three of them.
//
// An operation that succeeded is an application. An operation that failed
// before it had touched anything is a refusal and stays one: there is nothing to
// undo, and a rollback run here would be an action no failure asked for and no
// human expected. Only an operation that failed while this Auxiliary still had
// the machine reaches the rollback.
//
// The flag that separates the two is raised before the first effect rather than
// after it. An effect that returned an error is an effect that may well have
// happened — a useradd interrupted halfway leaves as much behind as one that
// succeeded — so the question is never "did it work" but "was it attempted".
func concluded(
	executor Executor,
	requested, rollback instance,
	application *Application,
	touched bool,
	failure error,
) (*Application, error) {
	if failure == nil {
		return application, nil
	}
	if !touched {
		return nil, failure
	}
	controlled := &ControlledFailure{
		Operation:    requested.operation,
		LocalPort:    requested.localPort,
		UnitPath:     requested.reportedUnitPath(),
		RouteHost:    requested.routeHost,
		FragmentPath: requested.reportedFragmentPath(),
		Outcome:      OutcomeRolledBack,
		Cause:        failure,
	}
	if err := attemptRollback(executor, rollback); err != nil {
		observed := observe(executor, rollback)
		controlled.Outcome = OutcomePartial
		controlled.Rollback = err
		controlled.Observed = &observed
	}
	return nil, controlled
}

// attemptRollback applies exactly the approved rollback document, exactly once.
//
// It is the ordinary path of an ordinary operation because the rollback is an
// ordinary plan: it was displayed, approved, hashed and held against its signed
// digest like the plan it undoes, and it was proven that plan's exact inverse
// before anything ran. Nothing here is improvised from the failure that led to
// it, and nothing here is retried: a second attempt to reach a state this
// machine has just failed to reach is how a partial state becomes an unknown
// one.
func attemptRollback(executor Executor, rollback instance) error {
	// The machine is read again rather than remembered. What the failed
	// operation created before failing — the account above all — is exactly what
	// the rollback now has to act against, and this Auxiliary keeps no record of
	// what it did.
	capabilities, err := executor.Capabilities(rollback.placement.account)
	if err != nil {
		return fmt.Errorf("observe this machine before rolling back: %w", err)
	}
	if err := requireCapableMachine(capabilities, rollback.placement); err != nil {
		return err
	}
	switch rollback.operation {
	case plan.OperationRemoveOCIProbe, plan.OperationRemoveWebService:
		_, _, err := remove(executor, rollback)
		return err
	case plan.OperationDeployOCIProbe, plan.OperationDeployWebService:
		_, _, err := deploy(executor, capabilities, rollback)
		return err
	case plan.OperationRemoveEntrypoint:
		_, _, err := removeEntrypoint(executor, rollback)
		return err
	case plan.OperationDeployEntrypoint:
		_, _, err := deployEntrypoint(executor, capabilities, rollback)
		return err
	case plan.OperationRetireRoute:
		_, _, err := retireRoute(executor, rollback)
		return err
	case plan.OperationPublishRoute:
		_, _, err := publishRoute(executor, rollback)
		return err
	default:
		// Unreachable while the rollback has been proven the exact inverse of an
		// operation this package applies, and kept as a refusal so that a
		// disagreement between the two closed lists undoes nothing rather than
		// something.
		return fmt.Errorf("the approved rollback describes %q, which this Auxiliary does not apply", rollback.operation)
	}
}

// observe establishes what can still be established, and says so in four words.
//
// Every call below is read-only, and every one of them may fail without that
// failure becoming a claim: what could not be read is reported unknown. The
// image reference the engine answers with never leaves this function, because a
// report of this product carries the conclusions of the machine and never the
// output of a command.
func observe(executor Executor, subject instance) Observation {
	where := subject.placement
	observed := Observation{
		Account:   observedUnknown,
		UnitFile:  observedUnknown,
		Service:   observedUnknown,
		Container: observedUnknown,
	}
	if subject.kind == kindRoute {
		// A route is one file, so the one thing worth establishing about it is
		// whether that file is still there. The four words above still answer for
		// the entry the route was served by, because that is what a partial route
		// state is left holding.
		observed.Fragment = observedUnknown
		if _, present, err := executor.ReadUnitFile(subject.reportedFragmentPath()); err == nil {
			observed.Fragment = observedAbsent
			if present {
				observed.Fragment = observedPresent
			}
		}
	}
	if capabilities, err := executor.Capabilities(where.account); err == nil {
		observed.Account = observedAbsent
		if capabilities.AccountPresent {
			observed.Account = observedPresent
		}
	}
	if _, present, err := executor.ReadUnitFile(where.unitPath()); err == nil {
		observed.UnitFile = observedAbsent
		if present {
			observed.UnitFile = observedPresent
		}
	}
	if active, err := executor.ServiceActive(where.account, where.serviceName); err == nil {
		observed.Service = observedInactive
		if active {
			observed.Service = observedActive
		}
	}
	if image, err := executor.ContainerImage(where.account, where.containerName); err == nil {
		switch image {
		case "":
			observed.Container = observedNone
		case where.image:
			observed.Container = observedPinned
		default:
			observed.Container = observedOther
		}
	}
	return observed
}

// deploy brings the machine to the state the plan describes, and says whether
// doing so changed anything.
//
// The decision is taken against what the machine actually holds — the sheet, the
// service and the image the running container was created from — rather than
// against a record this Auxiliary kept, because this Auxiliary keeps no record
// of what it did. A machine whose service drifted is therefore not an error: the
// approved plan is the state that must hold, and reaching it again is a change.
//
// The image the running container was created from is part of that comparison,
// and it is what makes an update an ordinary application rather than a mode of
// its own. A profile re-pinned to a newer digest is a new plan whose digest
// differs; the sheet it renders differs by its Image line and the container that
// is running was created from the previous pin, so the same path that repairs a
// drift is the path that performs the update. Nothing mutates in silence, and
// nothing needs a second procedure.
//
// The second return value says whether this machine was touched at all, which is
// what lets its caller tell a refusal from a controlled failure.
func deploy(executor Executor, capabilities Capabilities, subject instance) (*Application, bool, error) {
	where := subject.placement
	desired := renderSheet(where, subject.localPort)
	path := where.unitPath()

	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}

	if present && bytes.Equal(current, desired) && active && image == where.image {
		// The approved state already holds, down to the bytes of the sheet and
		// the identity of the running image. Nothing is rewritten and nothing is
		// restarted: a plan that demands what is already true is not an action.
		return &Application{
			Operation:    subject.operation,
			LocalPort:    subject.localPort,
			UnitPath:     path,
			ServiceState: ServiceStateActive,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine, so every failure below it
	// is a controlled failure and not a refusal.
	const touched = true

	if !capabilities.AccountPresent {
		if err := executor.CreateProbeAccount(where.account, where.home, where.comment); err != nil {
			return nil, touched, fmt.Errorf("create the service account: %w", err)
		}
		if err := executor.EnableLinger(where.account); err != nil {
			return nil, touched, fmt.Errorf("enable lingering for the service account: %w", err)
		}
		// Whether that fresh account can really run Podman rootless is a fact
		// about subordinate identifier ranges that cannot be observed before the
		// account exists. It is therefore re-read here rather than assumed. The
		// approved rollback follows, and it removes the service rather than the
		// account: the account is not a thing any plan of these paliers
		// describes, so the failure names it and no invented cleanup takes it
		// away.
		refreshed, err := executor.Capabilities(where.account)
		if err != nil {
			return nil, touched, fmt.Errorf("observe the service account after creating it: %w", err)
		}
		if !refreshed.RootlessPodman {
			return nil, touched, fmt.Errorf(
				"the account %s was created but cannot run Podman rootless: this machine now holds that account and no unit",
				where.account,
			)
		}
	}

	if err := executor.PullImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("fetch the pinned image: %w", err)
	}
	if err := executor.WriteUnitFile(path, desired); err != nil {
		return nil, touched, fmt.Errorf("write the Quadlet sheet: %w", err)
	}
	if err := executor.ReloadUserUnits(where.account); err != nil {
		return nil, touched, fmt.Errorf("reload the service account's units: %w", err)
	}
	if active {
		// A running service is stopped before the new sheet is started rather
		// than reloaded into place: the container that is running was created
		// from a description this machine no longer holds.
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the drifted service: %w", err)
		}
	}
	if err := executor.StartService(where.account, where.serviceName); err != nil {
		return nil, touched, fmt.Errorf("start the service: %w", err)
	}
	if err := executor.ProbeAnswers(subject.localPort, where.expectedContentType); err != nil {
		// The announced state is unproven: the service was started and the local
		// request did not obtain the expected answer. A service that runs without
		// answering is exactly the failure this local verification exists to
		// catch, and it is a controlled one — the machine is still this
		// Auxiliary's, so the approved rollback is attempted from here.
		return nil, touched, fmt.Errorf(
			"the service was started but did not answer on %s:%d: this machine held a started service whose announced state was unproven: %w",
			loopbackAddress, subject.localPort, err,
		)
	}
	return &Application{
		Operation:    subject.operation,
		LocalPort:    subject.localPort,
		UnitPath:     path,
		ServiceState: ServiceStateActive,
		Changed:      true,
	}, touched, nil
}

// remove takes the named instance away and leaves nothing of it behind.
//
// A removal names an instance, so an absent service is not a failure and not a
// repair: it is the approved state, already held, and nothing is touched to
// announce it.
//
// The second return value is the same one deploy returns, and it is what makes
// the two operations symmetric under failure: a removal that fails after it has
// begun attempts its own approved rollback, which is the complete redeployment
// of the very instance it was taking away.
func remove(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	path := where.unitPath()
	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}

	if !present && !active && image == "" {
		return &Application{
			Operation:    subject.operation,
			LocalPort:    subject.localPort,
			UnitPath:     path,
			ServiceState: ServiceStateAbsent,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the service: %w", err)
		}
	}
	if present {
		if err := executor.RemoveUnitFile(path); err != nil {
			return nil, touched, fmt.Errorf("remove the Quadlet sheet: %w", err)
		}
		if err := executor.ReloadUserUnits(where.account); err != nil {
			return nil, touched, fmt.Errorf("reload the service account's units: %w", err)
		}
	}
	// No profile of these paliers keeps data, so what is left of a service after
	// its container is gone is the image itself. Removing it is what makes the
	// machine hold nothing of a service that was retired.
	if err := executor.RemoveImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("remove the pinned image: %w", err)
	}
	return &Application{
		Operation:    subject.operation,
		LocalPort:    subject.localPort,
		UnitPath:     path,
		ServiceState: ServiceStateAbsent,
		Changed:      true,
	}, touched, nil
}
