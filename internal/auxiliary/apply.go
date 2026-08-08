package auxiliary

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
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
	// observedUnbacked is the one word this vocabulary gained for the failure of
	// the passage: a fragment this machine still publishes and a junction that is
	// no longer there to carry it.
	//
	// It is a single word rather than two facts a reader has to combine, because it
	// is the state the contract asks to be observable: the name answers the entry's
	// gateway error, nothing falls back, and what is missing is a junction a human
	// approves again. Saying "present" of that fragment would be true and would hide
	// exactly what has to be read.
	observedUnbacked = "unbacked"
)

// Application is what one applied plan leaves behind on the machine.
//
// It says what the machine now holds, not what the plan asked for. Changed is
// computed from what was observed before acting and never announced in advance:
// it is the one field a reader uses to tell an operation that did something from
// an operation that found the approved state already there.
// The fields below the operation name the instance that was applied, and which
// of them are filled is decided by what kind of instance it was: a managed
// service names its loopback port and its sheet, an entrypoint names its sheet
// alone, a route names the declared host and the one fragment file that host
// owns, and a passage names the file that describes its interface. Nothing here
// carries a certificate, a private key or any content of a file.
type Application struct {
	Operation    string
	LocalPort    int
	UnitPath     string
	RouteHost    string
	FragmentPath string
	ServiceState string
	// LinkPublicKey is filled by the preparation of a passage and by nothing
	// else. It is the public half of the key that machine just generated — or of
	// the key it already held, since a preparation never regenerates one — and it
	// is the single value of the private passage that is meant to travel: the
	// Controller reads it here and carries it, readable, into the junction plan
	// of the other machine, so the human who approves that plan names exactly the
	// peer they accept.
	//
	// The private half has no field here and no field anywhere else. It is not
	// omitted from this structure, it is unreachable from it: nothing in this
	// package can obtain it, because the seam that writes it returns the public
	// half alone.
	LinkPublicKey string
	// DataPath is the durable directory of a data-bearing profile, filled by every
	// operation that has one. After a deployment it names where the data lives;
	// after a removal it names what this machine still holds, which is the line
	// that makes "removing keeps the data, redeploying finds it" something a reader
	// is told rather than something they have to know.
	DataPath string
	// SecretsPath is the directory holding the values this machine generated for a
	// service that declares any, and it is filled by the two operations of the
	// third door alone.
	//
	// It names a directory and never a value, here as everywhere else: nothing in
	// this package can obtain one, because the seam that writes them returns none.
	// A removal fills it for the same reason it fills DataPath — what survives a
	// removal is stated rather than assumed, and the values a user's service was
	// given are among the things this product never destroys.
	SecretsPath string
	// SnapshotSlot is the one archive an archive operation acted on, and
	// PreviousSlot is filled by a return alone: it names the reserved slot the
	// return wrote the replaced state into, so the document that undoes this one is
	// readable in the report of the one it undoes.
	SnapshotSlot string
	PreviousSlot string
	// ArchiveSHA256 and ArchivedAt are what the machine concluded about the archive
	// it wrote: the digest of the bytes, and the instant, UTC and RFC 3339. They
	// are the whole of what this product says about an archive — its content is the
	// data of a vault, and nothing in this package can carry a byte of it.
	ArchiveSHA256 string
	ArchivedAt    string
	// SnapshotSlots are the archives this machine holds for the profile once the
	// operation is done, by the names a human gave them. The reserved slot is never
	// among them: it belongs to the return mechanism, not to a human's list.
	SnapshotSlots []string
	// PassageState is filled by the two operations of a route the private passage
	// carries, and by nothing else. It says whether the junction that carries the
	// published name was there when this machine acted.
	//
	// A publication reports it active because it refuses otherwise; a retirement
	// reports what it found, which is how the failure of the passage reaches a human
	// as a fact rather than as a name that stopped answering. It is not a second
	// service state: what the operation itself reached is ServiceState above, and
	// this says what the name it publishes was resting on.
	PassageState string
	Changed      bool
}

// Observation is what read-only calls could still establish about this machine
// after a rollback had itself failed.
//
// It is written in the closed vocabulary above and never in the words of a
// command: a reader learns what was seen, or that it could not be seen at all.
// It is deliberately incapable of saying that the machine is in a known state,
// because a failed rollback is precisely the moment that ceased to be true.
// Which words it carries is decided by the kind of instance that was being
// applied, and every one of them is omitted rather than reported empty where the
// operation never touched what it answers for: an observation says what was
// seen, and a word about something nobody looked at would be neither a fact nor
// an admission. The four words of an account and a container are what a service,
// an entrypoint and a route are left holding; a route adds the one file it is;
// and a passage carries none of the four, because it has neither an account nor
// a container to be left holding.
type Observation struct {
	Account   string `json:"account,omitempty"`
	UnitFile  string `json:"unit_file,omitempty"`
	Service   string `json:"service,omitempty"`
	Container string `json:"container,omitempty"`
	// Fragment is filled only while the instance that was being applied is a
	// route of either kind, because it is the only instance whose state is a
	// fragment file. For a route the passage carries it may also read `unbacked`,
	// which is the fragment being there and the junction not — the one state this
	// palier's contract asks to be observable rather than inferred.
	Fragment string `json:"fragment,omitempty"`
	// LinkKey, LinkInterface, LinkPeer and LinkBounds are filled only for a
	// passage. The key is reported present or absent and never by its value: the
	// public half would say more than an observation needs, and the private half
	// is not something any function of this package can reach. The bounds are
	// reported the same way and for the reason the peer is: after a rollback that
	// failed in its turn, whether this machine is left holding a peer nothing
	// bounds — or bounds with nothing left to bound — is exactly what a human has
	// to read, and neither can be inferred from the other.
	LinkKey       string `json:"link_key,omitempty"`
	LinkInterface string `json:"link_interface,omitempty"`
	LinkPeer      string `json:"link_peer,omitempty"`
	LinkBounds    string `json:"link_bounds,omitempty"`
	// Data, Egress and Archive are filled only for the operations of a
	// data-bearing profile, and they are three words rather than one because
	// neither can be inferred from the others. After a rollback that failed in its
	// turn, whether this machine still holds the data, whether the account is still
	// confined, and whether the archive the operation was writing exists are
	// exactly the three things a human has to read. Each is reported present or
	// absent and never by its content: an archive is named, never opened.
	Data    string `json:"data,omitempty"`
	Egress  string `json:"egress,omitempty"`
	Archive string `json:"archive,omitempty"`
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
	// SnapshotSlot names the archive an archive operation was acting on, because
	// that is what those three operations have instead of a sheet: a failure names
	// an instance as exactly as a success does.
	SnapshotSlot string

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
	// A passage is left holding other things than a service is, so it is named in
	// its own words rather than in four that would all read "unknown" about an
	// account and a container it never had. The key is named present or absent
	// and never by its value, here as everywhere else.
	if failure.Observed.LinkKey != "" {
		return fmt.Sprintf(
			"%s failed after this machine was changed (%v): the approved rollback was attempted and failed in its turn (%v): "+
				"this machine is left in a partial state, observed as description %s, key %s, interface %s, peer %s, bounds %s",
			failure.Operation, failure.Cause, failure.Rollback,
			failure.Observed.UnitFile, failure.Observed.LinkKey,
			failure.Observed.LinkInterface, failure.Observed.LinkPeer,
			failure.Observed.LinkBounds,
		)
	}
	// A confined placement is left holding things a stateless one has none of, and
	// after a rollback that failed they are what a human reads first: is the data
	// still there, is the account still confined, and does the slot the operation
	// was writing hold a file. They are added to the sentence rather than replacing
	// it, because the account, the sheet, the service and the container are still
	// exactly what such a service is left holding besides them. Each of the three
	// appears only where the operation had one — a user service that keeps no data
	// is still confined, and a word about data nobody looked at would be neither a
	// fact nor an admission. The archive is named present or absent, never opened.
	if failure.Observed.Egress != "" {
		return fmt.Sprintf(
			"%s failed after this machine was changed (%v): the approved rollback was attempted and failed in its turn (%v): "+
				"this machine is left in a partial state, observed as account %s, unit file %s, service %s, container %s%s, egress %s%s",
			failure.Operation, failure.Cause, failure.Rollback,
			failure.Observed.Account, failure.Observed.UnitFile,
			failure.Observed.Service, failure.Observed.Container,
			observedDataClause(failure.Observed.Data), failure.Observed.Egress,
			observedArchiveClause(failure.Observed.Archive),
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

// observedDataClause and observedArchiveClause add the data and the archive to a
// sentence only where the operation had one, and add nothing where it did not: a
// word about something nobody looked at would be neither a fact nor an admission.
func observedDataClause(data string) string {
	if data == "" {
		return ""
	}
	return ", data " + data
}

func observedArchiveClause(archive string) string {
	if archive == "" {
		return ""
	}
	return ", archive " + archive
}

// Unwrap keeps the failure that stopped the operation reachable, so a caller
// that wants to know why this machine was being changed at all does not have to
// read a sentence.
func (failure *ControlledFailure) Unwrap() error { return failure.Cause }

// instanceKind is which of the shapes an approved instance has, and it is read
// from the operation rather than guessed from which fields happen to be filled.
// It is what keeps a route from ever being applied through the sheet path, an
// entrypoint from ever being applied through the service one, an archive from
// ever being applied through either, and a passage from ever being applied
// through any of them.
type instanceKind int

const (
	kindWebService instanceKind = iota + 1
	kindEntrypoint
	kindRoute
	kindLink
	// kindLinkRoute is one declared name served by the entry and carried by the
	// private passage. It is a kind of its own beside kindRoute and not a flag on
	// it, because the two answer to different presence rules and write different
	// fragments: what a local route requires of this machine is a managed service
	// publishing the port, and what this one requires is a junction bounding it.
	kindLinkRoute
	// kindPrivateService is a managed service whose data outlives its container,
	// and kindArchive is an operation on the archives of such a service. They are
	// two kinds and not one because they leave different things behind: a service
	// operation answers for a sheet, a container and a confinement, and an archive
	// operation answers for one file in a directory beside them.
	kindPrivateService
	kindArchive
	// kindUserService is a service of the third door: the same machinery as a
	// private service, over a placement derived from a definition its user wrote
	// rather than enumerated by this package. It is a kind of its own and not a
	// flag on the private one because the two answer for different things — this
	// one holds any number of volumes, an interpolated environment and generated
	// values, and its report names all three as things a removal keeps.
	kindUserService
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
//
// A passage carries no placement at all, and the zero value below is the whole
// of the statement: it runs as root, owns no account, no home, no sheet and no
// container, so there is nothing for a placement to hold. What it carries
// instead is its role and the three bounded values a junction plan names.
type instance struct {
	kind        instanceKind
	operation   string
	placement   placement
	localPort   int
	routeHost   string
	backendPort int
	// linkRole is which side of the passage this machine is, resolved from the
	// plan's own field for a preparation and from the operation itself for a
	// junction — the asymmetry of the contract lives in the operations, so the
	// listener's junction needs no field to say it is the listener's.
	linkRole string
	// peerPublicKey and peerEndpointHost name the one peer a junction attaches,
	// and peerEndpointHost is filled for the initiator alone because only the
	// initiator has somewhere to reach.
	peerPublicKey    string
	peerEndpointHost string
	// servicePort is the single port the bounding tables of `#97` will let
	// through the passage. It is carried this far by `#96` so that the issue that
	// poses those tables adds effects to the existing junction flows rather than
	// reshaping them.
	servicePort int
	// originHost is the one origin a private service answers under, and the second
	// and last value of a plan this package ever writes into a file. It is filled
	// for a private service deployment or removal and for nothing else.
	originHost string
	// snapshotSlot is the one archive an archive operation names. It is filled for
	// the three archive operations and for nothing else, and the reserved slot may
	// appear in it only because a Controller wrote it into a signed rollback.
	snapshotSlot string
}

// reportedUnitPath and reportedFragmentPath are how one instance names itself in
// a conclusion, each answering only for the kind that has such a thing.
func (subject instance) reportedUnitPath() string {
	switch subject.kind {
	case kindRoute, kindLinkRoute:
		return ""
	case kindArchive:
		// An archive operation writes no sheet and describes none: what it acts on
		// is one file in the directory beside the service, and the slot names it.
		return ""
	case kindLink:
		// A passage names the file that describes its interface. It is a
		// root-owned file this Auxiliary writes and nobody else rewrites, which is
		// exactly what this field has always meant.
		return linkNetdevPath
	default:
		return subject.placement.unitPath()
	}
}

func (subject instance) reportedFragmentPath() string {
	// The two kinds of route name their file through one function, because they
	// share one namespace: a declared name owns one fragment on this machine,
	// whichever backend serves it.
	if subject.kind != kindRoute && subject.kind != kindLinkRoute {
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
//  2. the schema the two carried documents declare is read, and the three are
//     required to declare the same one: a pair written in two schemas is not a
//     pair, and no decoder is allowed to cover for another. A schema this
//     package does not read is refused here by name, with nothing decoded;
//  3. the two received documents are held against the two digests that
//     approval signed, through the transcript of their own schema, so a
//     Controller that reindented them carries the same plan and a Controller
//     that changed one value carries none;
//  4. the plan targets this machine and this infrastructure, as the machine's
//     own anchor names them and not as the document claims;
//  5. the plan's content stays inside the contract — the plan package refuses a
//     document that leaves it before its digest is even computed — and the
//     operation is one this Auxiliary actually performs. Every operation of the
//     three schemas this package reads is performed here, so what this step
//     refuses is a document whose operation belongs to no shape this package
//     places;
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
	if err := requireDefinitionCarriedByItsOwnDoor(requested, input); err != nil {
		return nil, err
	}

	capabilities, err := executor.Capabilities(requested.placement.account)
	if err != nil {
		return nil, fmt.Errorf("observe this machine's capabilities: %w", err)
	}
	if err := requireCapableMachineFor(requested, capabilities); err != nil {
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
	// The two routes of the passage are their own flows and never the local ones:
	// they write another fragment and they hold another presence rule against this
	// machine, which is exactly why dispatch resolved them to another kind.
	case plan.OperationPublishLinkRoute:
		application, touched, err := publishLinkRoute(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRetireLinkRoute:
		application, touched, err := retireLinkRoute(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationDeployPrivateService:
		application, touched, err := deployPrivateService(executor, capabilities, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRemovePrivateService:
		application, touched, err := removePrivateService(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	// The third door runs its own two flows and never the private profile's: what
	// they place is a placement derived from a definition, and what they leave
	// behind — every volume, every archive and every generated value — is named by
	// a report of their own kind.
	case plan.OperationDeployUserService:
		application, touched, err := deployUserService(executor, capabilities, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRemoveUserService:
		application, touched, err := removeUserService(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationSnapshotService:
		application, touched, err := snapshotService(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationDiscardSnapshot:
		application, touched, err := discardSnapshot(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	// A return is the one operation of this product whose undoing is itself, so it
	// appears once here and once below: the rollback the Controller froze beside it
	// is a return naming the reserved slot, and it runs through this very flow.
	case plan.OperationRestoreService:
		application, touched, err := restoreService(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationPrepareLink:
		application, touched, err := prepareLink(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationWithdrawLink:
		application, touched, err := withdrawLink(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	// The two junctions share one flow and the two departures share the other:
	// what differs between the listener and the initiator is the role's constants
	// and the fields their own plans carry, which dispatch has already resolved.
	case plan.OperationAttachLinkPeer, plan.OperationJoinLinkPeer:
		application, touched, err := joinLinkPeer(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationDetachLinkPeer, plan.OperationLeaveLinkPeer:
		application, touched, err := partLinkPeer(executor, requested)
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
// rule is what keeps the three schemas from covering for one another: a schema 1
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
	// A pair whose two digests are one digest is one document approved as its own
	// undoing, and this Auxiliary refuses it before either document is decoded.
	//
	// No Controller of this product can build such a pair — every builder refuses
	// to freeze two identical documents. That is exactly why the check is here:
	// this package assumes the Controller may have written the envelope itself,
	// and until the private profile's return arrived, no document of any schema
	// was even capable of being its own exact inverse. One now is, so the refusal
	// stops being unreachable and starts being a rule.
	if accepted.Envelope.PlanSHA256 == accepted.Envelope.RollbackSHA256 {
		return instance{}, instance{}, errors.New(
			"the approval names one digest as both the plan and its rollback: a document is not its own undoing")
	}
	switch planSchema {
	case plan.SchemaVersion:
		return probeInstances(accepted, input)
	case plan.SchemaVersionV2:
		return serviceInstances(accepted, input)
	case plan.SchemaVersionV3:
		return linkInstances(accepted, input)
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
// The document shapes of schema 2 become the instance kinds here, and this is the
// only place that mapping exists. Until `#91` landed, the four entrypoint and
// route operations were refused at this exact point by name; the four shapes of
// the private profile were refused here too, until `#102` and `#103`, and the
// third door's own shape until `#119`. Every shape of this schema is placed now,
// and what remains is the one refusal that outlived every window: a document
// shape this package has no placement for is refused before any effect, because
// there is nowhere for it to be placed.
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
	case plan.PrivateServiceDocument:
		undoing, paired := rollback.(plan.PrivateServiceDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		where, err := privatePlacementFor(subject)
		if err != nil {
			return instance{}, instance{}, err
		}
		return instance{
				kind: kindPrivateService, operation: subject.Operation,
				placement: where, localPort: subject.LocalPort,
				originHost: subject.OriginHost,
			},
			instance{
				kind: kindPrivateService, operation: undoing.Operation,
				placement: where, localPort: undoing.LocalPort,
				originHost: undoing.OriginHost,
			},
			nil
	case plan.SnapshotDocument:
		undoing, paired := rollback.(plan.SnapshotDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		where, err := archivedPlacementFor(subject.ServiceProfile)
		if err != nil {
			return instance{}, instance{}, err
		}
		return instance{
				kind: kindArchive, operation: subject.Operation,
				placement: where, snapshotSlot: subject.SnapshotSlot,
			},
			instance{
				kind: kindArchive, operation: undoing.Operation,
				placement: where, snapshotSlot: undoing.SnapshotSlot,
			},
			nil
	case plan.RestoreDocument:
		undoing, paired := rollback.(plan.RestoreDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		where, err := archivedPlacementFor(subject.ServiceProfile)
		if err != nil {
			return instance{}, instance{}, err
		}
		// The two slots differ and the operation does not, which is the one pair of
		// this schema shaped that way. Nothing here treats the rollback's slot as
		// special: it is the value the Controller froze, held against the plan by
		// the exact-inverse check above, and it reaches the same flow as any other.
		return instance{
				kind: kindArchive, operation: subject.Operation,
				placement: where, snapshotSlot: subject.SnapshotSlot,
			},
			instance{
				kind: kindArchive, operation: undoing.Operation,
				placement: where, snapshotSlot: undoing.SnapshotSlot,
			},
			nil
	case plan.LinkRouteDocument:
		undoing, paired := rollback.(plan.LinkRouteDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		// The name is held against what this machine can carry as one file exactly
		// where a local route's is, and for the same reason: the two kinds share one
		// namespace, so they share one bound and one refusal, taken before any effect
		// and before the machine is read at all.
		if err := requireHoldableFragmentName(subject.RouteHost); err != nil {
			return instance{}, instance{}, err
		}
		// The placement is the entry's, as a local route's is: this instance has no
		// account, no sheet and no container either, and what serves it is the entry.
		// What differs is everything below dispatch, which is why it is another kind.
		return instance{
				kind: kindLinkRoute, operation: subject.Operation,
				placement: entrypointPlacement,
				routeHost: subject.RouteHost, backendPort: subject.BackendPort,
			},
			instance{
				kind: kindLinkRoute, operation: undoing.Operation,
				placement: entrypointPlacement,
				routeHost: undoing.RouteHost, backendPort: undoing.BackendPort,
			},
			nil
	case plan.UserServiceDocument:
		undoing, paired := rollback.(plan.UserServiceDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		// The one shape of this product whose plan is not enough to place it. The
		// definition's own bytes arrived beside the signed pair, and everything
		// below is this machine refusing to believe anyone about them: they are
		// decoded, validated and rehashed here, held against the digest the plan
		// pins, and only then read for the placement they decide.
		where, err := userServicePlacementFor(subject, input.DefinitionDocument)
		if err != nil {
			return instance{}, instance{}, err
		}
		// The rollback is already the exact inverse of the plan, which compares the
		// two documents whole — the pinned revision and the slug included — so the
		// undoing places the very same service, from the very same definition, and
		// there is no second derivation for a second document to disagree with.
		return instance{
				kind: kindUserService, operation: subject.Operation,
				placement: where, localPort: subject.LocalPort,
				originHost: subject.OriginHost,
			},
			instance{
				kind: kindUserService, operation: undoing.Operation,
				placement: where, localPort: undoing.LocalPort,
				originHost: undoing.OriginHost,
			},
			nil
	default:
		// Unreachable while the plan package's closed interface holds exactly the
		// shapes above, and kept as a refusal rather than a panic so that a further
		// shape added there without a placement here is refused instead of placed
		// by accident.
		return instance{}, instance{}, fmt.Errorf(
			"the approved plan describes %q, which this Auxiliary has no placement for",
			requested.OperationName(),
		)
	}
}

// linkInstances holds one schema 3 pair against the approval that carries it,
// and turns it into the two instances the passage's effects act on.
//
// It is the very procedure serviceInstances follows — the same digests, the same
// target, the same exact inverse, then one assertion per shape — over the other
// closed interface. What differs is what comes out of it: a passage has no
// placement, because it has no account to run as and no container to be. What it
// has instead is a role, and the role is read from the plan's own field for a
// preparation and from the operation itself for a junction. That is the contract
// read literally: the listener's junction is an operation of its own precisely so
// that no field has to say which side it is for.
//
// Until `#96` landed, all six operations were refused at this exact point by the
// schema dispatch above, by name and before this machine was read at all.
func linkInstances(accepted *approval.Acceptance, input *Input) (instance, instance, error) {
	envelope := accepted.Envelope
	requested, err := v3DocumentMatching(input.PlanDocument, envelope.PlanSHA256, "plan")
	if err != nil {
		return instance{}, instance{}, err
	}
	rollback, err := v3DocumentMatching(input.RollbackDocument, envelope.RollbackSHA256, "rollback")
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

	switch subject := requested.(type) {
	case plan.LinkDocument:
		undoing, paired := rollback.(plan.LinkDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		// The role is held against this Auxiliary's own closed list before any
		// effect, for the reason placementFor exists: a role a plan may name and
		// this machine has no constants for is refused rather than configured.
		if _, err := linkPlacementFor(subject.LinkRole); err != nil {
			return instance{}, instance{}, err
		}
		return instance{
				kind: kindLink, operation: subject.Operation, linkRole: subject.LinkRole,
			},
			instance{
				kind: kindLink, operation: undoing.Operation, linkRole: undoing.LinkRole,
			},
			nil
	case plan.ListenerPeerDocument:
		undoing, paired := rollback.(plan.ListenerPeerDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		// No endpoint is carried, because the listener has none: the field does
		// not exist in the document and is not invented here either.
		return instance{
				kind: kindLink, operation: subject.Operation, linkRole: plan.LinkRoleListener,
				peerPublicKey: subject.PeerPublicKey, servicePort: subject.ServicePort,
			},
			instance{
				kind: kindLink, operation: undoing.Operation, linkRole: plan.LinkRoleListener,
				peerPublicKey: undoing.PeerPublicKey, servicePort: undoing.ServicePort,
			},
			nil
	case plan.InitiatorPeerDocument:
		undoing, paired := rollback.(plan.InitiatorPeerDocument)
		if !paired {
			return instance{}, instance{}, errMismatchedPair
		}
		return instance{
				kind: kindLink, operation: subject.Operation, linkRole: plan.LinkRoleInitiator,
				peerPublicKey: subject.PeerPublicKey, peerEndpointHost: subject.PeerEndpointHost,
				servicePort: subject.ServicePort,
			},
			instance{
				kind: kindLink, operation: undoing.Operation, linkRole: plan.LinkRoleInitiator,
				peerPublicKey: undoing.PeerPublicKey, peerEndpointHost: undoing.PeerEndpointHost,
				servicePort: undoing.ServicePort,
			},
			nil
	default:
		// Unreachable while the plan package's closed interface holds exactly the
		// three shapes above, and kept as a refusal rather than a panic so that a
		// fourth shape added there without constants here is refused instead of
		// applied by accident.
		return instance{}, instance{}, fmt.Errorf(
			"the approved plan describes %q, which this Auxiliary has no constants for",
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

// privatePlacementFor is placementFor over the other door, and it is a second
// function rather than a parameter for the reason the plan package keeps two
// lists: the refusal has to run in both directions, and a lookup that fails is a
// stronger refusal than a comparison somebody has to remember to write.
//
// A stateless profile named at a private operation is refused here — as the plan
// validation already refused it — and a private profile named at a stateless one
// is refused by placementFor, because neither list holds the other's entry.
func privatePlacementFor(document plan.PrivateServiceDocument) (placement, error) {
	where, err := archivedPlacementFor(document.ServiceProfile)
	if err != nil {
		return placement{}, err
	}
	if document.ImageReference+"@"+document.ImageDigest != where.image {
		return placement{}, fmt.Errorf(
			"the approved plan names another image than the %s profile pins", document.ServiceProfile)
	}
	return where, nil
}

// archivedPlacementFor is where one profile of the private door lives on this
// machine, and the refusal a profile with nothing to archive receives.
//
// It is the lookup the three archive operations use, and it carries no image
// comparison because their documents carry no image: an archive names a profile
// and a slot, and what it acts on is the data a deployment left behind. The
// second check is the one the archive operations genuinely need — a profile
// placed here but holding no durable path has nothing to archive, and saying so
// before any effect is better than discovering it at a tar.
//
// The third door shares this field with the delivered profiles, and it is placed
// here by its slug alone. That is not a shortcut: an archive names a service and
// a slot, and everything it acts on — the home, the volumes root under it, the
// archives beside it, the sheet the port is read from — derives from the slug,
// while the definition itself decides only what a *deployment* mounts. So no
// definition travels beside an archive plan, and none is needed: whether that
// home holds volumes to archive is a question this machine answers about itself,
// before any effect.
//
// The reservation of the four names at the source is what makes the lookup
// unambiguous: a well-formed slug is never the name of a delivered profile, and a
// name that is neither keeps the refusal it always had.
func archivedPlacementFor(serviceProfile string) (placement, error) {
	where, known := privateProfilePlacements[serviceProfile]
	if !known {
		if servicedefinition.ValidateSlug(serviceProfile) == nil {
			return userServicePlacementOfSlug(serviceProfile), nil
		}
		return placement{}, fmt.Errorf(
			"plan service_profile %q is not one this Auxiliary places behind the private door", serviceProfile)
	}
	if !where.bearsData() {
		return placement{}, fmt.Errorf(
			"the %s profile keeps no data on this machine: there is nothing for an archive to name", serviceProfile)
	}
	return where, nil
}

// userServicePlacementFor is where one approved user service lives on this
// machine, and the whole of what this Auxiliary revalidates about a definition it
// was handed.
//
// Nothing here is believed. The bytes are decoded and validated against the whole
// contract of a definition, the digest is rebuilt from the parsed fields and held
// against the one the plan pins, and then the plan and the definition are held
// against one another by the very function the Controller used at construction:
// the slug, the repository the image comes from, and the presence of an origin
// exactly where a line consumes one. A definition altered by one byte carries
// another digest and is refused right here, before this machine is read at all,
// while the plan it travelled with stays perfectly valid — which is what makes
// "the Auxiliary re-derives locally" a property of the documents rather than a
// promise of whoever handed the two over together.
//
// A plan of this door arriving without its definition is refused by name too. It
// is not a missing option: a placement of the third door cannot be derived at all
// without the revision, so acting would mean inventing one.
func userServicePlacementFor(document plan.UserServiceDocument, carried []byte) (placement, error) {
	if len(carried) == 0 {
		return placement{}, errors.New(
			"the approved plan pins a service definition and none travelled with it: a user service cannot be placed without the revision it names")
	}
	definition, err := servicedefinition.Verify(carried, document.DefinitionDigest)
	if err != nil {
		return placement{}, fmt.Errorf("carried definition: %w", err)
	}
	if err := plan.RequireDefinitionAgreement(document, definition); err != nil {
		return placement{}, err
	}
	return userServicePlacementOf(definition, document.ImageDigest, document.OriginHost), nil
}

// requireDefinitionCarriedByItsOwnDoor refuses a definition that travelled beside
// a plan pinning none.
//
// The third door's own shape has already consumed the one it needs by the time
// this runs, so what is left to refuse is the other direction: a definition
// arriving beside a probe, a route, a passage or an archive is a document nothing
// in this run reads, and a document nothing reads is a document nobody verified.
// Refusing it is the same rule the contract holds over origin_host — a value
// approved that no line consumes is an intention without a consequence — read over
// the input framing instead of over a field.
func requireDefinitionCarriedByItsOwnDoor(subject instance, input *Input) error {
	if subject.kind == kindUserService || len(input.DefinitionDocument) == 0 {
		return nil
	}
	return fmt.Errorf(
		"a service definition travelled beside %q, which pins none: it is refused before any effect",
		subject.operation)
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

// v3DocumentMatching returns the schema 3 plan a digest names, or a refusal. It
// is the same procedure again, over the transcript of the private passage.
func v3DocumentMatching(document []byte, signedDigest, role string) (plan.V3Document, error) {
	parsed, err := plan.DecodeV3(document)
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

// requireCapableMachineFor asks of this machine exactly what the kind of
// instance being applied needs, and nothing beside it.
//
// The passage is the one instance of this product that owns no account, no
// container and no image: it is a host-level identity held by root, so a
// container engine and a cgroup hierarchy decide nothing about whether this
// machine can hold one. Asking for them anyway would refuse a passage on a
// machine perfectly able to carry it, which is a refusal nothing in the contract
// asks for. What a passage does need is systemd, because the network manager
// that holds the interface across a reboot is one of its units — and that is the
// same reason the managed services need it, read once here for both.
func requireCapableMachineFor(subject instance, capabilities Capabilities) error {
	if subject.kind == kindLink {
		if !capabilities.Systemd {
			return errors.New("this machine is not run by systemd: the private passage is refused before any write")
		}
		return nil
	}
	return requireCapableMachine(capabilities, subject.placement)
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
		SnapshotSlot: requested.snapshotSlot,
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
	if err := requireCapableMachineFor(rollback, capabilities); err != nil {
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
	case plan.OperationRetireLinkRoute:
		_, _, err := retireLinkRoute(executor, rollback)
		return err
	// A publication that runs as a rollback holds the presence rule of a
	// publication, and that is deliberate: a machine whose junction has gone in the
	// meantime cannot be brought back to a name it can serve, so the rollback
	// refuses and the conclusion is a partial state a human reads — never a
	// fragment written over a passage that is not there.
	case plan.OperationPublishLinkRoute:
		_, _, err := publishLinkRoute(executor, rollback)
		return err
	case plan.OperationRemovePrivateService:
		_, _, err := removePrivateService(executor, rollback)
		return err
	case plan.OperationDeployPrivateService:
		_, _, err := deployPrivateService(executor, capabilities, rollback)
		return err
	case plan.OperationRemoveUserService:
		_, _, err := removeUserService(executor, rollback)
		return err
	// A redeployment run as a rollback finds the data and the generated values the
	// failed removal kept, because a removal of this door keeps them: what it puts
	// back is a container, and never a value it would have had to invent.
	case plan.OperationDeployUserService:
		_, _, err := deployUserService(executor, capabilities, rollback)
		return err
	case plan.OperationDiscardSnapshot:
		_, _, err := discardSnapshot(executor, rollback)
		return err
	case plan.OperationSnapshotService:
		_, _, err := snapshotService(executor, rollback)
		return err
	// The return of a return goes through the ordinary flow, exactly as every
	// other rollback does. It names the reserved slot, which the flow has just
	// written the replaced state into, and nothing here is improvised from the
	// failure that led to it.
	case plan.OperationRestoreService:
		_, _, err := restoreService(executor, rollback)
		return err
	case plan.OperationWithdrawLink:
		_, _, err := withdrawLink(executor, rollback)
		return err
	case plan.OperationPrepareLink:
		_, _, err := prepareLink(executor, rollback)
		return err
	case plan.OperationDetachLinkPeer, plan.OperationLeaveLinkPeer:
		_, _, err := partLinkPeer(executor, rollback)
		return err
	case plan.OperationAttachLinkPeer, plan.OperationJoinLinkPeer:
		_, _, err := joinLinkPeer(executor, rollback)
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
	if subject.kind == kindLink {
		// A passage is left holding other things than a service is, so it is
		// observed in its own words. Asking for an account and a container it
		// never had would produce four admissions about things nobody looked at.
		return observeLink(executor)
	}
	where := subject.placement
	observed := Observation{
		Account:   observedUnknown,
		UnitFile:  observedUnknown,
		Service:   observedUnknown,
		Container: observedUnknown,
	}
	if subject.kind == kindRoute || subject.kind == kindLinkRoute {
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
	if subject.kind == kindLinkRoute {
		// A name the passage carries rests on something the four words above cannot
		// say anything about, and after a rollback that failed in its turn it is the
		// thing a human has to read: is the junction still there. The peer is asked
		// separately and reported in its own word, and where the fragment is there
		// without it, the fragment's own word becomes the state rather than a
		// half-truth — this machine publishes a name nothing carries, which is the
		// failure of the passage exactly as the contract describes it. Nothing here
		// repairs it: the reprise is a junction a human approves.
		observed.LinkPeer = observedUnknown
		if content, present, err := executor.ReadUnitFile(linkNetdevPath); err == nil {
			observed.LinkPeer = observedAbsent
			if len(sectionAfter(content, present, linkPeerSectionMarker)) != 0 {
				observed.LinkPeer = observedPresent
			}
		}
		if observed.Fragment == observedPresent && observed.LinkPeer == observedAbsent {
			observed.Fragment = observedUnbacked
		}
	}
	if where.bearsData() || where.confined {
		// A data-bearing placement is left holding three things the four words above
		// cannot say: its data, its confinement, and — for an archive operation —
		// the archive that was being written. Each is asked separately, because a
		// human reading a partial state has to know which of the three survived, and
		// none of them can be inferred from another.
		//
		// The confinement is asked of every confined placement and not only of a
		// data-bearing one, because the third door admits a service that keeps
		// nothing and is confined all the same: whether such a service is left
		// running with nothing refusing what it emits is exactly what a human has to
		// read. The data is asked only where there is data, and a service that keeps
		// none is left saying nothing about it.
		observed.Data = observedUnknown
		if !where.bearsData() {
			observed.Data = ""
		} else if present, err := executor.ServiceDataPresent(where.dataDirectory); err == nil {
			observed.Data = observedAbsent
			if present {
				observed.Data = observedPresent
			}
		}
		observed.Egress = observedUnknown
		if _, present, err := executor.EgressRules(egressRulesPath); err == nil {
			observed.Egress = observedAbsent
			if present {
				observed.Egress = observedPresent
			}
		}
	}
	if subject.kind == kindArchive {
		// The archive is named and never opened: what is established is whether the
		// slot holds a file, and nothing whatsoever about what is in it.
		observed.Archive = observedUnknown
		if present, err := executor.ServiceArchivePresent(where.archivePath(subject.snapshotSlot)); err == nil {
			observed.Archive = observedAbsent
			if present {
				observed.Archive = observedPresent
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
		switch {
		case image == "":
			observed.Container = observedNone
		// A placement that pins no image is one derived from a slug alone — what an
		// archive operation acts on — and it has nothing to compare against. Saying
		// "other" of the container it found would be a claim this operation was
		// never handed the material for, so what is reported is presence: there is a
		// container, and this reading does not know which image it came from.
		case where.image == "":
			observed.Container = observedPresent
		case image == where.image:
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
	// The origin is empty here and it has to be: this flow places the stateless
	// profiles, whose placements declare no environment at all, so the sheet they
	// render carries none whatever is passed. The one profile whose sheet names an
	// origin is placed by its own flow, with the value its own document carries.
	desired := renderSheet(where, subject.localPort, "")
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
	// No profile of the stateless door keeps data, so what is left of such a
	// service after its container is gone is the image itself. Removing it is what
	// makes the machine hold nothing of a service that was retired. The private
	// door's removal is written separately and deliberately keeps one thing.
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
