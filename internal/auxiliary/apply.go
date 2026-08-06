package auxiliary

import (
	"bytes"
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
type Application struct {
	Operation    string
	LocalPort    int
	UnitPath     string
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
	// Operation, LocalPort and UnitPath name the instance that was being
	// applied, so that a failure names an instance as exactly as a success does.
	Operation string
	LocalPort int
	UnitPath  string

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

// Apply performs one approved mutating operation, in the one order the contract
// fixes and with no partial effect before it is complete.
//
// The order is the whole security argument, so it is written once, here:
//
//  1. the approval itself is already accepted by the caller — signature against
//     the root-owned anchor, target, epoch, expiry, exact privileges, and the
//     sequence durably consumed. A run interrupted after that point has spent
//     its sequence and will never be replayed;
//  2. the two received documents are held against the two digests that
//     approval signed, through the transcript, so a Controller that reindented
//     them carries the same plan and a Controller that changed one value carries
//     none;
//  3. the plan targets this machine and this infrastructure, as the machine's
//     own anchor names them and not as the document claims;
//  4. the plan's content stays inside the contract — the plan package refuses a
//     document that leaves it before its digest is even computed;
//  5. the machine is capable of the flow at all, and a machine that is not is
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
	envelope := accepted.Envelope

	requested, err := documentMatching(input.PlanDocument, envelope.PlanSHA256, "plan")
	if err != nil {
		return nil, err
	}
	rollback, err := documentMatching(input.RollbackDocument, envelope.RollbackSHA256, "rollback")
	if err != nil {
		return nil, err
	}

	// The anchor decides which machine this is. Comparing against the accepted
	// state rather than against the envelope is what keeps a plan from being
	// aimed at another installation by a Controller that also wrote the envelope
	// it travels with.
	if requested.InfrastructureID != accepted.State.InfrastructureID {
		return nil, errors.New("the approved plan targets another infrastructure than this machine's anchor")
	}
	if requested.MachineID != accepted.State.MachineID {
		return nil, errors.New("the approved plan targets another machine than this one")
	}
	if requested.Operation != envelope.Operation {
		return nil, fmt.Errorf(
			"the approved plan describes %q while the approval names %q",
			requested.Operation, envelope.Operation,
		)
	}
	if !rollback.IsExactInverseOf(requested) {
		return nil, errors.New("the approved rollback does not undo exactly the approved plan")
	}

	capabilities, err := executor.Capabilities(ProbeAccount)
	if err != nil {
		return nil, fmt.Errorf("observe this machine's capabilities: %w", err)
	}
	if err := requireCapableMachine(capabilities); err != nil {
		return nil, err
	}

	switch requested.Operation {
	case plan.OperationDeployOCIProbe:
		application, touched, err := deploy(executor, capabilities, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	case plan.OperationRemoveOCIProbe:
		application, touched, err := remove(executor, requested)
		return concluded(executor, requested, rollback, application, touched, err)
	default:
		// Unreachable while the plan validation and the approval subject agree
		// on the same closed list, and kept as a refusal rather than a panic so
		// that a disagreement between them is a refusal to act.
		return nil, fmt.Errorf("operation %q is not one this Auxiliary applies", requested.Operation)
	}
}

// documentMatching returns the plan a digest names, or a refusal.
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
	digest, err := parsed.SHA256()
	if err != nil {
		return nil, fmt.Errorf("carried %s: %w", role, err)
	}
	if digest != signedDigest {
		return nil, fmt.Errorf("the carried %s is not the document the approval signed", role)
	}
	return parsed, nil
}

// requireCapableMachine refuses a machine that cannot run the flow, while that
// machine is still untouched.
//
// Quadlet has no fallback and this product does not invent one: without systemd
// or without a unified cgroup hierarchy there is no unit to write, and writing
// one anyway would leave a file describing a service that will never exist.
func requireCapableMachine(capabilities Capabilities) error {
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
			ProbeAccount,
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
	requested, rollback *plan.Document,
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
		Operation: requested.Operation,
		LocalPort: requested.LocalPort,
		UnitPath:  UnitPath(),
		Outcome:   OutcomeRolledBack,
		Cause:     failure,
	}
	if err := attemptRollback(executor, rollback); err != nil {
		observed := observe(executor)
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
func attemptRollback(executor Executor, rollback *plan.Document) error {
	// The machine is read again rather than remembered. What the failed
	// operation created before failing — the account above all — is exactly what
	// the rollback now has to act against, and this Auxiliary keeps no record of
	// what it did.
	capabilities, err := executor.Capabilities(ProbeAccount)
	if err != nil {
		return fmt.Errorf("observe this machine before rolling back: %w", err)
	}
	if err := requireCapableMachine(capabilities); err != nil {
		return err
	}
	switch rollback.Operation {
	case plan.OperationRemoveOCIProbe:
		_, _, err := remove(executor, rollback)
		return err
	case plan.OperationDeployOCIProbe:
		_, _, err := deploy(executor, capabilities, rollback)
		return err
	default:
		// Unreachable while the rollback has been proven the exact inverse of an
		// operation this package applies, and kept as a refusal so that a
		// disagreement between the two closed lists undoes nothing rather than
		// something.
		return fmt.Errorf("the approved rollback describes %q, which this Auxiliary does not apply", rollback.Operation)
	}
}

// observe establishes what can still be established, and says so in four words.
//
// Every call below is read-only, and every one of them may fail without that
// failure becoming a claim: what could not be read is reported unknown. The
// image reference the engine answers with never leaves this function, because a
// report of this product carries the conclusions of the machine and never the
// output of a command.
func observe(executor Executor) Observation {
	observed := Observation{
		Account:   observedUnknown,
		UnitFile:  observedUnknown,
		Service:   observedUnknown,
		Container: observedUnknown,
	}
	if capabilities, err := executor.Capabilities(ProbeAccount); err == nil {
		observed.Account = observedAbsent
		if capabilities.AccountPresent {
			observed.Account = observedPresent
		}
	}
	if _, present, err := executor.ReadUnitFile(UnitPath()); err == nil {
		observed.UnitFile = observedAbsent
		if present {
			observed.UnitFile = observedPresent
		}
	}
	if active, err := executor.ServiceActive(ProbeAccount, serviceName); err == nil {
		observed.Service = observedInactive
		if active {
			observed.Service = observedActive
		}
	}
	if image, err := executor.ContainerImage(ProbeAccount, containerName); err == nil {
		switch image {
		case "":
			observed.Container = observedNone
		case PinnedImage():
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
// of what it did. A machine whose probe drifted is therefore not an error: the
// approved plan is the state that must hold, and reaching it again is a change.
//
// The second return value says whether this machine was touched at all, which is
// what lets its caller tell a refusal from a controlled failure.
func deploy(executor Executor, capabilities Capabilities, document *plan.Document) (*Application, bool, error) {
	desired := renderUnit(document)
	path := UnitPath()

	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(ProbeAccount, serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(ProbeAccount, containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}

	if present && bytes.Equal(current, desired) && active && image == PinnedImage() {
		// The approved state already holds, down to the bytes of the sheet and
		// the identity of the running image. Nothing is rewritten and nothing is
		// restarted: a plan that demands what is already true is not an action.
		return &Application{
			Operation:    document.Operation,
			LocalPort:    document.LocalPort,
			UnitPath:     path,
			ServiceState: ServiceStateActive,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine, so every failure below it
	// is a controlled failure and not a refusal.
	const touched = true

	if !capabilities.AccountPresent {
		if err := executor.CreateProbeAccount(ProbeAccount, ProbeHome); err != nil {
			return nil, touched, fmt.Errorf("create the probe account: %w", err)
		}
		if err := executor.EnableLinger(ProbeAccount); err != nil {
			return nil, touched, fmt.Errorf("enable lingering for the probe account: %w", err)
		}
		// Whether that fresh account can really run Podman rootless is a fact
		// about subordinate identifier ranges that cannot be observed before the
		// account exists. It is therefore re-read here rather than assumed. The
		// approved rollback follows, and it removes the probe rather than the
		// account: the account is not a thing any plan of this palier describes,
		// so the failure names it and no invented cleanup takes it away.
		refreshed, err := executor.Capabilities(ProbeAccount)
		if err != nil {
			return nil, touched, fmt.Errorf("observe the probe account after creating it: %w", err)
		}
		if !refreshed.RootlessPodman {
			return nil, touched, fmt.Errorf(
				"the account %s was created but cannot run Podman rootless: this machine now holds that account and no unit",
				ProbeAccount,
			)
		}
	}

	if err := executor.PullImage(ProbeAccount, PinnedImage()); err != nil {
		return nil, touched, fmt.Errorf("fetch the pinned probe image: %w", err)
	}
	if err := executor.WriteUnitFile(path, desired); err != nil {
		return nil, touched, fmt.Errorf("write the Quadlet sheet: %w", err)
	}
	if err := executor.ReloadUserUnits(ProbeAccount); err != nil {
		return nil, touched, fmt.Errorf("reload the probe account's units: %w", err)
	}
	if active {
		// A running service is stopped before the new sheet is started rather
		// than reloaded into place: the container that is running was created
		// from a description this machine no longer holds.
		if err := executor.StopService(ProbeAccount, serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the drifted probe: %w", err)
		}
	}
	if err := executor.StartService(ProbeAccount, serviceName); err != nil {
		return nil, touched, fmt.Errorf("start the probe: %w", err)
	}
	if err := executor.ProbeAnswers(document.LocalPort); err != nil {
		// The announced state is unproven: the service was started and the local
		// request did not obtain the expected answer. A service that runs without
		// answering is exactly the failure this local verification exists to
		// catch, and it is a controlled one — the machine is still this
		// Auxiliary's, so the approved rollback is attempted from here.
		return nil, touched, fmt.Errorf(
			"the probe was started but did not answer on %s:%d: this machine held a started service whose announced state was unproven: %w",
			loopbackAddress, document.LocalPort, err,
		)
	}
	return &Application{
		Operation:    document.Operation,
		LocalPort:    document.LocalPort,
		UnitPath:     path,
		ServiceState: ServiceStateActive,
		Changed:      true,
	}, touched, nil
}

// remove takes the named instance away and leaves nothing of it behind.
//
// A removal names an instance, so an absent probe is not a failure and not a
// repair: it is the approved state, already held, and nothing is touched to
// announce it.
//
// The second return value is the same one deploy returns, and it is what makes
// the two operations symmetric under failure: a removal that fails after it has
// begun attempts its own approved rollback, which is the complete redeployment
// of the very instance it was taking away.
func remove(executor Executor, document *plan.Document) (*Application, bool, error) {
	path := UnitPath()
	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(ProbeAccount, serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(ProbeAccount, containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}

	if !present && !active && image == "" {
		return &Application{
			Operation:    document.Operation,
			LocalPort:    document.LocalPort,
			UnitPath:     path,
			ServiceState: ServiceStateAbsent,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(ProbeAccount, serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the probe: %w", err)
		}
	}
	if present {
		if err := executor.RemoveUnitFile(path); err != nil {
			return nil, touched, fmt.Errorf("remove the Quadlet sheet: %w", err)
		}
		if err := executor.ReloadUserUnits(ProbeAccount); err != nil {
			return nil, touched, fmt.Errorf("reload the probe account's units: %w", err)
		}
	}
	// The probe keeps no data, so what is left of it after the container is
	// gone is the image itself. Removing it is what makes the machine hold
	// nothing of a probe that was retired.
	if err := executor.RemoveImage(ProbeAccount, PinnedImage()); err != nil {
		return nil, touched, fmt.Errorf("remove the pinned probe image: %w", err)
	}
	return &Application{
		Operation:    document.Operation,
		LocalPort:    document.LocalPort,
		UnitPath:     path,
		ServiceState: ServiceStateAbsent,
		Changed:      true,
	}, touched, nil
}
