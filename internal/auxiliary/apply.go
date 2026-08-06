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
// Only then does anything change.
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
		return deploy(executor, capabilities, requested)
	case plan.OperationRemoveOCIProbe:
		return remove(executor, requested)
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

// deploy brings the machine to the state the plan describes, and says whether
// doing so changed anything.
//
// The decision is taken against what the machine actually holds — the sheet, the
// service and the image the running container was created from — rather than
// against a record this Auxiliary kept, because this Auxiliary keeps no record
// of what it did. A machine whose probe drifted is therefore not an error: the
// approved plan is the state that must hold, and reaching it again is a change.
func deploy(executor Executor, capabilities Capabilities, document *plan.Document) (*Application, error) {
	desired := renderUnit(document)
	path := UnitPath()

	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(ProbeAccount, serviceName)
	if err != nil {
		return nil, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(ProbeAccount, containerName)
	if err != nil {
		return nil, fmt.Errorf("read the running image: %w", err)
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
		}, nil
	}

	if !capabilities.AccountPresent {
		if err := executor.CreateProbeAccount(ProbeAccount, ProbeHome); err != nil {
			return nil, fmt.Errorf("create the probe account: %w", err)
		}
		if err := executor.EnableLinger(ProbeAccount); err != nil {
			return nil, fmt.Errorf("enable lingering for the probe account: %w", err)
		}
		// Whether that fresh account can really run Podman rootless is a fact
		// about subordinate identifier ranges that cannot be observed before the
		// account exists. It is therefore re-read here rather than assumed, and
		// a machine that fails it is left with an account and no unit — a state
		// this refusal names, and whose repair belongs to #85.
		refreshed, err := executor.Capabilities(ProbeAccount)
		if err != nil {
			return nil, fmt.Errorf("observe the probe account after creating it: %w", err)
		}
		if !refreshed.RootlessPodman {
			return nil, fmt.Errorf(
				"the account %s was created but cannot run Podman rootless: this machine now holds that account and no unit",
				ProbeAccount,
			)
		}
	}

	if err := executor.PullImage(ProbeAccount, PinnedImage()); err != nil {
		return nil, fmt.Errorf("fetch the pinned probe image: %w", err)
	}
	if err := executor.WriteUnitFile(path, desired); err != nil {
		return nil, fmt.Errorf("write the Quadlet sheet: %w", err)
	}
	if err := executor.ReloadUserUnits(ProbeAccount); err != nil {
		return nil, fmt.Errorf("reload the probe account's units: %w", err)
	}
	if active {
		// A running service is stopped before the new sheet is started rather
		// than reloaded into place: the container that is running was created
		// from a description this machine no longer holds.
		if err := executor.StopService(ProbeAccount, serviceName); err != nil {
			return nil, fmt.Errorf("stop the drifted probe: %w", err)
		}
	}
	if err := executor.StartService(ProbeAccount, serviceName); err != nil {
		return nil, fmt.Errorf("start the probe: %w", err)
	}
	if err := executor.ProbeAnswers(document.LocalPort); err != nil {
		// The announced state is unproven: the service was started and the local
		// request did not obtain the expected answer. This is the controlled
		// failure of the palier, and attempting the approved rollback from here
		// is the behaviour #85 owns; this palier refuses by naming the state it
		// leaves rather than by acting further on its own.
		return nil, fmt.Errorf(
			"the probe was started but did not answer on %s:%d: this machine now holds a started service whose announced state is unproven: %w",
			loopbackAddress, document.LocalPort, err,
		)
	}
	return &Application{
		Operation:    document.Operation,
		LocalPort:    document.LocalPort,
		UnitPath:     path,
		ServiceState: ServiceStateActive,
		Changed:      true,
	}, nil
}

// remove takes the named instance away and leaves nothing of it behind.
//
// A removal names an instance, so an absent probe is not a failure and not a
// repair: it is the approved state, already held, and nothing is touched to
// announce it.
func remove(executor Executor, document *plan.Document) (*Application, error) {
	path := UnitPath()
	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(ProbeAccount, serviceName)
	if err != nil {
		return nil, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(ProbeAccount, containerName)
	if err != nil {
		return nil, fmt.Errorf("read the running image: %w", err)
	}

	if !present && !active && image == "" {
		return &Application{
			Operation:    document.Operation,
			LocalPort:    document.LocalPort,
			UnitPath:     path,
			ServiceState: ServiceStateAbsent,
			Changed:      false,
		}, nil
	}

	if active {
		if err := executor.StopService(ProbeAccount, serviceName); err != nil {
			return nil, fmt.Errorf("stop the probe: %w", err)
		}
	}
	if present {
		if err := executor.RemoveUnitFile(path); err != nil {
			return nil, fmt.Errorf("remove the Quadlet sheet: %w", err)
		}
		if err := executor.ReloadUserUnits(ProbeAccount); err != nil {
			return nil, fmt.Errorf("reload the probe account's units: %w", err)
		}
	}
	// The probe keeps no data, so what is left of it after the container is
	// gone is the image itself. Removing it is what makes the machine hold
	// nothing of a probe that was retired.
	if err := executor.RemoveImage(ProbeAccount, PinnedImage()); err != nil {
		return nil, fmt.Errorf("remove the pinned probe image: %w", err)
	}
	return &Application{
		Operation:    document.Operation,
		LocalPort:    document.LocalPort,
		UnitPath:     path,
		ServiceState: ServiceStateAbsent,
		Changed:      true,
	}, nil
}
