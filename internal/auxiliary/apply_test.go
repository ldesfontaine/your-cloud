package auxiliary

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestTheFirstApplicationWritesTheSheetAndStartsTheProbe is the palier's own
// result: a machine that held nothing now holds exactly what a human approved,
// and says so.
func TestTheFirstApplicationWritesTheSheetAndStartsTheProbe(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.afterAccount = &Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
		AccountPresent:         true,
		RootlessPodman:         true,
	}
	accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal deployment was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first application announced no change: %+v", application)
	}
	if application.UnitPath != UnitPath() || application.LocalPort != fixturePort {
		t.Fatalf("the application named another instance: %+v", application)
	}

	// The order is the argument: the account exists before it is asked to run
	// anything, the image is fetched before a sheet describes it, and the sheet
	// is on disk before systemd is told to read it again.
	expected := []string{
		"CreateProbeAccount", "EnableLinger", "PullImage",
		"WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the announced state was not verified locally: %v", executor.probedPorts)
	}
	if len(executor.pulled) != 1 || executor.pulled[0] != PinnedImage() {
		t.Fatalf("another image than the pinned one was fetched: %v", executor.pulled)
	}
	if len(executor.accountsCreated) != 1 || executor.accountsCreated[0] != ProbeAccount+" "+ProbeHome {
		t.Fatalf("another account than the probe's was created: %v", executor.accountsCreated)
	}
	if len(executor.lingeringAccounts) != 1 || executor.lingeringAccounts[0] != ProbeAccount {
		t.Fatalf("the probe account cannot survive without a session: %v", executor.lingeringAccounts)
	}
}

// TestAPlanDemandingTheStateAlreadyHeldChangesNothing is the idempotence the
// palier owes, computed against the machine rather than against a memory: no
// rewrite, no restart, and no effect of any kind.
func TestAPlanDemandingTheStateAlreadyHeldChangesNothing(t *testing.T) {
	t.Parallel()
	executor := deployedMachine(t, fixturePort)
	accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a plan demanding the state already held was refused: %v", err)
	}
	if application.Changed {
		t.Fatalf("the same state was announced as a change: %+v", application)
	}
	if application.ServiceState != ServiceStateActive {
		t.Fatalf("the probe that is running was announced absent: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a plan that changed nothing touched the machine: %q", executor.effects)
	}
}

// TestADriftedStateIsAChangeAndNotAnError holds the rule that a machine which no
// longer matches its approved plan is brought back by the new approved plan,
// each drift being one difference and nothing else.
func TestADriftedStateIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"the sheet was edited":             func(e *fakeExecutor) { e.unit = append(e.unit, "\n# edited\n"...) },
		"the sheet disappeared":            func(e *fakeExecutor) { e.unit, e.unitPresent = nil, false },
		"the service was stopped":          func(e *fakeExecutor) { e.active = false },
		"another image is running":         func(e *fakeExecutor) { e.image = "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64) },
		"the probe was never on this port": func(e *fakeExecutor) {},
	} {
		port := fixturePort
		if name == "the probe was never on this port" {
			port = fixturePort + 1
		}
		executor := deployedMachine(t, fixturePort)
		drift(executor)
		accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, port)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused instead of applied: %v", name, err)
		}
		if !application.Changed || application.ServiceState != ServiceStateActive {
			t.Fatalf("%s was not announced as a change: %+v", name, application)
		}
		if len(executor.writtenUnit) == 0 {
			t.Fatalf("%s left the machine describing the drifted state", name)
		}
		// The account is already there, so nothing recreates it.
		for _, effect := range executor.effects {
			if effect == "CreateProbeAccount" {
				t.Fatalf("%s recreated an account that already exists", name)
			}
		}
	}
}

// TestRemovingAnAbsentProbeChangesNothing keeps a removal a statement about one
// named instance rather than a sweep of whatever is running.
func TestRemovingAnAbsentProbeChangesNothing(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	accepted, input := approvedApplication(t, plan.OperationRemoveOCIProbe, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing an absent probe was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("an absent probe was announced as a removal: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("removing an absent probe touched the machine: %q", executor.effects)
	}
}

// TestRemovingAPresentProbeLeavesNothingBehind is the other half of the same
// rule: the named instance is stopped, its sheet is gone, and so is its image.
func TestRemovingAPresentProbeLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	executor := deployedMachine(t, fixturePort)
	accepted, input := approvedApplication(t, plan.OperationRemoveOCIProbe, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing a present probe was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the removal announced the wrong state: %+v", application)
	}
	expected := []string{"StopService", "RemoveUnitFile", "ReloadUserUnits", "RemoveImage"}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if executor.unitPresent || executor.active || executor.image != "" {
		t.Fatalf("the machine still holds part of the probe: %+v", executor)
	}
	if len(executor.removedImages) != 1 || executor.removedImages[0] != PinnedImage() {
		t.Fatalf("another image than the pinned one was removed: %v", executor.removedImages)
	}
}

// TestNothingIsTouchedWhileTheApprovedDocumentsAreStillInDoubt walks the
// verification order one refusal at a time.
//
// Each case proves the same thing twice: the operation is refused, and the fake
// machine recorded neither an effect nor a read — a document that is not the one
// a human signed is refused before this package even asks what the machine
// currently holds.
func TestNothingIsTouchedWhileTheApprovedDocumentsAreStillInDoubt(t *testing.T) {
	t.Parallel()
	other := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort+1)

	for name, forge := range map[string]func(*approvedInput){
		"a plan that is not the one the approval signed": func(subject *approvedInput) {
			subject.accepted.Envelope.PlanSHA256 = strings.Repeat("0", 64)
		},
		"a rollback that is not the one the approval signed": func(subject *approvedInput) {
			subject.accepted.Envelope.RollbackSHA256 = strings.Repeat("0", 64)
		},
		"a plan document swapped for another signed plan": func(subject *approvedInput) {
			subject.input.PlanDocument = other.PlanDocument
		},
		"a plan describing another operation than the approval": func(subject *approvedInput) {
			subject.accepted.Envelope.Operation = plan.OperationRemoveOCIProbe
		},
		"a plan aimed at another machine": func(subject *approvedInput) {
			subject.accepted.State.MachineID = "lab-machine-2"
		},
		"a plan aimed at another infrastructure": func(subject *approvedInput) {
			subject.accepted.State.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"
		},
		"a rollback that undoes another instance": func(subject *approvedInput) {
			subject.input.RollbackDocument = other.RollbackDocument
			subject.accepted.Envelope.RollbackSHA256 = other.RollbackSHA256
		},
		"a rollback that is a second deployment rather than an undoing": func(subject *approvedInput) {
			subject.input.RollbackDocument = other.PlanDocument
			subject.accepted.Envelope.RollbackSHA256 = other.PlanSHA256
		},
		"an approval presented without its documents": func(subject *approvedInput) {
			subject.input.Kind = KindDiagnose
		},
		"a plan document that is not a plan at all": func(subject *approvedInput) {
			subject.input.PlanDocument = []byte(`{"schema_version":1}`)
		},
	} {
		executor := deployedMachine(t, fixturePort)
		accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)
		subject := &approvedInput{accepted: accepted, input: input}
		forge(subject)

		if _, err := Apply(executor, subject.accepted, subject.input); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if len(executor.effects) != 0 {
			t.Fatalf("%s changed the machine before being refused: %q", name, executor.effects)
		}
		if len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine before being refused: %q", name, executor.reads)
		}
	}
}

// TestAMachineThatCannotRunTheFlowIsRefusedBeforeAnyWrite is the capability
// preflight. Quadlet has no fallback and this product invents none: what is
// missing is named, and the machine is left exactly as it was found.
func TestAMachineThatCannotRunTheFlowIsRefusedBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	for name, capabilities := range map[string]Capabilities{
		"a machine without systemd": {
			UnifiedCgroupHierarchy: true, PodmanPresent: true,
		},
		"a machine without cgroup v2": {
			Systemd: true, PodmanPresent: true,
		},
		"a machine without podman": {
			Systemd: true, UnifiedCgroupHierarchy: true,
		},
		"an account that cannot run podman rootless": {
			Systemd: true, UnifiedCgroupHierarchy: true, PodmanPresent: true,
			AccountPresent: true, RootlessPodman: false,
		},
	} {
		for _, operation := range []string{plan.OperationDeployOCIProbe, plan.OperationRemoveOCIProbe} {
			executor := newFakeExecutor()
			executor.capabilities = capabilities
			accepted, input := approvedApplication(t, operation, fixturePort)

			if _, err := Apply(executor, accepted, input); err == nil {
				t.Fatalf("%s applied %s", name, operation)
			}
			if len(executor.effects) != 0 {
				t.Fatalf("%s was written to before being refused: %q", name, executor.effects)
			}
			if strings.Join(executor.reads, ",") != "Capabilities" {
				t.Fatalf("%s was read beyond its capabilities: %q", name, executor.reads)
			}
		}
	}
}

// TestAFreshAccountThatCannotRunPodmanRootlessIsNamedRatherThanRepaired holds
// the one capability that cannot be observed before it is created.
//
// The refusal names the state the machine is left in. Repairing that state is
// the rollback behaviour #85 owns; this palier does not act further on its own.
func TestAFreshAccountThatCannotRunPodmanRootlessIsNamedRatherThanRepaired(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.afterAccount = &Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
		AccountPresent:         true,
		RootlessPodman:         false,
	}
	accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

	_, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("an account that cannot run podman rootless was applied on")
	}
	if !strings.Contains(err.Error(), "holds that account and no unit") {
		t.Fatalf("the refusal does not name the state it leaves: %v", err)
	}
	for _, effect := range executor.effects {
		if effect == "WriteUnitFile" || effect == "StartService" || effect == "PullImage" {
			t.Fatalf("the refusal happened after %s", effect)
		}
	}
}

// TestAProbeThatNeverAnswersIsAControlledFailure keeps a started service whose
// announced state is unproven from being reported as a success.
func TestAProbeThatNeverAnswersIsAControlledFailure(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	executor.failures["ProbeAnswers"] = errors.New("connection refused")
	accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a probe that never answered was reported as applied")
	}
	if application != nil {
		t.Fatalf("a controlled failure returned an application: %+v", application)
	}
	if !strings.Contains(err.Error(), "unproven") {
		t.Fatalf("the refusal does not name the state it leaves: %v", err)
	}
}

// approvedInput is one acceptance and one input, forged together in the tests
// above so that each case differs by exactly one thing.
type approvedInput struct {
	accepted *approval.Acceptance
	input    *Input
}
