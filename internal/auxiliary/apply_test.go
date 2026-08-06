package auxiliary

import (
	"strings"
	"testing"

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

// TestAFreshApprovalAfterACutAppliesAgainstTheStateItFinds is what a cut leaves
// to the next approval, and it is nothing special.
//
// The machine that comes back after an interrupted mutation holds a state no
// plan describes: a sheet nobody started, an account with no unit, a service
// running from an image the sheet no longer names. None of that is repaired in
// silence and none of it is a failure. A new approval over the same target is
// applied against what is observed, exactly as any drift is, and reaches the
// approved state in one operation.
func TestAFreshApprovalAfterACutAppliesAgainstTheStateItFinds(t *testing.T) {
	t.Parallel()
	for name, interrupted := range map[string]func(*testing.T) *fakeExecutor{
		"a sheet written and a service never started": func(t *testing.T) *fakeExecutor {
			return halfWrittenMachine(t, fixturePort)
		},
		"an account created and no unit at all": func(*testing.T) *fakeExecutor {
			executor := newFakeExecutor()
			executor.capabilities.AccountPresent = true
			executor.capabilities.RootlessPodman = true
			return executor
		},
		"an image fetched and nothing written": func(*testing.T) *fakeExecutor {
			executor := newFakeExecutor()
			executor.capabilities.AccountPresent = true
			executor.capabilities.RootlessPodman = true
			executor.image = PinnedImage()
			return executor
		},
		"a service started from a sheet that was then lost": func(t *testing.T) *fakeExecutor {
			executor := deployedMachine(t, fixturePort)
			executor.unit, executor.unitPresent = nil, false
			return executor
		},
	} {
		executor := interrupted(t)
		accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("a fresh approval over %s was refused: %v", name, err)
		}
		if !application.Changed || application.ServiceState != ServiceStateActive {
			t.Fatalf("a fresh approval over %s announced no change: %+v", name, application)
		}
		if len(executor.writtenUnit) == 0 || !executor.active {
			t.Fatalf("%s was left as it was found: %+v", name, executor)
		}
		// The account is not recreated where a cut already left one, because the
		// decision is taken against the machine and never against a memory of
		// what the interrupted run had reached.
		for _, effect := range executor.effects {
			if effect == "CreateProbeAccount" {
				t.Fatalf("%s had its existing account recreated", name)
			}
		}
	}
}
