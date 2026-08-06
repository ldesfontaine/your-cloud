package auxiliary

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestAControlledFailureAttemptsTheApprovedRollbackAndNothingElse is the
// behaviour the palier owes once a mutation has begun.
//
// The probe was started and never answered, which is exactly what the local
// verification exists to catch. The machine is still this Auxiliary's, so the
// second document a human signed is applied — the removal of that same instance,
// through the ordinary removal path — and the effect list is the whole proof:
// the deployment ran once, the rollback ran once, and nothing was tried twice or
// invented in between.
func TestAControlledFailureAttemptsTheApprovedRollbackAndNothingElse(t *testing.T) {
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

	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failure after a mutation was reported as a plain refusal: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack {
		t.Fatalf("the rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationDeployOCIProbe || failure.LocalPort != fixturePort {
		t.Fatalf("the failure does not name the instance it was applying: %+v", failure)
	}
	if failure.Observed != nil {
		t.Fatalf("a rollback that succeeded reported an observation: %+v", failure.Observed)
	}
	// The failure still says what stopped the operation, and the sentence names
	// the three things a reader needs: the failure, the attempt, and its result.
	for _, said := range []string{"unproven", "the approved rollback was attempted"} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the controlled failure does not state %q: %v", said, err)
		}
	}

	expected := []string{
		"PullImage", "WriteUnitFile", "ReloadUserUnits", "StartService",
		"StopService", "RemoveUnitFile", "ReloadUserUnits", "RemoveImage",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("the rollback was not the approved removal and nothing else: %q", executor.effects)
	}
	if len(executor.pulled) != 1 || len(executor.startedServices) != 1 {
		t.Fatalf("the failed deployment was retried: %v %v", executor.pulled, executor.startedServices)
	}
	if executor.holds(UnitPath()) || executor.active || executor.image != "" {
		t.Fatalf("the machine still holds what the rollback undoes: %+v", executor)
	}
}

// TestEveryControlledFailureOfADeploymentReachesTheSameRollback walks the seam
// failures one at a time, from the first effect onwards.
//
// Where the deployment stopped changes nothing about what follows: the approved
// removal is applied, once, against whatever the machine actually holds at that
// point. The rollback is not a sequence of undo steps mirroring the steps that
// ran; it is a plan, and a plan is applied against an observed state.
//
// One case names its own limit. A machine whose systemd will not reload its
// units cannot roll back either, because the removal needs that same reload: the
// rollback fails in its turn and the result is a named partial state rather than
// a rollback that pretends.
func TestEveryControlledFailureOfADeploymentReachesTheSameRollback(t *testing.T) {
	t.Parallel()
	for failing, expected := range map[string]string{
		"PullImage":       OutcomeRolledBack,
		"WriteUnitFile":   OutcomeRolledBack,
		"StartService":    OutcomeRolledBack,
		"ProbeAnswers":    OutcomeRolledBack,
		"ReloadUserUnits": OutcomePartial,
	} {
		executor := newFakeExecutor()
		executor.capabilities.AccountPresent = true
		executor.capabilities.RootlessPodman = true
		executor.failures[failing] = errors.New("the machine refused this effect")
		accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

		_, err := Apply(executor, accepted, input)
		var failure *ControlledFailure
		if !errors.As(err, &failure) {
			t.Fatalf("a failure at %s was not a controlled failure: %v", failing, err)
		}
		if failure.Outcome != expected {
			t.Fatalf("a failure at %s concluded %q: %+v", failing, failure.Outcome, failure)
		}
		if executor.holds(UnitPath()) || executor.active {
			t.Fatalf("a failure at %s left the machine holding the probe: %+v", failing, executor)
		}
		// The failed deployment is never retried: the two effects that belong to
		// it alone happen at most once, and the removal that rolls it back has
		// neither of them.
		if count(executor.effects, "PullImage") > 1 || count(executor.effects, "StartService") > 1 {
			t.Fatalf("the failed deployment was retried at %s: %q", failing, executor.effects)
		}
		if count(executor.effects, "CreateProbeAccount") != 0 {
			t.Fatalf("a failure at %s created an account the plan never described: %q", failing, executor.effects)
		}
	}
}

// TestARollbackThatFailsInItsTurnIsANamedPartialState is the limit of what this
// Auxiliary can promise.
//
// The rollback is attempted once and is not attempted again. What replaces the
// certainty it failed to restore is a list of what read-only calls could still
// establish — and nothing is added to that list to round it off, because a
// partial state that reads as a complete one is worse than one that admits it.
func TestARollbackThatFailsInItsTurnIsANamedPartialState(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	executor.failures["ProbeAnswers"] = errors.New("connection refused")
	executor.failures["RemoveUnitFile"] = errors.New("the sheet could not be removed")
	accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failed rollback was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomePartial {
		t.Fatalf("a failed rollback was announced as a rollback: %+v", failure)
	}
	if failure.Rollback == nil {
		t.Fatal("a partial state named no rollback failure")
	}
	if failure.Observed == nil {
		t.Fatal("a partial state was announced without saying what was observed")
	}
	// The machine was read, not guessed: the sheet the rollback could not remove
	// is still there, and the service it did stop is not running.
	observed := *failure.Observed
	expected := Observation{
		Account:   observedPresent,
		UnitFile:  observedPresent,
		Service:   observedInactive,
		Container: observedNone,
	}
	if observed != expected {
		t.Fatalf("the observation does not match the machine: %+v", observed)
	}
	// The rollback that failed is not attempted a second time.
	if count(executor.effects, "RemoveUnitFile") != 1 {
		t.Fatalf("the failed rollback was retried: %q", executor.effects)
	}
	for _, said := range []string{"partial state", "the approved rollback was attempted and failed"} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the partial state does not state %q: %v", said, err)
		}
	}
}

// TestWhatCannotBeReadAfterAFailedRollbackIsReportedUnknown keeps the
// observation from ever becoming a claim. A machine that cannot answer a
// read-only question has not answered it, and the report says so.
func TestWhatCannotBeReadAfterAFailedRollbackIsReportedUnknown(t *testing.T) {
	t.Parallel()
	executor := deployedMachine(t, fixturePort)
	executor.failures["RemoveImage"] = errors.New("the image could not be removed")
	accepted, input := approvedApplication(t, plan.OperationRemoveOCIProbe, fixturePort)

	// The removal fails; its rollback then cannot even read the machine it was
	// meant to redeploy, and neither can the observation that follows. Each read
	// answers the removal once and refuses everything after it.
	for _, read := range []string{"ReadUnitFile", "ServiceActive", "ContainerImage"} {
		executor.failures[read] = errors.New("this machine could no longer be asked")
		executor.tolerated[read] = 1
	}

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failed rollback was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a machine that could not be read was announced as restored: %+v", failure)
	}
	// The one question the machine still answered is answered, and the three it
	// did not are unknown rather than assumed.
	expected := Observation{
		Account:   observedPresent,
		UnitFile:  observedUnknown,
		Service:   observedUnknown,
		Container: observedUnknown,
	}
	if *failure.Observed != expected {
		t.Fatalf("a machine that answered nothing was reported as known: %+v", failure.Observed)
	}
}

// TestARemovalThatFailsMidwayRedeploysTheInstanceItWasTakingAway is the mirror
// image, and it is a real one: the rollback of a removal is the complete
// redeployment of that exact instance, applied through the ordinary deployment
// path.
//
// The one asymmetry is worth naming rather than hiding: this rollback fetches
// the pinned image, so a removal that fails depends on a registry the removal
// itself never needed. That is a dependency of the approved document and not a
// liberty this Auxiliary takes, and a fetch that fails leaves a partial state
// named like any other.
func TestARemovalThatFailsMidwayRedeploysTheInstanceItWasTakingAway(t *testing.T) {
	t.Parallel()
	executor := deployedMachine(t, fixturePort)
	executor.failures["RemoveImage"] = errors.New("the image could not be removed")
	accepted, input := approvedApplication(t, plan.OperationRemoveOCIProbe, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a removal that failed midway was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack {
		t.Fatalf("the removal's rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationRemoveOCIProbe {
		t.Fatalf("the failure names another operation than the one that ran: %+v", failure)
	}

	expected := []string{
		"StopService", "RemoveUnitFile", "ReloadUserUnits", "RemoveImage",
		"PullImage", "WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("the rollback was not the approved redeployment and nothing else: %q", executor.effects)
	}
	if !executor.holds(UnitPath()) || !executor.active || executor.image != PinnedImage() {
		t.Fatalf("the instance the removal was taking away was not put back: %+v", executor)
	}
	// The redeployment is verified locally like any other, which is what makes
	// the rollback a state that was reached rather than a state that was claimed.
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the restored probe was never verified: %v", executor.probedPorts)
	}
}

// TestAFreshAccountThatCannotRunPodmanRootlessLeavesANamedPartialState holds the
// one capability that cannot be observed before it is created.
//
// The account exists, it cannot run what it was created for, and the approved
// rollback describes the probe rather than the account — so the account stays.
// This Auxiliary does not remove what no human approved removing, and the state
// it leaves is named instead of tidied.
func TestAFreshAccountThatCannotRunPodmanRootlessLeavesANamedPartialState(t *testing.T) {
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
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failure after the account was created was reported as a refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "holds that account and no unit") {
		t.Fatalf("the failure does not name the state it leaves: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a machine that cannot run the rollback was announced as restored: %+v", failure)
	}
	if failure.Observed.Account != observedPresent || failure.Observed.UnitFile != observedAbsent {
		t.Fatalf("the observation does not name the account and the absent unit: %+v", failure.Observed)
	}
	// Nothing was written, nothing was fetched, and nothing removed the account:
	// the two effects that ran are the two the deployment had reached.
	if strings.Join(executor.effects, ",") != "CreateProbeAccount,EnableLinger" {
		t.Fatalf("something beyond the approved documents ran: %q", executor.effects)
	}
}

// count reports how many times one effect was recorded, which is how the checks
// above tell "attempted once" from "retried".
func count(effects []string, name string) int {
	total := 0
	for _, effect := range effects {
		if effect == name {
			total++
		}
	}
	return total
}
