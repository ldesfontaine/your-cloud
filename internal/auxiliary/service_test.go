package auxiliary

// This file holds for the managed web service exactly what apply_test.go and
// rollback_test.go hold for the probe: idempotence computed against the machine,
// drift as a change rather than an error, an update that is nothing but a
// deployment over a drifted digest, and a failure after the first effect that
// attempts the approved rollback and nothing else.
//
// It is a second suite rather than a widened first one because the two subjects
// must be able to fail independently: a regression in the generalisation has to
// name the profile it broke.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestTheProbeAndTheProfileShareNothingOnAMachine is the placement itself, read
// as a reviewer reads it: two managed services own two accounts, two homes, two
// sheets and two containers, and a generalisation that let one of them move onto
// the other's names would be caught here rather than in the LAB.
func TestTheProbeAndTheProfileShareNothingOnAMachine(t *testing.T) {
	t.Parallel()
	for name, shared := range map[string]bool{
		"the account":        probePlacement.account == bentoPDFPlacement.account,
		"the home":           probePlacement.home == bentoPDFPlacement.home,
		"the sheet":          probePlacement.unitPath() == bentoPDFPlacement.unitPath(),
		"the service":        probePlacement.serviceName == bentoPDFPlacement.serviceName,
		"the container":      probePlacement.containerName == bentoPDFPlacement.containerName,
		"the pinned image":   probePlacement.image == bentoPDFPlacement.image,
		"the container port": probePlacement.containerPort == bentoPDFPlacement.containerPort,
	} {
		if shared {
			t.Fatalf("the probe and the bentopdf profile share %s", name)
		}
	}
	// The profile's names are the ones the contract writes, and its sheet lives
	// under its own account's home rather than anywhere a plan could name.
	if bentoPDFPlacement.account != "your-cloud-svc-bentopdf" {
		t.Fatalf("the profile runs as %q", bentoPDFPlacement.account)
	}
	if bentoPDFPlacement.home != "/var/lib/your-cloud-svc-bentopdf" {
		t.Fatalf("the profile's home is %q", bentoPDFPlacement.home)
	}
	if !strings.HasPrefix(bentoPDFPlacement.unitPath(), bentoPDFPlacement.home+"/") {
		t.Fatalf("the profile's sheet is outside its own home: %q", bentoPDFPlacement.unitPath())
	}
	path, known := ServiceUnitPath(plan.ServiceProfileBentoPDF)
	if !known || path != bentoPDFPlacement.unitPath() {
		t.Fatalf("the one profile of this palier names no sheet: %q %t", path, known)
	}
	if _, known := ServiceUnitPath("vaultwarden"); known {
		t.Fatal("a profile this palier does not describe was placed")
	}
}

// TestAServicePlanDemandingTheStateAlreadyHeldChangesNothing is the idempotence
// the palier owes, computed against the machine rather than against a memory.
func TestAServicePlanDemandingTheStateAlreadyHeldChangesNothing(t *testing.T) {
	t.Parallel()
	executor := deployedServiceMachine(t, fixturePort)
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a plan demanding the state already held was refused: %v", err)
	}
	if application.Changed {
		t.Fatalf("the same state was announced as a change: %+v", application)
	}
	if application.ServiceState != ServiceStateActive {
		t.Fatalf("the service that is running was announced absent: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a plan that changed nothing touched the machine: %q", executor.effects)
	}
}

// TestADriftedServiceIsAChangeAndNotAnError walks every difference the machine
// can hold against the approved plan, the running image's identity included.
//
// The last case is what makes an update ordinary: a container created from a
// digest the profile no longer pins is a drift like any other, so a profile
// re-pinned to a newer image applies through this same path, with changed=true
// and then idempotence — never a silent mutation and never a second procedure.
func TestADriftedServiceIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"the sheet was edited": func(e *fakeExecutor) {
			e.hold(bentoPDFPlacement.unitPath(), append(e.held(bentoPDFPlacement.unitPath()), "\n# edited\n"...))
		},
		"the sheet disappeared": func(e *fakeExecutor) { e.drop(bentoPDFPlacement.unitPath()) },
		"the service was stopped": func(e *fakeExecutor) {
			e.active = false
		},
		"the container runs the digest the profile no longer pins": func(e *fakeExecutor) {
			e.image = plan.BentoPDFImageReference + "@sha256:" + strings.Repeat("c", 64)
		},
		"the service was never on this port": func(*fakeExecutor) {},
	} {
		port := fixturePort
		if name == "the service was never on this port" {
			port = fixturePort + 1
		}
		executor := deployedServiceMachine(t, fixturePort)
		drift(executor)
		accepted, input := approvedService(t, plan.OperationDeployWebService, port)

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
		if executor.image != bentoPDFPlacement.image {
			t.Fatalf("%s left the machine running another image than the pin: %q", name, executor.image)
		}
		// The account is already there, so nothing recreates it.
		if count(executor.effects, "CreateProbeAccount") != 0 {
			t.Fatalf("%s recreated an account that already exists", name)
		}

		// And the same plan, presented again against what the repair reached,
		// changes nothing: an update is one application and then idempotence.
		settled := deployedServiceMachine(t, port)
		accepted, input = approvedService(t, plan.OperationDeployWebService, port)
		application, err = Apply(settled, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused when applied a second time: %v", name, err)
		}
		if application.Changed || len(settled.effects) != 0 {
			t.Fatalf("%s did not settle: %+v %q", name, application, settled.effects)
		}
	}
}

// TestRemovingAnAbsentServiceChangesNothing keeps a removal a statement about
// one named instance rather than a sweep of whatever is running.
func TestRemovingAnAbsentServiceChangesNothing(t *testing.T) {
	t.Parallel()
	executor := serviceMachine()
	accepted, input := approvedService(t, plan.OperationRemoveWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing an absent service was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("an absent service was announced as a removal: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("removing an absent service touched the machine: %q", executor.effects)
	}
}

// TestAControlledFailureOfTheServiceAttemptsTheApprovedRollbackAndNothingElse is
// the conduct of `#85`, inherited whole by the generalised machinery.
//
// The service was started and did not answer, which is exactly what the local
// verification exists to catch. The machine is still this Auxiliary's, so the
// second document a human signed is applied — the removal of that same instance,
// through the ordinary removal path — and the effect list is the whole proof.
func TestAControlledFailureOfTheServiceAttemptsTheApprovedRollbackAndNothingElse(t *testing.T) {
	t.Parallel()
	executor := serviceMachine()
	executor.failures["ProbeAnswers"] = errors.New("connection refused")
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a service that never answered was reported as applied")
	}
	if application != nil {
		t.Fatalf("a controlled failure returned an application: %+v", application)
	}
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failure after a mutation was reported as a plain refusal: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack || failure.Observed != nil {
		t.Fatalf("the rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationDeployWebService || failure.LocalPort != fixturePort {
		t.Fatalf("the failure does not name the instance it was applying: %+v", failure)
	}
	if failure.UnitPath != bentoPDFPlacement.unitPath() {
		t.Fatalf("the failure names another sheet than the profile's: %+v", failure)
	}
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
	if executor.holds(bentoPDFPlacement.unitPath()) || executor.active || executor.image != "" {
		t.Fatalf("the machine still holds what the rollback undoes: %+v", executor)
	}
}

// TestEveryControlledFailureOfAServiceDeploymentReachesTheSameRollback walks the
// seam failures one at a time, from the first effect onwards, exactly as the
// probe's own matrix does.
//
// The one case that names its own limit is the same one: a machine whose systemd
// will not reload its units cannot roll back either, because the removal needs
// that same reload, so the result is a named partial state rather than a
// rollback that pretends.
func TestEveryControlledFailureOfAServiceDeploymentReachesTheSameRollback(t *testing.T) {
	t.Parallel()
	for failing, expected := range map[string]string{
		"PullImage":       OutcomeRolledBack,
		"WriteUnitFile":   OutcomeRolledBack,
		"StartService":    OutcomeRolledBack,
		"ProbeAnswers":    OutcomeRolledBack,
		"ReloadUserUnits": OutcomePartial,
	} {
		executor := serviceMachine()
		executor.failures[failing] = errors.New("the machine refused this effect")
		accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

		_, err := Apply(executor, accepted, input)
		var failure *ControlledFailure
		if !errors.As(err, &failure) {
			t.Fatalf("a failure at %s was not a controlled failure: %v", failing, err)
		}
		if failure.Outcome != expected {
			t.Fatalf("a failure at %s concluded %q: %+v", failing, failure.Outcome, failure)
		}
		if executor.holds(bentoPDFPlacement.unitPath()) || executor.active {
			t.Fatalf("a failure at %s left the machine holding the service: %+v", failing, executor)
		}
		if count(executor.effects, "PullImage") > 1 || count(executor.effects, "StartService") > 1 {
			t.Fatalf("the failed deployment was retried at %s: %q", failing, executor.effects)
		}
		if count(executor.effects, "CreateProbeAccount") != 0 {
			t.Fatalf("a failure at %s created an account the plan never described: %q", failing, executor.effects)
		}
	}
}

// TestAServiceRemovalThatFailsMidwayRedeploysTheInstanceItWasTakingAway is the
// mirror image, and it carries the same named asymmetry as the probe's: the
// rollback of a removal fetches the pinned image, so a removal that fails
// depends on a registry the removal itself never needed.
func TestAServiceRemovalThatFailsMidwayRedeploysTheInstanceItWasTakingAway(t *testing.T) {
	t.Parallel()
	executor := deployedServiceMachine(t, fixturePort)
	executor.failures["RemoveImage"] = errors.New("the image could not be removed")
	accepted, input := approvedService(t, plan.OperationRemoveWebService, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a removal that failed midway was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack {
		t.Fatalf("the removal's rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationRemoveWebService {
		t.Fatalf("the failure names another operation than the one that ran: %+v", failure)
	}
	expected := []string{
		"StopService", "RemoveUnitFile", "ReloadUserUnits", "RemoveImage",
		"PullImage", "WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("the rollback was not the approved redeployment and nothing else: %q", executor.effects)
	}
	if !executor.holds(bentoPDFPlacement.unitPath()) || !executor.active || executor.image != bentoPDFPlacement.image {
		t.Fatalf("the instance the removal was taking away was not put back: %+v", executor)
	}
	// The redeployment is verified locally like any other, with the profile's
	// own invariant rather than the probe's.
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the restored service was never verified: %v", executor.probedPorts)
	}
	if len(executor.probedContentTypes) != 1 || executor.probedContentTypes[0] != contentTypeHTMLDocument {
		t.Fatalf("the restored service was verified as another profile: %v", executor.probedContentTypes)
	}
}

// TestAFailedServiceRollbackObservesTheProfileAndNotTheProbe keeps the partial
// state a statement about the machine that was actually being changed.
func TestAFailedServiceRollbackObservesTheProfileAndNotTheProbe(t *testing.T) {
	t.Parallel()
	executor := serviceMachine()
	executor.failures["ProbeAnswers"] = errors.New("connection refused")
	executor.failures["RemoveUnitFile"] = errors.New("the sheet could not be removed")
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failed rollback was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a failed rollback was announced as a rollback: %+v", failure)
	}
	expected := Observation{
		Account:   observedPresent,
		UnitFile:  observedPresent,
		Service:   observedInactive,
		Container: observedNone,
	}
	if *failure.Observed != expected {
		t.Fatalf("the observation does not match the machine: %+v", failure.Observed)
	}
	if count(executor.effects, "RemoveUnitFile") != 1 {
		t.Fatalf("the failed rollback was retried: %q", executor.effects)
	}
	if failure.UnitPath != bentoPDFPlacement.unitPath() {
		t.Fatalf("the partial state names the probe's sheet: %+v", failure)
	}
}

// TestAFreshServiceAccountThatCannotRunPodmanRootlessLeavesANamedPartialState
// holds the one capability that cannot be observed before it is created, for the
// profile's account rather than the probe's.
func TestAFreshServiceAccountThatCannotRunPodmanRootlessLeavesANamedPartialState(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.afterAccount = &Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
		AccountPresent:         true,
		RootlessPodman:         false,
	}
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failure after the account was created was reported as a refusal: %v", err)
	}
	if !strings.Contains(err.Error(), BentoPDFAccount) ||
		!strings.Contains(err.Error(), "holds that account and no unit") {
		t.Fatalf("the failure does not name the account it left behind: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a machine that cannot run the rollback was announced as restored: %+v", failure)
	}
	if failure.Observed.Account != observedPresent || failure.Observed.UnitFile != observedAbsent {
		t.Fatalf("the observation does not name the account and the absent unit: %+v", failure.Observed)
	}
	// The comment the account carries names the service that owns the identity,
	// so an administrator reading the user database is not left guessing.
	if len(executor.accountComments) != 1 || executor.accountComments[0] != bentoPDFPlacement.comment {
		t.Fatalf("the account was created without naming its service: %v", executor.accountComments)
	}
	if strings.Join(executor.effects, ",") != "CreateProbeAccount,EnableLinger" {
		t.Fatalf("something beyond the approved documents ran: %q", executor.effects)
	}
}
