package auxiliary

// This file holds for the public entrypoint what service_test.go holds for the
// managed web service: the effect list of one deployment and one removal in the
// one order the contract fixes, idempotence computed against the machine, every
// drift as a change rather than an error, and a failure after the first effect
// that attempts the approved rollback and nothing else.
//
// It adds the two things only an entrypoint has. The host policy is a declared
// effect of the plan, so where it sits in the order is asserted rather than
// assumed — before the entry is started, after it is stopped. And the removal
// refuses while this machine still publishes a route, which is the decision this
// issue owes and the one place a reader should look for it.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestTheEntrypointAndTheOtherServicesShareNothingOnAMachine is the placement
// read as a reviewer reads it: three managed things own three accounts, three
// homes, three sheets and three containers, and a generalisation that let one of
// them move onto another's names would be caught here rather than in the LAB.
func TestTheEntrypointAndTheOtherServicesShareNothingOnAMachine(t *testing.T) {
	t.Parallel()
	for name, shared := range map[string]bool{
		"the probe's account":     probePlacement.account == entrypointPlacement.account,
		"the profile's account":   bentoPDFPlacement.account == entrypointPlacement.account,
		"the probe's home":        probePlacement.home == entrypointPlacement.home,
		"the profile's home":      bentoPDFPlacement.home == entrypointPlacement.home,
		"the probe's sheet":       probePlacement.unitPath() == entrypointPlacement.unitPath(),
		"the profile's sheet":     bentoPDFPlacement.unitPath() == entrypointPlacement.unitPath(),
		"the probe's service":     probePlacement.serviceName == entrypointPlacement.serviceName,
		"the profile's service":   bentoPDFPlacement.serviceName == entrypointPlacement.serviceName,
		"the probe's container":   probePlacement.containerName == entrypointPlacement.containerName,
		"the profile's container": bentoPDFPlacement.containerName == entrypointPlacement.containerName,
		"the probe's image":       probePlacement.image == entrypointPlacement.image,
		"the profile's image":     bentoPDFPlacement.image == entrypointPlacement.image,
	} {
		if shared {
			t.Fatalf("the entrypoint shares %s", name)
		}
	}
	if entrypointPlacement.account != "your-cloud-entrypoint" {
		t.Fatalf("the entrypoint runs as %q", entrypointPlacement.account)
	}
	if entrypointPlacement.home != "/var/lib/your-cloud-entrypoint" {
		t.Fatalf("the entrypoint's home is %q", entrypointPlacement.home)
	}
	if !strings.HasPrefix(entrypointPlacement.unitPath(), entrypointPlacement.home+"/") {
		t.Fatalf("the entrypoint's sheet is outside its own home: %q", entrypointPlacement.unitPath())
	}
	// The three root-owned files and directories are outside that home on
	// purpose: the account that runs the entry reads what it serves and may never
	// write it.
	for _, path := range []string{
		entrypointConfigurationPath, entrypointFragmentDirectory, entrypointCertificateDirectory,
	} {
		if strings.HasPrefix(path, entrypointPlacement.home) {
			t.Fatalf("%q is under the home of the account that reads it", path)
		}
	}
	if entrypointPlacement.image != plan.EntrypointImageReference+"@"+plan.EntrypointImageDigest {
		t.Fatalf("the entrypoint is not pinned to the image of the contract: %q", entrypointPlacement.image)
	}
}

// TestTheFirstEntrypointApplicationDoesEverythingItDeclaresInOneOrder is the
// result this issue owes for the entry, and the order is the whole argument.
func TestTheFirstEntrypointApplicationDoesEverythingItDeclaresInOneOrder(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.afterAccount = &Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
		AccountPresent:         true,
		RootlessPodman:         true,
	}
	accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal entrypoint deployment was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first entrypoint application announced no change: %+v", application)
	}
	if application.UnitPath != entrypointPlacement.unitPath() {
		t.Fatalf("the entrypoint was written where something else lives: %q", application.UnitPath)
	}
	// An entrypoint plan carries no port and no host, so its conclusion names
	// neither: a report that stated one would be stating a value nobody approved.
	if application.LocalPort != 0 || application.RouteHost != "" || application.FragmentPath != "" {
		t.Fatalf("the entrypoint named a value its plan does not carry: %+v", application)
	}

	expected := []string{
		"CreateProbeAccount", "EnableLinger", "PullImage",
		"EnsureEntrypointDirectories", "WriteUnitFile", "WriteHostPortsPolicy",
		"WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	// The two files that were written are the static configuration and then the
	// sheet, in that order: the entry has its configuration before anything
	// describes the container that reads it.
	expectedWrites := []string{entrypointConfigurationPath, entrypointPlacement.unitPath()}
	if strings.Join(executor.writtenPaths, ",") != strings.Join(expectedWrites, ",") {
		t.Fatalf("the entrypoint wrote another set of files: %q", executor.writtenPaths)
	}
	if len(executor.accountsCreated) != 1 || executor.accountsCreated[0] != EntrypointAccount+" "+EntrypointHome {
		t.Fatalf("another account than the entrypoint's was created: %v", executor.accountsCreated)
	}
	if len(executor.lingeringAccounts) != 1 || executor.lingeringAccounts[0] != EntrypointAccount {
		t.Fatalf("the entrypoint account cannot survive without a session: %v", executor.lingeringAccounts)
	}
	if len(executor.pulled) != 1 || executor.pulled[0] != entrypointPlacement.image {
		t.Fatalf("another image than the entrypoint's pin was fetched: %v", executor.pulled)
	}
	// The three files the machine now holds are exactly the ones the contract
	// fixes, byte for byte.
	if string(executor.held(entrypointPlacement.unitPath())) != string(renderEntrypointSheet()) {
		t.Fatal("the machine does not hold the sheet this contract fixes")
	}
	if string(executor.held(entrypointConfigurationPath)) != string(renderEntrypointConfiguration()) {
		t.Fatal("the machine does not hold the configuration this contract fixes")
	}
	if !executor.policyPresent || string(executor.policy) != string(renderHostPortsPolicy()) {
		t.Fatalf("the machine does not hold the host policy the plan declares: %q", executor.policy)
	}
	// The local verification ran exactly once, and it asked nothing of any route:
	// no fragment exists on this machine at all.
	if executor.entrypointChecks != 1 || len(executor.verifiedRoutes) != 0 {
		t.Fatalf("the entrypoint was verified %d times and %d routes were verified with it",
			executor.entrypointChecks, len(executor.verifiedRoutes))
	}
	if fragments, _ := executor.ListRouteFragments(); len(fragments) != 0 {
		t.Fatalf("deploying an entrypoint published a route: %v", fragments)
	}
}

// TestTheHostPolicyIsAppliedBeforeTheEntryStartsAndRemovedAfterItStops is the
// ordering the contract's own sentence implies, asserted in both directions.
//
// A machine that started the entry before it was allowed to bind would fail at
// start rather than slowly, and a machine that forgot the relaxation while the
// entry was still running would be a machine whose running state and whose
// declared state disagree. Both are one comparison of positions in the recorded
// effect list.
func TestTheHostPolicyIsAppliedBeforeTheEntryStartsAndRemovedAfterItStops(t *testing.T) {
	t.Parallel()
	deployed := entrypointMachine()
	accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)
	if _, err := Apply(deployed, accepted, input); err != nil {
		t.Fatalf("the nominal entrypoint deployment was refused: %v", err)
	}
	if position(deployed.effects, "WriteHostPortsPolicy") > position(deployed.effects, "StartService") {
		t.Fatalf("the entry was started before this machine allowed it to listen: %q", deployed.effects)
	}

	removed := deployedEntrypointMachine()
	accepted, input = approvedEntrypoint(t, plan.OperationRemoveEntrypoint)
	if _, err := Apply(removed, accepted, input); err != nil {
		t.Fatalf("the nominal entrypoint removal was refused: %v", err)
	}
	if position(removed.effects, "RemoveHostPortsPolicy") < position(removed.effects, "StopService") {
		t.Fatalf("the relaxation was taken away while the entry was still running: %q", removed.effects)
	}
	expected := []string{
		"StopService", "RemoveHostPortsPolicy", "RemoveUnitFile",
		"ReloadUserUnits", "RemoveUnitFile", "RemoveImage",
	}
	if strings.Join(removed.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected removal effects: %q", removed.effects)
	}
	expectedRemovals := []string{entrypointPlacement.unitPath(), entrypointConfigurationPath}
	if strings.Join(removed.removedPaths, ",") != strings.Join(expectedRemovals, ",") {
		t.Fatalf("the removal took away another set of files: %q", removed.removedPaths)
	}
	if removed.policyPresent {
		t.Fatal("the removed entrypoint left its host relaxation behind")
	}
}

// TestAnEntrypointPlanDemandingTheStateAlreadyHeldChangesNothing is the
// idempotence the palier owes, computed against the machine rather than against
// a memory, and across all three files at once.
func TestAnEntrypointPlanDemandingTheStateAlreadyHeldChangesNothing(t *testing.T) {
	t.Parallel()
	executor := deployedEntrypointMachine()
	accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("an entrypoint plan demanding the state already held was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the same state was announced as a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a plan that changed nothing touched the machine: %q", executor.effects)
	}
	// Nothing was verified either: a state that was already held was not reached
	// by this run, so this run claims nothing about it.
	if executor.entrypointChecks != 0 {
		t.Fatal("a plan that did nothing still claimed to have proven something")
	}
}

// TestADriftedEntrypointIsAChangeAndNotAnError walks every difference the
// machine can hold against the approved plan, the three files and the running
// image's identity included.
//
// The host policy is in this list for the same reason the sheet is: it is part
// of what the plan declares, so a machine that lost it or had it edited is a
// machine the next approved plan repairs, and never a machine that quietly keeps
// listening under a policy nobody approved.
func TestADriftedEntrypointIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"the sheet was edited": func(e *fakeExecutor) {
			e.hold(entrypointPlacement.unitPath(), append(e.held(entrypointPlacement.unitPath()), "\n# edited\n"...))
		},
		"the sheet disappeared": func(e *fakeExecutor) { e.drop(entrypointPlacement.unitPath()) },
		"the configuration was edited": func(e *fakeExecutor) {
			e.hold(entrypointConfigurationPath, append(e.held(entrypointConfigurationPath), "\napi: {}\n"...))
		},
		"the configuration disappeared": func(e *fakeExecutor) { e.drop(entrypointConfigurationPath) },
		"the host policy disappeared":   func(e *fakeExecutor) { e.policy, e.policyPresent = nil, false },
		"the host policy was edited": func(e *fakeExecutor) {
			e.policy = []byte("net.ipv4.ip_unprivileged_port_start=1024\n")
		},
		"the entry was stopped": func(e *fakeExecutor) { e.active = false },
		"the container runs the digest the contract no longer pins": func(e *fakeExecutor) {
			e.image = plan.EntrypointImageReference + "@sha256:" + strings.Repeat("c", 64)
		},
	} {
		executor := deployedEntrypointMachine()
		drift(executor)
		accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused instead of applied: %v", name, err)
		}
		if !application.Changed || application.ServiceState != ServiceStateActive {
			t.Fatalf("%s was not announced as a change: %+v", name, application)
		}
		if string(executor.held(entrypointPlacement.unitPath())) != string(renderEntrypointSheet()) ||
			string(executor.held(entrypointConfigurationPath)) != string(renderEntrypointConfiguration()) ||
			string(executor.policy) != string(renderHostPortsPolicy()) {
			t.Fatalf("%s left the machine describing the drifted state", name)
		}
		if executor.image != entrypointPlacement.image {
			t.Fatalf("%s left the machine running another image than the pin: %q", name, executor.image)
		}
		if count(executor.effects, "CreateProbeAccount") != 0 {
			t.Fatalf("%s recreated an account that already exists", name)
		}

		// And the same plan, presented again against what the repair reached,
		// changes nothing: an update is one application and then idempotence.
		settled := deployedEntrypointMachine()
		accepted, input = approvedEntrypoint(t, plan.OperationDeployEntrypoint)
		application, err = Apply(settled, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused when applied a second time: %v", name, err)
		}
		if application.Changed || len(settled.effects) != 0 {
			t.Fatalf("%s did not settle: %+v %q", name, application, settled.effects)
		}
	}
}

// TestRemovingAnAbsentEntrypointChangesNothing keeps a removal a statement about
// one named thing rather than a sweep of whatever is running.
func TestRemovingAnAbsentEntrypointChangesNothing(t *testing.T) {
	t.Parallel()
	executor := entrypointMachine()
	accepted, input := approvedEntrypoint(t, plan.OperationRemoveEntrypoint)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing an absent entrypoint was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("an absent entrypoint was announced as a removal: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("removing an absent entrypoint touched the machine: %q", executor.effects)
	}
}

// TestRemovingAnEntrypointWhileRoutesRemainIsRefusedAndNamesThem is the decision
// this issue owes, and it is a refusal rather than a removal that leaves the
// fragments inert.
//
// Taking the entry away takes its mounts away, so every fragment left behind
// would stop being served without a single plan saying so. The order of a
// removal — retire the routes, then remove the entry — is a sequencing concern of
// the plans a human approves, so this refuses and names what is in the way
// rather than deciding for the human what happens to it. It is an ordinary
// refusal and never a controlled failure: nothing was touched.
func TestRemovingAnEntrypointWhileRoutesRemainIsRefusedAndNamesThem(t *testing.T) {
	t.Parallel()
	executor := deployedEntrypointMachine()
	executor.hold(routeFragmentPath(fixtureRouteHost), renderRouteFragment(fixtureRouteHost, fixturePort))
	accepted, input := approvedEntrypoint(t, plan.OperationRemoveEntrypoint)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("an entrypoint still publishing a route was removed")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	if !strings.Contains(err.Error(), fixtureRouteHost) {
		t.Fatalf("the refusal does not name the route that is in the way: %v", err)
	}
	if !strings.Contains(err.Error(), "retired by their own approved plans first") {
		t.Fatalf("the refusal does not say what to do about it: %v", err)
	}
	var controlled *ControlledFailure
	if errors.As(err, &controlled) {
		t.Fatalf("the refusal was reported as a controlled failure: %v", err)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("the refusal changed the machine: %q", executor.effects)
	}
	// The machine is left exactly as it was found: the entry is still there, the
	// route is still published, and the relaxation is still declared.
	if !executor.holds(entrypointPlacement.unitPath()) || !executor.active || !executor.policyPresent {
		t.Fatalf("the refused removal took something away: %+v", executor)
	}
	if !executor.holds(routeFragmentPath(fixtureRouteHost)) {
		t.Fatal("the refused removal took the route away")
	}
	// And retiring the route first is what makes the removal possible, which is
	// the whole of the sequencing this refusal asks for.
	retired := deployedEntrypointMachine()
	accepted, input = approvedEntrypoint(t, plan.OperationRemoveEntrypoint)
	if _, err := Apply(retired, accepted, input); err != nil {
		t.Fatalf("removing an entrypoint that publishes nothing was refused: %v", err)
	}
}

// TestAControlledFailureOfTheEntrypointAttemptsTheApprovedRollbackAndNothingElse
// is the conduct of `#85`, inherited whole by the entrypoint.
//
// The entry was started and did not hold the two ports as this contract
// requires, which is exactly what the local verification exists to catch. The
// machine is still this Auxiliary's, so the second document a human signed is
// applied — the removal of that same entry, through the ordinary removal path —
// and the effect list is the whole proof, host policy included.
func TestAControlledFailureOfTheEntrypointAttemptsTheApprovedRollbackAndNothingElse(t *testing.T) {
	t.Parallel()
	executor := entrypointMachine()
	executor.failures["EntrypointAnswers"] = errors.New("connection refused")
	accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("an entrypoint that never answered was reported as applied")
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
	if failure.Operation != plan.OperationDeployEntrypoint || failure.UnitPath != entrypointPlacement.unitPath() {
		t.Fatalf("the failure does not name the entry it was applying: %+v", failure)
	}
	for _, said := range []string{"unproven", "the approved rollback was attempted"} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the controlled failure does not state %q: %v", said, err)
		}
	}

	expected := []string{
		"PullImage", "EnsureEntrypointDirectories", "WriteUnitFile",
		"WriteHostPortsPolicy", "WriteUnitFile", "ReloadUserUnits", "StartService",
		"StopService", "RemoveHostPortsPolicy", "RemoveUnitFile", "ReloadUserUnits",
		"RemoveUnitFile", "RemoveImage",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("the rollback was not the approved removal and nothing else: %q", executor.effects)
	}
	if len(executor.pulled) != 1 || len(executor.startedServices) != 1 {
		t.Fatalf("the failed deployment was retried: %v %v", executor.pulled, executor.startedServices)
	}
	// Nothing of the entry is left, and neither is the relaxation it declared: a
	// machine that rolled back an entrypoint is a machine whose public ports are
	// closed again.
	if executor.holds(entrypointPlacement.unitPath()) || executor.holds(entrypointConfigurationPath) ||
		executor.policyPresent || executor.active || executor.image != "" {
		t.Fatalf("the machine still holds what the rollback undoes: %+v", executor)
	}
}

// TestEveryControlledFailureOfAnEntrypointDeploymentReachesTheSameRollback walks
// the seam failures one at a time, from the first effect onwards, exactly as the
// probe's and the profile's own matrices do.
//
// The one case that names its own limit is the same one as theirs: a machine
// whose systemd will not reload its units cannot roll back either, because the
// removal needs that same reload. The host policy adds a second: a machine that
// cannot take the relaxation away is a machine left in a named partial state
// rather than one whose public ports are quietly declared closed.
func TestEveryControlledFailureOfAnEntrypointDeploymentReachesTheSameRollback(t *testing.T) {
	t.Parallel()
	for failing, expected := range map[string]string{
		"PullImage":                   OutcomeRolledBack,
		"EnsureEntrypointDirectories": OutcomeRolledBack,
		"WriteUnitFile":               OutcomeRolledBack,
		"WriteHostPortsPolicy":        OutcomeRolledBack,
		"StartService":                OutcomeRolledBack,
		"EntrypointAnswers":           OutcomeRolledBack,
		"ReloadUserUnits":             OutcomePartial,
		"RemoveHostPortsPolicy":       OutcomePartial,
	} {
		executor := entrypointMachine()
		if failing == "RemoveHostPortsPolicy" {
			// This one only ever runs during the rollback, so the deployment is
			// made to fail at its own verification first.
			executor.failures["EntrypointAnswers"] = errors.New("connection refused")
		}
		executor.failures[failing] = errors.New("the machine refused this effect")
		accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)

		_, err := Apply(executor, accepted, input)
		var failure *ControlledFailure
		if !errors.As(err, &failure) {
			t.Fatalf("a failure at %s was not a controlled failure: %v", failing, err)
		}
		if failure.Outcome != expected {
			t.Fatalf("a failure at %s concluded %q: %+v", failing, failure.Outcome, failure)
		}
		if executor.active {
			t.Fatalf("a failure at %s left the entry running: %+v", failing, executor)
		}
		if count(executor.effects, "PullImage") > 1 || count(executor.effects, "StartService") > 1 {
			t.Fatalf("the failed deployment was retried at %s: %q", failing, executor.effects)
		}
		if count(executor.effects, "CreateProbeAccount") != 0 {
			t.Fatalf("a failure at %s created an account the plan never described: %q", failing, executor.effects)
		}
	}
}

// TestAnEntrypointRemovalThatFailsMidwayRedeploysTheEntryItWasTakingAway is the
// mirror image, and it carries the same named asymmetry as the service's: the
// rollback of a removal fetches the pinned image, so a removal that fails
// depends on a registry the removal itself never needed. It also puts the host
// relaxation back, because the entry it redeploys needs it.
func TestAnEntrypointRemovalThatFailsMidwayRedeploysTheEntryItWasTakingAway(t *testing.T) {
	t.Parallel()
	executor := deployedEntrypointMachine()
	executor.failures["RemoveImage"] = errors.New("the image could not be removed")
	accepted, input := approvedEntrypoint(t, plan.OperationRemoveEntrypoint)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a removal that failed midway was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack {
		t.Fatalf("the removal's rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationRemoveEntrypoint {
		t.Fatalf("the failure names another operation than the one that ran: %+v", failure)
	}
	expected := []string{
		"StopService", "RemoveHostPortsPolicy", "RemoveUnitFile", "ReloadUserUnits",
		"RemoveUnitFile", "RemoveImage",
		"PullImage", "EnsureEntrypointDirectories", "WriteUnitFile",
		"WriteHostPortsPolicy", "WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("the rollback was not the approved redeployment and nothing else: %q", executor.effects)
	}
	if !executor.holds(entrypointPlacement.unitPath()) || !executor.holds(entrypointConfigurationPath) ||
		!executor.policyPresent || !executor.active || executor.image != entrypointPlacement.image {
		t.Fatalf("the entry the removal was taking away was not put back: %+v", executor)
	}
	if executor.entrypointChecks != 1 {
		t.Fatalf("the restored entry was verified %d times", executor.entrypointChecks)
	}
}

// TestAFailedEntrypointRollbackObservesTheEntryAndNotTheProfile keeps the
// partial state a statement about the thing that was actually being changed.
func TestAFailedEntrypointRollbackObservesTheEntryAndNotTheProfile(t *testing.T) {
	t.Parallel()
	executor := entrypointMachine()
	executor.failures["EntrypointAnswers"] = errors.New("connection refused")
	executor.failures["RemoveUnitFile"] = errors.New("the sheet could not be removed")
	accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)

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
	// An entrypoint is not a route, so nothing about a fragment is claimed.
	if failure.Observed.Fragment != "" {
		t.Fatalf("the observation claimed something about a fragment: %+v", failure.Observed)
	}
	if failure.UnitPath != entrypointPlacement.unitPath() {
		t.Fatalf("the partial state names another sheet than the entry's: %+v", failure)
	}
}

// position is where one effect first appears in what a machine recorded, and it
// is what lets an ordering be asserted rather than described.
func position(effects []string, name string) int {
	for index, effect := range effects {
		if effect == name {
			return index
		}
	}
	return -1
}
