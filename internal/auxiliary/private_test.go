package auxiliary

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file holds the deployment and the removal of a service whose data
// outlives its container: the order of what they do, what they decide not to do,
// and the one thing a removal of this product deliberately keeps.

// TestTheFirstPrivateDeploymentPlacesTheServiceAndItsConfinement is the palier's
// own claim, read as a report will have to explain it: one account's service,
// one durable directory, one sheet carrying the origin, and one table refusing
// everything that account emits — in the one order the flow fixes.
func TestTheFirstPrivateDeploymentPlacesTheServiceAndItsConfinement(t *testing.T) {
	t.Parallel()
	executor := privateMachine()
	accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the first private deployment was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first deployment announced nothing: %+v", application)
	}
	if application.UnitPath != vaultwardenPlacement.unitPath() ||
		application.DataPath != VaultwardenDataDirectory {
		t.Fatalf("the deployment named another instance: %+v", application)
	}

	// The order is the security argument of this operation, so it is asserted as
	// an order rather than as a set. The fetch runs as the service's own account,
	// so it stands between a machine with no confinement and a machine with one —
	// never inside a table that refuses exactly what fetching needs.
	if strings.Join(executor.effects, ",") != strings.Join([]string{
		"EnsureServiceData",
		"PullImage",
		"WriteEgressRules",
		"WriteUnitFile",
		"EnableEgressRulesAtBoot",
		"WriteUnitFile",
		"ReloadUserUnits",
		"StartService",
	}, ",") {
		t.Fatalf("the deployment did not follow the order of the flow: %q", executor.effects)
	}

	if string(executor.held(vaultwardenPlacement.unitPath())) !=
		string(renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost)) {
		t.Fatalf("the sheet on the machine is not the one the plan describes:\n%s",
			executor.held(vaultwardenPlacement.unitPath()))
	}
	if !executor.dataPresent || executor.dataEnsured != 1 {
		t.Fatalf("the durable directory was not created exactly once: %t %d",
			executor.dataPresent, executor.dataEnsured)
	}
	// The table in this fake machine's kernel is the one the account identifier it
	// holds renders, and it was applied rather than only written.
	if string(executor.nftTables[egressTableFamily+" "+egressTableName]) !=
		string(renderEgressRules(vaultwardenPlacement, executor.accountIdentifier)) {
		t.Fatalf("the confinement in the kernel is not the one this machine renders:\n%s",
			executor.nftTables[egressTableFamily+" "+egressTableName])
	}
	if !executor.egressAtBoot {
		t.Fatal("the confinement would not be posed again after a reboot")
	}
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the announced state was not proven on the approved port: %v", executor.probedPorts)
	}
}

// TestAPrivateDeploymentDemandingTheStateAlreadyHeldChangesNothing is the
// idempotence of a flow that now reads five things instead of three.
//
// The data directory being there is one of the five, and it must not flap the
// answer: a machine holding exactly the approved state reports no change however
// many facts had to be read to establish it.
func TestAPrivateDeploymentDemandingTheStateAlreadyHeldChangesNothing(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a plan demanding the state already held was refused: %v", err)
	}
	if application.Changed {
		t.Fatalf("a plan demanding the state already held reported a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a plan demanding the state already held touched the machine: %q", executor.effects)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("a plan that changed nothing changed the data: %q", executor.dataContent)
	}
}

// TestADriftedPrivateServiceIsAChangeAndNotAnError walks every difference the
// machine can hold and requires the same conclusion of each: the approved plan is
// the state that must hold, and reaching it again is a change rather than a
// failure.
//
// The vanished data directory is the case this palier had to decide, and the
// decision is written into the expectations below: a deployed service whose data
// has gone is a drift reapplied as a change — the directory is created again,
// empty — and never a continuity this Auxiliary pretends to. It has no way to
// know what was in that directory, so a run that recreated it while announcing
// "nothing changed" would be a machine claiming data it does not have.
func TestADriftedPrivateServiceIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"a sheet somebody edited": func(executor *fakeExecutor) {
			executor.hold(vaultwardenPlacement.unitPath(),
				[]byte(strings.Replace(
					string(renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost)),
					"Environment=SIGNUPS_ALLOWED=false", "Environment=SIGNUPS_ALLOWED=true", 1)))
		},
		"a sheet naming another origin": func(executor *fakeExecutor) {
			executor.hold(vaultwardenPlacement.unitPath(),
				renderSheet(vaultwardenPlacement, fixturePort, "vault.somewhere-else.test"))
		},
		"a sheet that is gone": func(executor *fakeExecutor) {
			executor.drop(vaultwardenPlacement.unitPath())
		},
		"a service that stopped": func(executor *fakeExecutor) {
			executor.active = false
		},
		"a container created from another image": func(executor *fakeExecutor) {
			executor.image = "docker.io/library/nothing@sha256:" + strings.Repeat("c", 64)
		},
		"a confinement somebody flushed": func(executor *fakeExecutor) {
			executor.egressRulesPresent = false
			executor.egressRules = nil
			delete(executor.nftTables, egressTableFamily+" "+egressTableName)
		},
		"a confinement whose unit is gone": func(executor *fakeExecutor) {
			executor.drop(egressRulesUnitPath)
		},
		"a confinement rendered for another account": func(executor *fakeExecutor) {
			executor.egressRules = renderEgressRules(vaultwardenPlacement, executor.accountIdentifier+1)
			executor.nftTables[egressTableFamily+" "+egressTableName] = executor.egressRules
		},
		"a durable directory that vanished": func(executor *fakeExecutor) {
			executor.dataPresent = false
			executor.dataContent = ""
		},
	} {
		executor := deployedPrivateMachine(fixturePort)
		drift(executor)
		accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was reported as a failure: %v", name, err)
		}
		if !application.Changed {
			t.Fatalf("%s was not reported as a change: %+v", name, application)
		}
		if string(executor.held(vaultwardenPlacement.unitPath())) !=
			string(renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost)) {
			t.Fatalf("%s left the sheet drifted", name)
		}
		if string(executor.egressRules) !=
			string(renderEgressRules(vaultwardenPlacement, executor.accountIdentifier)) {
			t.Fatalf("%s left the confinement drifted:\n%s", name, executor.egressRules)
		}
		if !executor.dataPresent {
			t.Fatalf("%s left the durable directory absent", name)
		}
	}
}

// TestAVanishedDataDirectoryIsReappliedAsAnEmptyOneAndSaidSo is the honest half
// of the decision above, stated on its own because it is the one a reader is
// entitled to see argued.
//
// A deployed service whose data has gone comes back with an empty directory and a
// report saying the machine changed. Nothing here claims the previous data is
// back, and nothing here goes looking for an archive to fill it with: returning
// to a named archive is a `restore_service` a human approves, and inventing one
// would be this Auxiliary choosing a state nobody signed.
func TestAVanishedDataDirectoryIsReappliedAsAnEmptyOneAndSaidSo(t *testing.T) {
	t.Parallel()
	executor := archivedPrivateMachine(fixturePort)
	executor.dataPresent = false
	executor.dataContent = ""
	accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a service whose data had vanished was refused: %v", err)
	}
	if !application.Changed {
		t.Fatalf("a service whose data had vanished reported no change: %+v", application)
	}
	if !executor.dataPresent || executor.dataContent != "" {
		t.Fatalf("the data was invented rather than recreated empty: %q", executor.dataContent)
	}
	if executor.dataRestores != 0 {
		t.Fatal("the deployment restored an archive nobody approved")
	}
	if executor.archives[vaultwardenPlacement.archivePath(fixtureSnapshotSlot)] != fixtureRestoredSecrets {
		t.Fatal("the deployment touched an archive")
	}
}

// TestAnUpdateLiftsTheConfinementFetchesAndPosesItAgain is the three visible
// effects of the contract, read in their order and counted.
//
// The fetch runs as the service's own account and the table refuses exactly what
// fetching needs, so an update has to lift the confinement, fetch, and pose it
// again. What the contract refuses — and what this case exists to catch — is the
// other way of making that work: an exception written into the table so the fetch
// passes through it, which would be a confinement that quietly stopped being one.
func TestAnUpdateLiftsTheConfinementFetchesAndPosesItAgain(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	executor.image = "docker.io/library/nothing@sha256:" + strings.Repeat("c", 64)
	accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

	if _, err := Apply(executor, accepted, input); err != nil {
		t.Fatalf("an update was refused: %v", err)
	}

	if strings.Join(executor.effects, ",") != strings.Join([]string{
		"EnsureServiceData",
		"StopService",
		"DisableEgressRulesAtBoot",
		"RemoveUnitFile",
		"RemoveEgressRules",
		"PullImage",
		"WriteEgressRules",
		"WriteUnitFile",
		"EnableEgressRulesAtBoot",
		"WriteUnitFile",
		"ReloadUserUnits",
		"StartService",
	}, ",") {
		t.Fatalf("an update did not lift, fetch and pose again in that order: %q", executor.effects)
	}
	// The service is stopped before its confinement is lifted, so no instant of
	// this flow holds a running service that nothing confines.
	stopped := indexOfEffect(executor.effects, "StopService")
	lifted := indexOfEffect(executor.effects, "RemoveEgressRules")
	posed := indexOfEffect(executor.effects, "WriteEgressRules")
	started := indexOfEffect(executor.effects, "StartService")
	if !(stopped < lifted && lifted < posed && posed < started) {
		t.Fatalf("a running service was left unconfined at some instant: %q", executor.effects)
	}
	if string(executor.egressRules) !=
		string(renderEgressRules(vaultwardenPlacement, executor.accountIdentifier)) {
		t.Fatalf("the table posed again carries an exception:\n%s", executor.egressRules)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("an update changed the data: %q", executor.dataContent)
	}
}

// indexOfEffect answers where one effect happened in a run, so an ordering can be
// asserted as an ordering rather than as a spelling of a whole list.
func indexOfEffect(effects []string, name string) int {
	for index, effect := range effects {
		if effect == name {
			return index
		}
	}
	return -1
}

// TestRemovingAPrivateServiceKeepsItsDataAndItsArchives is the decision this
// palier owes a reader in the clearest form it has.
//
// A removal takes away everything that runs — the container, the sheet, the
// image, the confinement — and keeps everything that is data. No plan of this
// product describes the destruction of data, so no operation of this package
// performs one; a human who wants the data gone removes it themselves, with their
// own eyes on the path.
func TestRemovingAPrivateServiceKeepsItsDataAndItsArchives(t *testing.T) {
	t.Parallel()
	executor := archivedPrivateMachine(fixturePort)
	accepted, input := approvedPrivateService(t, plan.OperationRemovePrivateService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the removal was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the removal announced nothing: %+v", application)
	}

	if strings.Join(executor.effects, ",") != strings.Join([]string{
		"StopService",
		"RemoveUnitFile",
		"ReloadUserUnits",
		"RemoveImage",
		"DisableEgressRulesAtBoot",
		"RemoveUnitFile",
		"RemoveEgressRules",
	}, ",") {
		t.Fatalf("the removal did not take away what it names, in order: %q", executor.effects)
	}
	if executor.holds(vaultwardenPlacement.unitPath()) || executor.egressRulesPresent ||
		executor.holds(egressRulesUnitPath) || executor.egressAtBoot {
		t.Fatal("the removal left something of the running service behind")
	}
	// A machine's own firewall is never a casualty of a removal of this product.
	if _, standing := executor.nftTables[foreignTable]; !standing {
		t.Fatal("the removal took away a table this product never wrote")
	}

	// And the whole point: the data and the archives are exactly where they were.
	if !executor.dataPresent || executor.dataContent != fixtureSecrets {
		t.Fatalf("the removal destroyed the data: %t %q", executor.dataPresent, executor.dataContent)
	}
	if executor.archives[vaultwardenPlacement.archivePath(fixtureSnapshotSlot)] != fixtureRestoredSecrets {
		t.Fatal("the removal destroyed an archive")
	}
	if application.DataPath != VaultwardenDataDirectory {
		t.Fatalf("the removal did not name the data it kept: %+v", application)
	}
	if strings.Join(application.SnapshotSlots, ",") != fixtureSnapshotSlot {
		t.Fatalf("the removal did not name the archives it kept: %+v", application.SnapshotSlots)
	}
}

// TestRemovingAnAbsentPrivateServiceChangesNothingAndStillKeepsTheData keeps a
// removal a statement about one instance rather than a repair of a machine.
//
// The data being there is deliberately not part of the decision to act: a machine
// that keeps its data forever must still be able to say "this service is already
// removed", so the four things a removal takes away are the four things it reads.
func TestRemovingAnAbsentPrivateServiceChangesNothingAndStillKeepsTheData(t *testing.T) {
	t.Parallel()
	executor := privateMachine()
	executor.dataPresent = true
	executor.dataContent = fixtureSecrets
	accepted, input := approvedPrivateService(t, plan.OperationRemovePrivateService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing an absent private service was refused: %v", err)
	}
	if application.Changed {
		t.Fatalf("removing an absent private service reported a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("removing an absent private service touched the machine: %q", executor.effects)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("removing an absent private service touched the data: %q", executor.dataContent)
	}
}

// TestAControlledRecreationFindsTheSameDataBehindANewContainer is the contract's
// own sentence — mêmes données, nouveau conteneur — as two plans a human reads.
//
// There is no recreation operation and there is deliberately none: what the
// contract calls a controlled recreation is a removal followed by a deployment,
// each approved, each reported, and the data is untouched by both.
func TestAControlledRecreationFindsTheSameDataBehindANewContainer(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)

	removal, removalInput := approvedPrivateService(t, plan.OperationRemovePrivateService, fixturePort)
	if _, err := Apply(executor, removal, removalInput); err != nil {
		t.Fatalf("the removal of the recreation was refused: %v", err)
	}
	if executor.active || executor.image != "" {
		t.Fatal("the removal left the container standing")
	}

	deployment, deploymentInput := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)
	application, err := Apply(executor, deployment, deploymentInput)
	if err != nil {
		t.Fatalf("the deployment of the recreation was refused: %v", err)
	}
	if !application.Changed {
		t.Fatalf("the deployment of the recreation found nothing to do: %+v", application)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("the recreation lost the data: %q", executor.dataContent)
	}
	if executor.dataRestores != 0 {
		t.Fatal("the recreation restored an archive nobody approved")
	}
	if !executor.active || executor.image != vaultwardenPlacement.image {
		t.Fatal("the recreation did not leave a new container on the pinned image")
	}
}

// TestAControlledFailureOfAPrivateDeploymentRollsBackWithoutTouchingTheData
// walks the seam calls a deployment can fail at, and requires the same conclusion
// of each: the approved rollback is attempted, this machine ends up holding the
// state that rollback describes, and the data is exactly where it was.
//
// That last clause is the one this palier adds. The rollback of a deployment is a
// removal, and a removal of this product keeps the data — so a failed deployment
// on a machine that already held data is not a way to lose it.
func TestAControlledFailureOfAPrivateDeploymentRollsBackWithoutTouchingTheData(t *testing.T) {
	t.Parallel()
	for _, failing := range []string{
		"EnsureServiceData", "PullImage", "WriteEgressRules",
		"EnableEgressRulesAtBoot", "WriteUnitFile", "ReloadUserUnits",
		"StartService", "ProbeAnswers",
	} {
		executor := deployedPrivateMachine(fixturePort)
		executor.drop(vaultwardenPlacement.unitPath())
		executor.failures[failing] = errors.New("the machine refused this effect")
		accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("a deployment failing at %s succeeded", failing)
		}
		if application != nil {
			t.Fatalf("a deployment failing at %s returned an application: %+v", failing, application)
		}
		var controlled *ControlledFailure
		if !errors.As(err, &controlled) {
			t.Fatalf("a deployment failing at %s was not a controlled failure: %v", failing, err)
		}
		if controlled.Operation != plan.OperationDeployPrivateService {
			t.Fatalf("a deployment failing at %s named another operation: %+v", failing, controlled)
		}
		if executor.dataContent != fixtureSecrets || !executor.dataPresent {
			t.Fatalf("a deployment failing at %s lost the data: %t %q",
				failing, executor.dataPresent, executor.dataContent)
		}
	}
}

// TestAFailedPrivateRollbackObservesTheDataAndTheConfinement keeps the partial
// state a statement about the instance that was being applied.
//
// A data-bearing profile is left holding three things the four words of a
// stateless service cannot say, and after a rollback that failed in its turn each
// of them is exactly what a human has to read: is the data still there, is the
// account still confined, and — for an archive operation — does the slot hold a
// file. None can be inferred from another, so all three are asked.
func TestAFailedPrivateRollbackObservesTheDataAndTheConfinement(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	executor.drop(vaultwardenPlacement.unitPath())
	executor.failures["ProbeAnswers"] = errors.New("the service never answered")
	executor.failures["RemoveImage"] = errors.New("the machine refused this effect")
	accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

	_, err := Apply(executor, accepted, input)
	var controlled *ControlledFailure
	if !errors.As(err, &controlled) {
		t.Fatalf("the failure was not a controlled one: %v", err)
	}
	if controlled.Outcome != OutcomePartial || controlled.Observed == nil {
		t.Fatalf("a rollback that failed in its turn was not named a partial state: %+v", controlled)
	}
	if controlled.Observed.Data != observedPresent {
		t.Fatalf("the observation says nothing true about the data: %+v", controlled.Observed)
	}
	if controlled.Observed.Egress == "" {
		t.Fatalf("the observation says nothing about the confinement: %+v", controlled.Observed)
	}
	// A private service is not an archive operation, so the word about an archive
	// is omitted rather than reported empty: an observation says what was seen, and
	// a word about something nobody looked at is neither a fact nor an admission.
	if controlled.Observed.Archive != "" {
		t.Fatalf("the observation answered for an archive nobody looked at: %+v", controlled.Observed)
	}
}

// TestAPrivateServiceWithoutARouteIsALicitSteadyState holds the sentence of the
// contract that is easiest to lose: publier est optionnel.
//
// Nothing of this flow reads a route, asks for an entrypoint or refuses a machine
// that has neither. A private service deployed on a machine holding no entry at
// all reaches its loopback port and stays there, for as long as its owner wants —
// which is the state of a user without a domain.
func TestAPrivateServiceWithoutARouteIsALicitSteadyState(t *testing.T) {
	t.Parallel()
	executor := privateMachine()
	accepted, input := approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a private service on a machine holding no entry was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("a private service without a route was not deployed: %+v", application)
	}
	if len(executor.verifiedRoutes) != 0 || executor.entrypointChecks != 0 {
		t.Fatal("the deployment of a private service read something of a route")
	}
	if application.RouteHost != "" || application.FragmentPath != "" {
		t.Fatalf("the deployment of a private service named a route: %+v", application)
	}
	for path := range executor.files {
		if strings.HasPrefix(path, entrypointFragmentDirectory+"/") {
			t.Fatalf("the deployment of a private service wrote a fragment: %q", path)
		}
	}
}

// TestThePrivateServiceIsBoundedByThePassageLikeAnyManagedService is the one
// consequence of this palier the passage cares about.
//
// The reference scenario bounds the tunnel to the private service, so the reading
// that answers "does a managed service of this machine publish this port" has to
// see the private door as well as the stateless one. It is asserted through the
// junction rather than through the reading, because that is where a regression
// would be felt: a passage bounded to a port nothing manages is refused.
func TestThePrivateServiceIsBoundedByThePassageLikeAnyManagedService(t *testing.T) {
	t.Parallel()
	executor := preparedLinkMachine(plan.LinkRoleInitiator)
	executor.drop(bentoPDFPlacement.unitPath())
	executor.hold(vaultwardenPlacement.unitPath(),
		renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost))
	accepted, input := approvedInitiatorPeer(t, plan.OperationJoinLinkPeer, fixturePort)

	if _, err := Apply(executor, accepted, input); err != nil {
		t.Fatalf("a junction bounded to the private service was refused: %v", err)
	}
}
