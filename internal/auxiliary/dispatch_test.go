package auxiliary

// This file is the dispatch of the three plan schemas: which decoder a carried
// pair reaches, what happens when the two documents do not agree on one, and
// which operations this Auxiliary performs rather than merely reads.
//
// Each schema widened what this Auxiliary performs in steps, and each step
// closed a window a test named. `#90` added the two managed web service
// operations, `#91` the four entrypoint and route ones, `#96` the six of the
// private passage, which were refused by the schema dispatch alone until it
// landed, `#102` and `#103` the seven of the private profile, and `#119` the five
// forms of the third door — the two user service operations and the archive
// operations naming a definition by its slug. No window is open: every operation
// these three schemas describe is performed. What this file holds is therefore
// that every document shape reaches the effects of its own kind and no other,
// that a shape this package has no placement for is refused by name before
// anything happens, and that no decoder covers for another.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestASchemaTwoServicePlanReachesTheGeneralisedDeployment is the result this
// issue owes: a schema 2 document describing the managed web service profile is
// applied through the very machinery the probe uses, against the profile's own
// account, sheet, container and pinned image.
func TestASchemaTwoServicePlanReachesTheGeneralisedDeployment(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.afterAccount = &Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
		AccountPresent:         true,
		RootlessPodman:         true,
	}
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal service deployment was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first service application announced no change: %+v", application)
	}
	if application.Operation != plan.OperationDeployWebService || application.LocalPort != fixturePort {
		t.Fatalf("the application named another instance: %+v", application)
	}

	// The order is the same argument as for the probe, and the names are the
	// profile's rather than the probe's: nothing of this operation touched the
	// account, the sheet or the container the previous palier owns.
	expected := []string{
		"CreateProbeAccount", "EnableLinger", "PullImage",
		"WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if application.UnitPath != bentoPDFPlacement.unitPath() || application.UnitPath == UnitPath() {
		t.Fatalf("the service was written where the probe lives: %q", application.UnitPath)
	}
	if len(executor.accountsCreated) != 1 || executor.accountsCreated[0] != BentoPDFAccount+" "+BentoPDFHome {
		t.Fatalf("another account than the profile's was created: %v", executor.accountsCreated)
	}
	if len(executor.lingeringAccounts) != 1 || executor.lingeringAccounts[0] != BentoPDFAccount {
		t.Fatalf("the service account cannot survive without a session: %v", executor.lingeringAccounts)
	}
	if len(executor.pulled) != 1 || executor.pulled[0] != bentoPDFPlacement.image {
		t.Fatalf("another image than the profile's pin was fetched: %v", executor.pulled)
	}
	// The local verification is the profile's: the loopback port a human
	// approved, and the one invariant beyond the status that this profile asks
	// for.
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the announced state was not verified locally: %v", executor.probedPorts)
	}
	if len(executor.probedContentTypes) != 1 || executor.probedContentTypes[0] != contentTypeHTMLDocument {
		t.Fatalf("the local verification asked for another answer: %v", executor.probedContentTypes)
	}
	// The sheet is the profile's, published on the port the image listens on and
	// carrying no low-port sysctl, because this image listens above 1024.
	sheet := string(executor.writtenUnit)
	for _, line := range []string{
		"Image=" + plan.BentoPDFImageReference + "@" + plan.BentoPDFImageDigest,
		"ContainerName=" + BentoPDFAccount,
		"PublishPort=127.0.0.1:8080:8080",
		"Pull=never",
		"ReadOnly=true",
		"NoNewPrivileges=true",
		"DropCapability=ALL",
	} {
		if !strings.Contains(sheet, line) {
			t.Fatalf("the service sheet does not declare %q:\n%s", line, sheet)
		}
	}
	if strings.Contains(sheet, "Sysctl=") {
		t.Fatalf("the service sheet carries a sysctl its image does not need:\n%s", sheet)
	}
}

// TestASchemaTwoServiceRemovalTakesTheProfileAwayAndNothingElse is the other
// half of the same dispatch, with the same effect list a probe removal has and
// none of the probe's names.
func TestASchemaTwoServiceRemovalTakesTheProfileAwayAndNothingElse(t *testing.T) {
	t.Parallel()
	executor := deployedServiceMachine(t, fixturePort)
	accepted, input := approvedService(t, plan.OperationRemoveWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing a present service was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the removal announced the wrong state: %+v", application)
	}
	expected := []string{"StopService", "RemoveUnitFile", "ReloadUserUnits", "RemoveImage"}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if len(executor.removedImages) != 1 || executor.removedImages[0] != bentoPDFPlacement.image {
		t.Fatalf("another image than the profile's pin was removed: %v", executor.removedImages)
	}
	if executor.holds(bentoPDFPlacement.unitPath()) || executor.active || executor.image != "" {
		t.Fatalf("the machine still holds part of the service: %+v", executor)
	}
}

// TestAPairWrittenInTwoSchemasIsNotAPair holds the gate that keeps the two
// decoders from covering for one another.
//
// The refusal happens on what the two documents declare, before either is held
// against the digest an approval signed — so a Controller that pairs a probe
// plan with a service rollback is refused for mixing them rather than for
// happening to hash differently.
func TestAPairWrittenInTwoSchemasIsNotAPair(t *testing.T) {
	t.Parallel()
	probe := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)
	service := frozenServicePair(t, plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, fixturePort)

	for name, mixed := range map[string]plan.Frozen{
		"a schema 1 plan undone by a schema 2 rollback": {
			PlanDocument:     probe.PlanDocument,
			PlanSHA256:       probe.PlanSHA256,
			RollbackDocument: service.RollbackDocument,
			RollbackSHA256:   service.RollbackSHA256,
		},
		"a schema 2 plan undone by a schema 1 rollback": {
			PlanDocument:     service.PlanDocument,
			PlanSHA256:       service.PlanSHA256,
			RollbackDocument: probe.RollbackDocument,
			RollbackSHA256:   probe.RollbackSHA256,
		},
	} {
		executor := deployedServiceMachine(t, fixturePort)
		accepted, input := approvedFrozenPair(plan.OperationDeployWebService, mixed)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), "a pair written in two schemas is not a pair") {
			t.Fatalf("%s was refused for another reason than its own: %v", name, err)
		}
		if len(executor.effects) != 0 || len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine: %q %q", name, executor.effects, executor.reads)
		}
	}
}

// TestASchemaThisAuxiliaryDoesNotReadIsRefusedByName keeps the dispatch closed
// at both ends: a document declaring a schema no decoder owns is refused before
// any of them is asked to try.
//
// The number it declares is one beyond the last contract this product has
// written, which is exactly the case the refusal exists for: a Controller ahead
// of the machine it is talking to.
func TestASchemaThisAuxiliaryDoesNotReadIsRefusedByName(t *testing.T) {
	t.Parallel()
	executor := deployedServiceMachine(t, fixturePort)
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)
	unread := strconv.Itoa(plan.SchemaVersionV3 + 1)
	input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
		"schema_version": unread,
	})
	input.RollbackDocument = forgedServicePlan(t, plan.OperationRemoveWebService, fixturePort, map[string]string{
		"schema_version": unread,
	})

	if _, err := Apply(executor, accepted, input); err == nil {
		t.Fatal("a plan schema this Auxiliary does not read was accepted")
	} else if !strings.Contains(err.Error(), "which this Auxiliary does not read") {
		t.Fatalf("an unknown plan schema was refused for another reason: %v", err)
	}
	if len(executor.effects) != 0 || len(executor.reads) != 0 {
		t.Fatalf("an unknown plan schema reached the machine: %q %q", executor.effects, executor.reads)
	}
}

// TestEverySchemaThreeOperationIsNowPerformedAndNamesItsOwnInstance is the
// window this issue closes.
//
// Until `#96` the six operations of the private passage were refused at the
// schema dispatch by name, before any effect and before any read: the approval
// package held them in its closed list, so a human could sign one and this
// Auxiliary could be handed a real, valid, canonically frozen pair of that
// contract — and it acted on none of them. They are performed now, so what this
// test holds is the property that refusal used to guard: each of the six reaches
// the effects of its own kind, announces the state of its own kind, and names
// the one file a passage owns on this machine rather than any other.
//
// The two junctions and the two departures share one flow apiece, which is
// exactly why both roles appear below: a regression that resolved the initiator's
// constants for a listener's plan would be caught here.
func TestEverySchemaThreeOperationIsNowPerformedAndNamesItsOwnInstance(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		operation string
		machine   func() *fakeExecutor
		approved  func(*testing.T) (*approval.Acceptance, *Input)
		state     string
	}{
		"a listener preparation": {
			operation: plan.OperationPrepareLink,
			machine:   linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
			},
			state: ServiceStateActive,
		},
		"an initiator preparation": {
			operation: plan.OperationPrepareLink,
			machine:   linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleInitiator)
			},
			state: ServiceStateActive,
		},
		"a listener withdrawal": {
			operation: plan.OperationWithdrawLink,
			machine:   func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationWithdrawLink, plan.LinkRoleListener)
			},
			state: ServiceStateAbsent,
		},
		"a listener junction": {
			operation: plan.OperationAttachLinkPeer,
			machine:   func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)
			},
			state: ServiceStateActive,
		},
		"a listener detachment": {
			operation: plan.OperationDetachLinkPeer,
			machine:   func() *fakeExecutor { return joinedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationDetachLinkPeer, fixturePort)
			},
			state: ServiceStateAbsent,
		},
		"an initiator junction": {
			operation: plan.OperationJoinLinkPeer,
			machine:   func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleInitiator) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedInitiatorPeer(t, plan.OperationJoinLinkPeer, fixturePort)
			},
			state: ServiceStateActive,
		},
		"an initiator departure": {
			operation: plan.OperationLeaveLinkPeer,
			machine:   func() *fakeExecutor { return joinedLinkMachine(plan.LinkRoleInitiator) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedInitiatorPeer(t, plan.OperationLeaveLinkPeer, fixturePort)
			},
			state: ServiceStateAbsent,
		},
	} {
		executor := subject.machine()
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused by an Auxiliary that performs it: %v", name, err)
		}
		if application.Operation != subject.operation || application.ServiceState != subject.state {
			t.Fatalf("%s announced another instance or another state: %+v", name, application)
		}
		if !application.Changed {
			t.Fatalf("%s found nothing to do on a machine that needed it: %+v", name, application)
		}
		if application.UnitPath != linkNetdevPath {
			t.Fatalf("%s named %q rather than the file a passage owns", name, application.UnitPath)
		}
		// A passage has no loopback port, no declared name and no fragment: those
		// are what the two older schemas describe, and a report that named one
		// would be claiming something this operation never touched.
		if application.LocalPort != 0 || application.RouteHost != "" || application.FragmentPath != "" {
			t.Fatalf("%s named an instance of another schema: %+v", name, application)
		}
		if len(executor.effects) == 0 {
			t.Fatalf("%s reported a change without touching the machine", name)
		}
	}
}

// TestOnlyThePreparationOfAPassageReportsAPublicKey holds the one value of the
// private passage that is meant to travel, and the five operations that must not
// carry it.
//
// The public key is an observation: the Controller reads it here and carries it,
// readable, into the junction plan of the other machine. A junction reporting one
// would be this machine restating a value it was given rather than one it
// established, and a withdrawal reporting one would be a machine answering for a
// key it has just taken away.
func TestOnlyThePreparationOfAPassageReportsAPublicKey(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		machine  func() *fakeExecutor
		approved func(*testing.T) (*approval.Acceptance, *Input)
		reports  bool
	}{
		"a preparation": {
			machine: linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
			},
			reports: true,
		},
		"a withdrawal": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationWithdrawLink, plan.LinkRoleListener)
			},
		},
		"a junction": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)
			},
		},
		"a departure": {
			machine: func() *fakeExecutor { return joinedLinkMachine(plan.LinkRoleInitiator) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedInitiatorPeer(t, plan.OperationLeaveLinkPeer, fixturePort)
			},
		},
	} {
		executor := subject.machine()
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
		if subject.reports && application.LinkPublicKey != fixtureLinkPublicKey {
			t.Fatalf("%s did not report the public key this machine holds: %+v", name, application)
		}
		if !subject.reports && application.LinkPublicKey != "" {
			t.Fatalf("%s reported a key it had no business establishing: %+v", name, application)
		}
	}
}

// TestEveryLinkRouteOperationIsNowPerformedAndNamesItsOwnInstance is the window
// this issue closes, and it replaces the test that named that window.
//
// Until `#103` the two operations of the route the passage publishes were refused
// where the shapes of schema 2 become instances, by name and before this machine
// was read: the approval package holds them in its closed list, so a human could
// sign one and this Auxiliary could be handed a real, valid, canonically frozen
// pair — and it acted on neither. They are performed now, so what this test holds
// is the property that refusal used to guard: each reaches the effects of its own
// kind, announces the state of its own kind, and names the one file a declared
// name owns rather than a sheet it has none of.
//
// The kind matters and is checked through the verification each one made: a
// publication that reached the local route's flow would have proven the isolation
// headers of another profile, and one that reached this flow proves the status of
// a name served through the tunnel. The two are recorded apart on purpose.
func TestEveryLinkRouteOperationIsNowPerformedAndNamesItsOwnInstance(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		operation string
		machine   func() *fakeExecutor
		state     string
		verified  int
	}{
		"a link route publication": {
			operation: plan.OperationPublishLinkRoute,
			machine:   func() *fakeExecutor { return linkRoutableMachine(fixturePort) },
			state:     ServiceStateActive,
			verified:  1,
		},
		"a link route retirement": {
			operation: plan.OperationRetireLinkRoute,
			machine: func() *fakeExecutor {
				return publishedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
			},
			state: ServiceStateAbsent,
		},
	} {
		executor := subject.machine()
		accepted, input := approvedLinkRoute(t, subject.operation, fixtureLinkRouteHost, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused by an Auxiliary that performs it: %v", name, err)
		}
		if application.Operation != subject.operation || application.ServiceState != subject.state {
			t.Fatalf("%s announced another instance or another state: %+v", name, application)
		}
		if !application.Changed {
			t.Fatalf("%s found nothing to do on a machine that needed it: %+v", name, application)
		}
		if application.RouteHost != fixtureLinkRouteHost ||
			application.FragmentPath != routeFragmentPath(fixtureLinkRouteHost) {
			t.Fatalf("%s named another route: %+v", name, application)
		}
		// A route has no sheet, no loopback port and no key: those belong to the
		// instances of other kinds, and a report naming one would claim something
		// this operation never touched.
		if application.UnitPath != "" || application.LocalPort != 0 || application.LinkPublicKey != "" {
			t.Fatalf("%s named an instance of another kind: %+v", name, application)
		}
		// Both operations say what the name was resting on, and both found the
		// junction there: that is what makes its absence readable when it happens.
		if application.PassageState != ServiceStateActive {
			t.Fatalf("%s did not name the state of the passage: %+v", name, application)
		}
		if len(executor.verifiedLinkRoutes) != subject.verified || len(executor.verifiedRoutes) != 0 {
			t.Fatalf("%s verified the wrong kind of route: %v %v",
				name, executor.verifiedLinkRoutes, executor.verifiedRoutes)
		}
		if len(executor.effects) == 0 {
			t.Fatalf("%s reported a change without touching the machine", name)
		}
	}
}

// TestEveryPrivateProfileOperationIsNowPerformedAndNamesItsOwnInstance is the
// window `#102` closed, held by the property that refusal used to guard.
//
// Each of the five operations reaches the effects of its own kind, announces what
// its own kind has to announce, and names the instance it acted on rather than
// any other. A regression that routed a private deployment through the stateless
// path — or an archive operation through either — is caught here.
func TestEveryPrivateProfileOperationIsNowPerformedAndNamesItsOwnInstance(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		operation string
		machine   func() *fakeExecutor
		approved  func(*testing.T) (*approval.Acceptance, *Input)
		state     string
		unitPath  string
		slot      string
		digestOf  string
	}{
		{
			operation: plan.OperationDeployPrivateService,
			machine:   privateMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)
			},
			state:    ServiceStateActive,
			unitPath: vaultwardenPlacement.unitPath(),
		},
		{
			operation: plan.OperationRemovePrivateService,
			machine:   func() *fakeExecutor { return deployedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedPrivateService(t, plan.OperationRemovePrivateService, fixturePort)
			},
			state:    ServiceStateAbsent,
			unitPath: vaultwardenPlacement.unitPath(),
		},
		{
			operation: plan.OperationSnapshotService,
			machine:   func() *fakeExecutor { return deployedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationSnapshotService)
			},
			slot:     fixtureSnapshotSlot,
			digestOf: fixtureSecrets,
		},
		{
			operation: plan.OperationDiscardSnapshot,
			machine:   func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationDiscardSnapshot)
			},
			slot: fixtureSnapshotSlot,
		},
		{
			operation: plan.OperationRestoreService,
			machine:   func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved:  func(t *testing.T) (*approval.Acceptance, *Input) { return approvedRestore(t) },
			slot:      fixtureSnapshotSlot,
			// A return reports the digest of what it *wrote*, which is the archive of
			// the state it replaced — the one the reserved slot now holds.
			digestOf: fixtureSecrets,
		},
	} {
		executor := subject.machine()
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused by an Auxiliary that performs it: %v", subject.operation, err)
		}
		if application.Operation != subject.operation || application.ServiceState != subject.state {
			t.Fatalf("%s announced another instance or another state: %+v", subject.operation, application)
		}
		if !application.Changed {
			t.Fatalf("%s found nothing to do on a machine that needed it: %+v", subject.operation, application)
		}
		if application.UnitPath != subject.unitPath {
			t.Fatalf("%s named the sheet %q rather than %q", subject.operation, application.UnitPath, subject.unitPath)
		}
		if application.SnapshotSlot != subject.slot {
			t.Fatalf("%s named the slot %q rather than %q", subject.operation, application.SnapshotSlot, subject.slot)
		}
		if application.ArchiveSHA256 != "" && application.ArchiveSHA256 != archiveDigest(subject.digestOf) {
			t.Fatalf("%s reported another archive than the one it wrote: %+v", subject.operation, application)
		}
		if subject.digestOf != "" && application.ArchiveSHA256 != archiveDigest(subject.digestOf) {
			t.Fatalf("%s wrote an archive and reported no digest for it: %+v", subject.operation, application)
		}
		// Every one of the five names the durable directory, in both directions and
		// in every shape: it is the one thing all five have in common on a machine.
		if application.DataPath != vaultwardenPlacement.dataDirectory {
			t.Fatalf("%s named the data %q", subject.operation, application.DataPath)
		}
		if application.RouteHost != "" || application.FragmentPath != "" || application.LinkPublicKey != "" {
			t.Fatalf("%s named an instance of another kind: %+v", subject.operation, application)
		}
		if len(executor.effects) == 0 {
			t.Fatalf("%s reported a change without touching the machine", subject.operation)
		}
	}
}

// TestAPairWhoseTwoDigestsAreOneDigestIsRefusedBeforeAnythingIsDecoded is the
// rule the private profile's return makes reachable.
//
// A restore of the reserved slot genuinely is its own exact inverse — applying it
// twice returns the machine where it started — so it is the first document of the
// product an approval could name as both halves of a pair. No Controller can
// build such a pair, and this package does not trust the Controller: it refuses
// on the two digests alone, before either document is decoded, before the target
// is held and before this machine is read.
func TestAPairWhoseTwoDigestsAreOneDigestIsRefusedBeforeAnythingIsDecoded(t *testing.T) {
	t.Parallel()
	pair := frozenRestorePair(t)
	executor := deployedServiceMachine(t, fixturePort)
	accepted, input := approvedFrozenPair(plan.OperationRestoreService, plan.Frozen{
		PlanDocument:     pair.RollbackDocument,
		PlanSHA256:       pair.RollbackSHA256,
		RollbackDocument: pair.RollbackDocument,
		RollbackSHA256:   pair.RollbackSHA256,
	})

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a document approved as its own undoing was applied")
	}
	if application != nil {
		t.Fatalf("a document approved as its own undoing returned an application: %+v", application)
	}
	if !strings.Contains(err.Error(), "a document is not its own undoing") {
		t.Fatalf("it was refused for another reason: %v", err)
	}
	if len(executor.effects) != 0 || len(executor.reads) != 0 {
		t.Fatalf("it reached the machine: %q %q", executor.effects, executor.reads)
	}
}

// TestEveryThirdDoorOperationIsNowPerformedAndNamesItsOwnInstance is the window
// this issue closes, and it replaces the test that named that window.
//
// Until `#119` the third door's five forms were refused where the shapes of
// schema 2 become instances, by name and before this machine was read: the
// approval package holds their operations in its closed list and the Controller
// builds their pairs, so a human could sign one and this Auxiliary could be handed
// a real, valid, canonically frozen pair — and it acted on none of them. They are
// performed now, so what this test holds is the property that refusal used to
// guard: each of the five reaches the effects of its own kind, announces what its
// own kind has to announce, and names the instance it acted on rather than any
// other.
//
// The five are two halves of one door and they reach it by two different paths: a
// deployment and a removal arrive as a shape of their own, with the definition's
// bytes beside them, while the three archive operations arrive through the very
// field the delivered profiles use — a slug where a profile's name goes. Both
// halves must land on the home the slug derives, or a plan of the third door
// would act on a home another door owns, which is precisely what the reservation
// of the four names exists to make inconstructible.
func TestEveryThirdDoorOperationIsNowPerformedAndNamesItsOwnInstance(t *testing.T) {
	t.Parallel()
	where := fixtureUserPlacement(t)
	archived := userServicePlacementOfSlug(fixtureUserSlug)
	for name, subject := range map[string]struct {
		operation string
		machine   func(*testing.T) *fakeExecutor
		approved  func(*testing.T) (*approval.Acceptance, *Input)
		state     string
		unitPath  string
		slot      string
		digestOf  string
		secrets   string
	}{
		"a user service deployment": {
			operation: plan.OperationDeployUserService,
			machine:   func(*testing.T) *fakeExecutor { return userServiceMachine() },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedUserService(t, plan.OperationDeployUserService, fixturePort)
			},
			state:    ServiceStateActive,
			unitPath: where.unitPath(),
			secrets:  where.secretsDirectory(),
		},
		"a user service removal": {
			operation: plan.OperationRemoveUserService,
			machine:   func(t *testing.T) *fakeExecutor { return deployedUserServiceMachine(t, fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedUserService(t, plan.OperationRemoveUserService, fixturePort)
			},
			state:    ServiceStateAbsent,
			unitPath: where.unitPath(),
			secrets:  where.secretsDirectory(),
		},
		"a snapshot of a user service": {
			operation: plan.OperationSnapshotService,
			machine:   func(t *testing.T) *fakeExecutor { return deployedUserServiceMachine(t, fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedUserArchive(t, plan.OperationSnapshotService)
			},
			slot:     fixtureSnapshotSlot,
			digestOf: fixtureSecrets,
		},
		"a discard of a user service archive": {
			operation: plan.OperationDiscardSnapshot,
			machine:   func(t *testing.T) *fakeExecutor { return archivedUserServiceMachine(t, fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedUserArchive(t, plan.OperationDiscardSnapshot)
			},
			slot: fixtureSnapshotSlot,
		},
		"a restore of a user service": {
			operation: plan.OperationRestoreService,
			machine:   func(t *testing.T) *fakeExecutor { return archivedUserServiceMachine(t, fixturePort) },
			approved:  func(t *testing.T) (*approval.Acceptance, *Input) { return approvedUserRestore(t) },
			slot:      fixtureSnapshotSlot,
			// A return reports the digest of what it *wrote*, which is the archive of
			// the state it replaced — the one the reserved slot now holds.
			digestOf: fixtureSecrets,
		},
	} {
		executor := subject.machine(t)
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused by an Auxiliary that performs it: %v", name, err)
		}
		if application.Operation != subject.operation || application.ServiceState != subject.state {
			t.Fatalf("%s announced another instance or another state: %+v", name, application)
		}
		if !application.Changed {
			t.Fatalf("%s found nothing to do on a machine that needed it: %+v", name, application)
		}
		if application.UnitPath != subject.unitPath {
			t.Fatalf("%s named the sheet %q rather than %q", name, application.UnitPath, subject.unitPath)
		}
		if application.SnapshotSlot != subject.slot {
			t.Fatalf("%s named the slot %q rather than %q", name, application.SnapshotSlot, subject.slot)
		}
		if subject.digestOf != "" && application.ArchiveSHA256 != archiveDigest(subject.digestOf) {
			t.Fatalf("%s wrote an archive and reported no digest for it: %+v", name, application)
		}
		if application.ArchiveSHA256 != "" && application.ArchiveSHA256 != archiveDigest(subject.digestOf) {
			t.Fatalf("%s reported another archive than the one it wrote: %+v", name, application)
		}
		// Every one of the five names the durable root of this service, and the two
		// that were handed the revision name the directory its generated values live
		// in. An archive was handed none, so it names none: the values it never looked
		// at are not a conclusion of an operation about a file beside them.
		if application.DataPath != archived.dataDirectory {
			t.Fatalf("%s named the data %q rather than %q", name, application.DataPath, archived.dataDirectory)
		}
		if application.SecretsPath != subject.secrets {
			t.Fatalf("%s named the secrets %q rather than %q", name, application.SecretsPath, subject.secrets)
		}
		if application.RouteHost != "" || application.FragmentPath != "" || application.LinkPublicKey != "" {
			t.Fatalf("%s named an instance of another kind: %+v", name, application)
		}
		if len(executor.effects) == 0 {
			t.Fatalf("%s reported a change without touching the machine", name)
		}
		// Nothing this door does may carry a generated value out of the machine. The
		// fake draws sentences rather than plausible secrets exactly so that this can
		// be a search rather than an inspection.
		if carried := carriesAGeneratedValue(executor, application); carried != "" {
			t.Fatalf("%s carried a generated value out of this machine: %s", name, carried)
		}
	}
}

// carriesAGeneratedValue searches everything one applied operation produced for
// any of the values this machine generated, and names the first it finds.
//
// It reads the report whole rather than field by field, because the property is
// about the report and not about a list of fields somebody kept up to date beside
// it: a field added later that carried a value would be caught here.
func carriesAGeneratedValue(executor *fakeExecutor, application *Application) string {
	rendered := fmt.Sprintf("%+v", *application)
	for path, value := range executor.secrets {
		if strings.Contains(rendered, value) {
			return path
		}
	}
	return ""
}

// TestEverySchemaTwoOperationIsNowPerformedAndNamesItsOwnInstance is the window
// an earlier issue closed.
//
// Until `#91` the four entrypoint and route operations were refused at dispatch
// by name, before any effect and before any read. They are performed now, so
// what this test holds is the property that refusal used to guard: each of the
// six schema 2 operations reaches the effects of its own kind, announces the
// state of its own kind, and names the instance it acted on rather than any
// other. A regression that routed one kind through another's path is caught
// here.
func TestEverySchemaTwoOperationIsNowPerformedAndNamesItsOwnInstance(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		operation string
		machine   func(*testing.T) *fakeExecutor
		approved  func(*testing.T) (*approval.Acceptance, *Input)
		state     string
		unitPath  string
		routeHost string
	}{
		{
			operation: plan.OperationDeployWebService,
			machine:   func(t *testing.T) *fakeExecutor { return serviceMachine() },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedService(t, plan.OperationDeployWebService, fixturePort)
			},
			state:    ServiceStateActive,
			unitPath: bentoPDFPlacement.unitPath(),
		},
		{
			operation: plan.OperationRemoveWebService,
			machine:   func(t *testing.T) *fakeExecutor { return deployedServiceMachine(t, fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedService(t, plan.OperationRemoveWebService, fixturePort)
			},
			state:    ServiceStateAbsent,
			unitPath: bentoPDFPlacement.unitPath(),
		},
		{
			operation: plan.OperationDeployEntrypoint,
			machine:   func(t *testing.T) *fakeExecutor { return entrypointMachine() },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedEntrypoint(t, plan.OperationDeployEntrypoint)
			},
			state:    ServiceStateActive,
			unitPath: entrypointPlacement.unitPath(),
		},
		{
			operation: plan.OperationRemoveEntrypoint,
			machine:   func(t *testing.T) *fakeExecutor { return deployedEntrypointMachine() },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedEntrypoint(t, plan.OperationRemoveEntrypoint)
			},
			state:    ServiceStateAbsent,
			unitPath: entrypointPlacement.unitPath(),
		},
		{
			operation: plan.OperationPublishRoute,
			machine:   func(t *testing.T) *fakeExecutor { return routableMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)
			},
			state:     ServiceStateActive,
			routeHost: fixtureRouteHost,
		},
		{
			operation: plan.OperationRetireRoute,
			machine:   func(t *testing.T) *fakeExecutor { return publishedRouteMachine(fixtureRouteHost, fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedRoute(t, plan.OperationRetireRoute, fixtureRouteHost, fixturePort)
			},
			state:     ServiceStateAbsent,
			routeHost: fixtureRouteHost,
		},
	} {
		executor := subject.machine(t)
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused by an Auxiliary that performs it: %v", subject.operation, err)
		}
		if application.Operation != subject.operation || application.ServiceState != subject.state {
			t.Fatalf("%s announced another instance or another state: %+v", subject.operation, application)
		}
		if !application.Changed {
			t.Fatalf("%s found nothing to do on a machine that needed it: %+v", subject.operation, application)
		}
		if application.UnitPath != subject.unitPath {
			t.Fatalf("%s named the sheet %q rather than %q", subject.operation, application.UnitPath, subject.unitPath)
		}
		if application.RouteHost != subject.routeHost {
			t.Fatalf("%s named the route %q rather than %q", subject.operation, application.RouteHost, subject.routeHost)
		}
		// A route names its fragment and never a sheet; everything else names a
		// sheet and never a fragment.
		if subject.routeHost == "" && application.FragmentPath != "" {
			t.Fatalf("%s named a fragment: %+v", subject.operation, application)
		}
		if subject.routeHost != "" && application.FragmentPath != routeFragmentPath(subject.routeHost) {
			t.Fatalf("%s named another fragment: %+v", subject.operation, application)
		}
		if len(executor.effects) == 0 {
			t.Fatalf("%s reported a change without touching the machine", subject.operation)
		}
	}
}
