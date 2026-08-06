package auxiliary

// This file is the dispatch of the three plan schemas: which decoder a carried
// pair reaches, what happens when the two documents do not agree on one, and
// which operations this Auxiliary performs rather than merely reads.
//
// Each schema widened what this Auxiliary performs in steps, and each step
// closed a window a test named. `#90` added the two managed web service
// operations, `#91` the four entrypoint and route ones, and `#96` the six of the
// private passage, which were refused by the schema dispatch alone until it
// landed. One window is open again: the four document shapes of the private
// profile are read but not performed, and `#102` and `#103` close it. What this
// file holds is therefore that every document shape this Auxiliary performs
// reaches the effects of its own kind and no other, that the shapes it does not
// perform are refused by name before anything happens, and that no decoder covers
// for another.

import (
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

// TestEveryPrivateProfileOperationIsRefusedByNameBeforeAnyEffect is the window
// this issue opens, named here so that the issues that close it have one test to
// replace rather than a silence to notice.
//
// The approval package now holds the seven operations of the private profile in
// its closed list, so a human may sign one and this Auxiliary may be handed the
// pair. Performing them is `#102` — the data-bearing service and its archives —
// and `#103` — the route the passage publishes. Until then the pairs below are
// real, valid, canonically frozen documents of that contract, and every one of
// them is refused where the shapes of schema 2 become instances: by name, before
// any effect, and before this machine is read at all.
//
// They are schema 2 documents, so unlike the passage's window they are decoded,
// held against their signed digests, held against this machine's target and held
// as exact inverses before the refusal. That is deliberate: the refusal is about
// what this Auxiliary performs, not about what it can read, and everything that
// could have refused earlier still does.
func TestEveryPrivateProfileOperationIsRefusedByNameBeforeAnyEffect(t *testing.T) {
	t.Parallel()
	for name, frozen := range map[string]func(*testing.T) (string, plan.Frozen){
		"a private service deployment": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationDeployPrivateService,
				frozenPrivateServicePair(t, plan.OperationDeployPrivateService, fixturePort)
		},
		"a private service removal": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationRemovePrivateService,
				frozenPrivateServicePair(t, plan.OperationRemovePrivateService, fixturePort)
		},
		"a link route publication": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationPublishLinkRoute,
				frozenLinkRoutePair(t, plan.OperationPublishLinkRoute, fixturePort)
		},
		"a link route retirement": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationRetireLinkRoute,
				frozenLinkRoutePair(t, plan.OperationRetireLinkRoute, fixturePort)
		},
		"a snapshot": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationSnapshotService, frozenSnapshotPair(t, plan.OperationSnapshotService)
		},
		"a snapshot discard": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationDiscardSnapshot, frozenSnapshotPair(t, plan.OperationDiscardSnapshot)
		},
		"a restore": func(t *testing.T) (string, plan.Frozen) {
			return plan.OperationRestoreService, frozenRestorePair(t)
		},
	} {
		operation, pair := frozen(t)
		executor := deployedServiceMachine(t, fixturePort)
		accepted, input := approvedFrozenPair(operation, pair)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was applied by an Auxiliary that does not perform it", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), "which this Auxiliary does not yet perform") {
			t.Fatalf("%s was refused for another reason than the window: %v", name, err)
		}
		if !strings.Contains(err.Error(), operation) {
			t.Fatalf("%s was refused without being named: %v", name, err)
		}
		if len(executor.effects) != 0 || len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine: %q %q", name, executor.effects, executor.reads)
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
