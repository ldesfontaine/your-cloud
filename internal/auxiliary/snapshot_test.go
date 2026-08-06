package auxiliary

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file holds the three archive operations: what each of them does to a
// machine, what each of them refuses, and the one invariant that runs through all
// three — no state this machine held is ever destroyed by a return.

// TestASnapshotStopsArchivesRestartsAndReportsItsDigest is the flow of the
// contract, read as a report will have to explain it.
func TestASnapshotStopsArchivesRestartsAndReportsItsDigest(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	accepted, input := approvedSnapshot(t, plan.OperationSnapshotService)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the snapshot was refused: %v", err)
	}
	if !application.Changed {
		t.Fatalf("an archive was written and no change reported: %+v", application)
	}
	if strings.Join(executor.effects, ",") != "StopService,ArchiveServiceData,StartService" {
		t.Fatalf("the snapshot did not stop, archive and restart in that order: %q", executor.effects)
	}
	if executor.archives[vaultwardenPlacement.archivePath(fixtureSnapshotSlot)] != fixtureSecrets {
		t.Fatal("the archive does not hold the data that was there")
	}
	// The report carries the slot, the digest of the bytes and the instant — and
	// none of them is a value a human could have approved in advance, which is why
	// the plan carries no digest at all.
	if application.SnapshotSlot != fixtureSnapshotSlot {
		t.Fatalf("the snapshot named another slot: %+v", application)
	}
	if application.ArchiveSHA256 != archiveDigest(fixtureSecrets) {
		t.Fatalf("the snapshot reported another digest than the archive it wrote: %+v", application)
	}
	if application.ArchivedAt != fixtureArchiveInstant.Format(archiveTimeLayout) {
		t.Fatalf("the snapshot reported no instant: %+v", application)
	}
	if strings.Join(application.SnapshotSlots, ",") != fixtureSnapshotSlot {
		t.Fatalf("the snapshot did not name the archives this machine holds: %+v", application.SnapshotSlots)
	}
	// The service came back and was proven to answer on the port its own sheet
	// publishes — a port no archive plan carries and none could.
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the service was not proven to answer again: %v", executor.probedPorts)
	}
	if !executor.active {
		t.Fatal("the snapshot left the service stopped")
	}
	// A snapshot is about data. It announces no service state, because the two
	// words this package has for a service are running and gone, and a snapshot
	// returns a machine to whichever it found.
	if application.ServiceState != "" || application.UnitPath != "" {
		t.Fatalf("the snapshot announced a service rather than an archive: %+v", application)
	}
}

// TestASnapshotOfAStoppedServiceLeavesItStopped holds the licit steady state the
// contract names: a private service without a route, or with its container down,
// is an ordinary state and its data is exactly what an archive is for.
func TestASnapshotOfAStoppedServiceLeavesItStopped(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	executor.active = false
	executor.image = ""
	accepted, input := approvedSnapshot(t, plan.OperationSnapshotService)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a snapshot of a stopped service was refused: %v", err)
	}
	if !application.Changed {
		t.Fatalf("a snapshot of a stopped service reported no change: %+v", application)
	}
	if strings.Join(executor.effects, ",") != "ArchiveServiceData" {
		t.Fatalf("a snapshot of a stopped service touched more than the archive: %q", executor.effects)
	}
	if executor.active {
		t.Fatal("a snapshot started a service no plan asked to start")
	}
	if len(executor.probedPorts) != 0 {
		t.Fatal("a snapshot proved a service it never started")
	}
}

// TestADiscardRemovesExactlyOneArchiveAndReadsNoService keeps a discard a
// statement about a file beside a service rather than about the service.
func TestADiscardRemovesExactlyOneArchiveAndReadsNoService(t *testing.T) {
	t.Parallel()
	executor := archivedPrivateMachine(fixturePort)
	accepted, input := approvedSnapshot(t, plan.OperationDiscardSnapshot)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the discard was refused: %v", err)
	}
	if !application.Changed || application.SnapshotSlot != fixtureSnapshotSlot {
		t.Fatalf("the discard announced nothing: %+v", application)
	}
	if strings.Join(executor.effects, ",") != "RemoveServiceArchive" {
		t.Fatalf("the discard did more than remove one archive: %q", executor.effects)
	}
	if _, standing := executor.archives[vaultwardenPlacement.archivePath(fixtureSnapshotSlot)]; standing {
		t.Fatal("the discard left the archive behind")
	}
	if len(application.SnapshotSlots) != 0 {
		t.Fatalf("the discard named an archive it had just destroyed: %+v", application.SnapshotSlots)
	}
	// It writes no archive, so it reports no digest and no instant: a report says
	// what happened, and a date on nothing is not a fact.
	if application.ArchiveSHA256 != "" || application.ArchivedAt != "" {
		t.Fatalf("the discard reported an archive it never wrote: %+v", application)
	}
	if !executor.active || executor.dataContent != fixtureSecrets {
		t.Fatal("the discard touched the service or its data")
	}
}

// TestDiscardingAnAbsentArchiveChangesNothing keeps a discard a statement about
// one slot rather than a repair of a directory.
func TestDiscardingAnAbsentArchiveChangesNothing(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	accepted, input := approvedSnapshot(t, plan.OperationDiscardSnapshot)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("discarding an absent archive was refused: %v", err)
	}
	if application.Changed {
		t.Fatalf("discarding an absent archive reported a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("discarding an absent archive touched the machine: %q", executor.effects)
	}
}

// TestAReturnWritesTheReservedSlotAndBringsTheNamedStateBack is the flow of the
// contract and the invariant of the file at once.
func TestAReturnWritesTheReservedSlotAndBringsTheNamedStateBack(t *testing.T) {
	t.Parallel()
	executor := archivedPrivateMachine(fixturePort)
	accepted, input := approvedRestore(t)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the return was refused: %v", err)
	}
	if !application.Changed {
		t.Fatalf("a return reported no change: %+v", application)
	}
	if strings.Join(executor.effects, ",") !=
		"StopService,EnsureServiceData,ExchangeServiceData,StartService" {
		t.Fatalf("the return did not follow the order of the flow: %q", executor.effects)
	}
	// The named state came back, and the state it replaced is in the reserved slot
	// — which is the whole of what makes the return of a return possible.
	if executor.dataContent != fixtureRestoredSecrets {
		t.Fatalf("the return did not bring the named state back: %q", executor.dataContent)
	}
	if executor.archives[vaultwardenPlacement.archivePath(plan.ReservedSnapshotSlot)] != fixtureSecrets {
		t.Fatal("the reserved slot does not hold the state the return replaced")
	}
	// The report names the slot it read, the slot it wrote, and the digest of what
	// it wrote — the three things a human needs in order to undo this.
	if application.SnapshotSlot != fixtureSnapshotSlot ||
		application.PreviousSlot != plan.ReservedSnapshotSlot {
		t.Fatalf("the return did not name both slots: %+v", application)
	}
	if application.ArchiveSHA256 != archiveDigest(fixtureSecrets) {
		t.Fatalf("the return reported another digest than the archive it wrote: %+v", application)
	}
	if !executor.active || len(executor.probedPorts) != 1 {
		t.Fatal("the return did not put the service back and prove it")
	}
}

// TestTheReservedSlotIsNeverListedAsAnArchiveAHumanNamed holds the one property
// that separates the return mechanism's slot from a human's.
//
// It is held after a return, which is the only moment the reserved slot exists at
// all: the machine really does carry that archive, the seam that lists slots
// really does read the directory, and the slot really is left out.
func TestTheReservedSlotIsNeverListedAsAnArchiveAHumanNamed(t *testing.T) {
	t.Parallel()
	executor := archivedPrivateMachine(fixturePort)
	accepted, input := approvedRestore(t)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the return was refused: %v", err)
	}
	if _, written := executor.archives[vaultwardenPlacement.archivePath(plan.ReservedSnapshotSlot)]; !written {
		t.Fatal("this case proves nothing: the reserved slot was never written")
	}
	for _, slot := range application.SnapshotSlots {
		if slot == plan.ReservedSnapshotSlot {
			t.Fatalf("the reserved slot was listed as one a human named: %+v", application.SnapshotSlots)
		}
	}
	if strings.Join(application.SnapshotSlots, ",") != fixtureSnapshotSlot {
		t.Fatalf("the listing is not the archives a human named: %+v", application.SnapshotSlots)
	}
}

// TestAReturnOfTheReservedSlotIsAnExchangeAndTherefore	ItsOwnUndoing holds the
// property the rollback of every return rests on.
//
// It is held over the flow rather than through Apply, and the reason is the
// contract itself: a return naming the reserved slot is its own exact inverse, so
// it can never travel as a forward plan — the builder refuses to freeze such a
// pair and this Auxiliary refuses one whose two digests are one digest. It reaches
// a machine as the signed rollback of a return and by no other road, which is
// exactly the road the case below the next one takes.
//
// What is asserted here is what that road depends on: running the flow twice over
// the reserved slot returns this machine where it started, because the exchange
// reads the named archive before it writes the reserved one. Written as two
// effects in the order "reserved slot first, data second", both would be the same
// file and the second would read back what the first had just written — a return
// of a return that restored precisely the state it was meant to undo.
func TestAReturnOfTheReservedSlotIsAnExchangeAndThereforeItsOwnUndoing(t *testing.T) {
	t.Parallel()
	executor := deployedPrivateMachine(fixturePort)
	executor.archives[vaultwardenPlacement.archivePath(plan.ReservedSnapshotSlot)] = fixtureRestoredSecrets
	returning := instance{
		kind:         kindArchive,
		operation:    plan.OperationRestoreService,
		placement:    vaultwardenPlacement,
		snapshotSlot: plan.ReservedSnapshotSlot,
	}

	application, _, err := restoreService(executor, returning)
	if err != nil {
		t.Fatalf("a return of the reserved slot was refused: %v", err)
	}
	if application.SnapshotSlot != plan.ReservedSnapshotSlot {
		t.Fatalf("the return named another slot: %+v", application)
	}
	if executor.dataContent != fixtureRestoredSecrets {
		t.Fatalf("the return did not bring the reserved state back: %q", executor.dataContent)
	}
	if executor.archives[vaultwardenPlacement.archivePath(plan.ReservedSnapshotSlot)] != fixtureSecrets {
		t.Fatal("the reserved slot does not hold the state this return replaced")
	}

	if _, _, err := restoreService(executor, returning); err != nil {
		t.Fatalf("the return of the return was refused: %v", err)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("running the return twice did not return this machine where it started: %q", executor.dataContent)
	}
	if executor.archives[vaultwardenPlacement.archivePath(plan.ReservedSnapshotSlot)] != fixtureRestoredSecrets {
		t.Fatal("the reserved slot did not come back to what it held")
	}
}

// TestAControlledFailureMidReturnAttemptsTheApprovedReturnOfTheReservedSlot is
// the same conduct read through a failure rather than through a second plan.
//
// The machine is made to refuse the effect that puts the service back after the
// data has been replaced. That is a failure after this machine was changed, so the
// approved rollback runs — through the ordinary path, with nothing improvised —
// and the state the return had replaced comes back.
func TestAControlledFailureMidReturnAttemptsTheApprovedReturnOfTheReservedSlot(t *testing.T) {
	t.Parallel()
	executor := archivedPrivateMachine(fixturePort)
	executor.failures["StartService"] = errors.New("the machine refused this effect")
	accepted, input := approvedRestore(t)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a return that could not put the service back succeeded")
	}
	if application != nil {
		t.Fatalf("a controlled failure returned an application: %+v", application)
	}
	var controlled *ControlledFailure
	if !errors.As(err, &controlled) {
		t.Fatalf("the failure was not a controlled one: %v", err)
	}
	if controlled.Outcome != OutcomeRolledBack {
		t.Fatalf("the approved rollback did not reach the state it describes: %+v", controlled)
	}
	if controlled.Operation != plan.OperationRestoreService ||
		controlled.SnapshotSlot != fixtureSnapshotSlot {
		t.Fatalf("the failure did not name the instance it was applying: %+v", controlled)
	}
	// Two returns ran and no third: the failed one and the approved rollback.
	if strings.Count(strings.Join(executor.effects, ","), "ExchangeServiceData") != 2 {
		t.Fatalf("something other than the approved rollback ran: %q", executor.effects)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("the rollback did not bring the replaced state back: %q", executor.dataContent)
	}
}

// TestNothingOfAnArchiveOperationIsTouchedWhileItIsStillRefusable is the refusal
// matrix of the three archive operations, in one place and in one form.
//
// Each case is refused for its own reason, with nothing written and — for the
// ones that are decided before the machine is read at all — with nothing read
// either. The two that do read are refused on what they read, which is the whole
// point of reading it: a slot that already holds an archive and a slot that holds
// none cannot be known without asking.
func TestNothingOfAnArchiveOperationIsTouchedWhileItIsStillRefusable(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		machine  func() *fakeExecutor
		approved func(*testing.T) (*approval.Acceptance, *Input)
		named    string
	}{
		"a snapshot of a profile this machine never deployed": {
			machine: privateMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationSnapshotService)
			},
			named: "holds no your-cloud-svc-vaultwarden service",
		},
		"a snapshot of a service holding no data": {
			machine: func() *fakeExecutor {
				executor := deployedPrivateMachine(fixturePort)
				executor.dataPresent = false
				return executor
			},
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationSnapshotService)
			},
			named: "there is nothing to archive",
		},
		"a snapshot towards a slot that already holds one": {
			machine: func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationSnapshotService)
			},
			named: "backups are immutable",
		},
		"a return towards a profile this machine never deployed": {
			machine:  privateMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) { return approvedRestore(t) },
			named:    "holds no your-cloud-svc-vaultwarden service",
		},
		"a return from a slot that holds nothing": {
			machine:  func() *fakeExecutor { return deployedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) { return approvedRestore(t) },
			named:    "there is nothing to return to",
		},
		"a snapshot of a service whose sheet names no port": {
			machine: func() *fakeExecutor {
				executor := deployedPrivateMachine(fixturePort)
				executor.hold(vaultwardenPlacement.unitPath(), []byte("[Container]\nImage=whatever\n"))
				return executor
			},
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationSnapshotService)
			},
			named: "names no loopback port this machine can read",
		},
	} {
		executor := subject.machine()
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), subject.named) {
			t.Fatalf("%s was refused for another reason than its own: %v", name, err)
		}
		var controlled *ControlledFailure
		if errors.As(err, &controlled) {
			t.Fatalf("%s was reported as a controlled failure: %v", name, err)
		}
		if len(executor.effects) != 0 {
			t.Fatalf("%s changed the machine before being refused: %q", name, executor.effects)
		}
	}
}

// TestNoArchiveContentEverLeavesTheMachine is the sentinel of this palier, and it
// is the passage's own rule read over the other kind of private material.
//
// What an archive holds is the data of a vault. The digest of the bytes travels,
// the slot travels, the instant travels; the bytes do not, and nothing in a
// report, an error, an observation or a file this Auxiliary writes may spell one.
// The fake machine's archives carry a sentence rather than plausible data, so a
// match here can only mean something really did carry the content.
func TestNoArchiveContentEverLeavesTheMachine(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		machine  func() *fakeExecutor
		approved func(*testing.T) (*approval.Acceptance, *Input)
		failing  string
	}{
		"a snapshot": {
			machine: func() *fakeExecutor { return deployedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationSnapshotService)
			},
		},
		"a discard": {
			machine: func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedSnapshot(t, plan.OperationDiscardSnapshot)
			},
		},
		"a return": {
			machine:  func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) { return approvedRestore(t) },
		},
		"a return whose rollback failed in its turn": {
			machine:  func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) { return approvedRestore(t) },
			failing:  "ExchangeServiceData",
		},
		"a private deployment": {
			machine: privateMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedPrivateService(t, plan.OperationDeployPrivateService, fixturePort)
			},
		},
		"a private removal": {
			machine: func() *fakeExecutor { return archivedPrivateMachine(fixturePort) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedPrivateService(t, plan.OperationRemovePrivateService, fixturePort)
			},
		},
	} {
		executor := subject.machine()
		if subject.failing != "" {
			executor.failures[subject.failing] = errors.New("the machine refused this effect")
		}
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)

		said := []string{}
		if application != nil {
			rendered, marshalErr := json.Marshal(application)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			said = append(said, string(rendered))
		}
		if err != nil {
			said = append(said, err.Error())
			var failure *ControlledFailure
			if errors.As(err, &failure) && failure.Observed != nil {
				rendered, marshalErr := json.Marshal(failure.Observed)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				said = append(said, string(rendered))
			}
		}
		for path, content := range executor.files {
			said = append(said, path, string(content))
		}
		said = append(said, string(executor.egressRules))
		for _, table := range executor.nftTables {
			said = append(said, string(table))
		}
		for _, spoken := range said {
			for _, secret := range []string{fixtureSecrets, fixtureRestoredSecrets} {
				if strings.Contains(spoken, secret) {
					t.Fatalf("%s carried the data of its own machine: %q", name, spoken)
				}
			}
		}
	}
}
