package controller

import (
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

// readingsSnapshot builds one Relay snapshot carrying exactly what one machine
// reported about its declared loopback ports.
func readingsSnapshot(snapshotAt, observedAt string, readings ...observation.ExternalReading) *RelaySnapshot {
	snapshot := &RelaySnapshot{
		SchemaVersion:    1,
		ControllerID:     testControllerID,
		InfrastructureID: testInfrastructureID,
		SnapshotAt:       snapshotAt,
		Machines: []RelaySnapshotMachine{{
			MachineID:        "lab-machine-1",
			EnrollmentStatus: "active",
			Observation: &RelaySnapshotObservation{
				SchemaVersion: 1,
				MachineID:     "lab-machine-1",
				DaemonVersion: observation.DaemonVersion,
				Profile:       observation.Profile,
				Sequence:      1,
				ObservedAt:    observedAt,
				ReceivedAt:    observedAt,
				Gaps:          []observation.Gap{},
				External:      readings,
			},
		}},
	}
	return snapshot
}

// silentMachineSnapshot is the same machine carrying no observation at all.
func silentMachineSnapshot(snapshotAt string) *RelaySnapshot {
	return &RelaySnapshot{
		SchemaVersion:    1,
		ControllerID:     testControllerID,
		InfrastructureID: testInfrastructureID,
		SnapshotAt:       snapshotAt,
		Machines: []RelaySnapshotMachine{
			{MachineID: "lab-machine-1", EnrollmentStatus: "active"},
		},
	}
}

func declaredElement(t *testing.T, store *ExternalStore, port int) ExternalElement {
	t.Helper()
	element, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: port,
	}, true, externalTestTime(t, "2026-08-07T10:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	return element
}

func heldObservation(t *testing.T, store *ExternalStore, elementID string) *ExternalObservation {
	t.Helper()
	for _, element := range store.Snapshot().Elements {
		if element.ElementID == elementID {
			return element.Observation
		}
	}
	t.Fatalf("no declaration carries %s", elementID)
	return nil
}

// TestAbsorbedReadingsSpeakTheThreeStates walks the whole vocabulary of the
// contract through the chain that carries it, and proves what each word means
// here.
//
// `verified` is dated by the machine's own collection instant and never by the
// Controller's clock: the constat happened on the machine, and the age the App
// shows must be the age of the reading rather than of the refresh that fetched
// it. `contradicted` is the narrow thing this product decided it is — a port a
// dated reading found answering accepts nothing any more. `unverifiable` always
// names a reason from the closed list, and a first refusal is one of those
// rather than a contradiction, because nobody ever saw that port answer.
func TestAbsorbedReadingsSpeakTheThreeStates(t *testing.T) {
	store, _ := externalTestStore(t)
	element := declaredElement(t, store, 5000)

	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:01:00Z", "2026-08-07T10:00:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalAnswered})); err != nil {
		t.Fatal(err)
	}
	held := heldObservation(t, store, element.ElementID)
	if held == nil || held.State != ExternalStateVerified || held.Reason != "" ||
		held.ObservedAt != "2026-08-07T10:00:50Z" {
		t.Fatalf("an answered port was recorded as %+v", held)
	}

	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:02:00Z", "2026-08-07T10:01:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalNoListener})); err != nil {
		t.Fatal(err)
	}
	held = heldObservation(t, store, element.ElementID)
	if held.State != ExternalStateContradicted || held.Reason != "" {
		t.Fatalf("a port that stopped answering was recorded as %+v", held)
	}

	// A contradiction that persists keeps saying the same word rather than falling
	// back to `unverifiable`: nothing about the element changed, so the sentence
	// the human reads must not change either.
	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:03:00Z", "2026-08-07T10:02:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalNoListener})); err != nil {
		t.Fatal(err)
	}
	if held = heldObservation(t, store, element.ElementID); held.State != ExternalStateContradicted {
		t.Fatalf("a lasting contradiction became %+v", held)
	}

	// And a port that answers again is verified again, dated by that reading.
	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:04:00Z", "2026-08-07T10:03:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalAnswered})); err != nil {
		t.Fatal(err)
	}
	if held = heldObservation(t, store, element.ElementID); held.State != ExternalStateVerified {
		t.Fatalf("a port answering again stayed %+v", held)
	}
}

// TestFirstRefusalIsUnverifiableAndNeverAContradiction is the direction the
// contract's own proof insists on: never the inverse by default.
func TestFirstRefusalIsUnverifiableAndNeverAContradiction(t *testing.T) {
	store, _ := externalTestStore(t)
	element := declaredElement(t, store, 5000)
	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:01:00Z", "2026-08-07T10:00:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalNoListener})); err != nil {
		t.Fatal(err)
	}
	held := heldObservation(t, store, element.ElementID)
	if held.State != ExternalStateUnverifiable || held.Reason != ExternalReasonNothingListening {
		t.Fatalf("a first refusal was recorded as %+v", held)
	}
}

// TestUnverifiableAlwaysNamesItsReason walks the reasons a reading may carry,
// including the one `#107` added.
//
// The managed one is the collision `#106` could not decide, and what it must
// never be is silence: an element whose port this product itself published says
// so, in words, instead of going on looking like an external thing nobody has
// got round to reading.
func TestUnverifiableAlwaysNamesItsReason(t *testing.T) {
	for outcome, reason := range map[string]string{
		observation.ExternalTooLarge: ExternalReasonResponseTooLarge,
		observation.ExternalManaged:  ExternalReasonPortIsManaged,
	} {
		store, _ := externalTestStore(t)
		element := declaredElement(t, store, 5000)
		if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:01:00Z", "2026-08-07T10:00:50Z",
			observation.ExternalReading{ProbePort: 5000, Outcome: outcome})); err != nil {
			t.Fatal(err)
		}
		held := heldObservation(t, store, element.ElementID)
		if held.State != ExternalStateUnverifiable || held.Reason != reason {
			t.Fatalf("%s was recorded as %+v rather than %s", outcome, held, reason)
		}
		projected, err := projectExternalElement(ExternalElement{
			ElementID: element.ElementID, MachineID: element.MachineID, Label: element.Label,
			Kind: element.Kind, ProbePort: element.ProbePort, DeclaredAt: element.DeclaredAt,
			Observation: held,
		}, externalTestTime(t, "2026-08-07T10:01:10Z"))
		if err != nil || projected.Reason == nil || *projected.Reason != reason {
			t.Fatalf("the reason did not reach the App's view: %+v %v", projected, err)
		}
	}
}

// TestASilentMachineIsNamedRatherThanAged separates the two dimensions the
// contract keeps apart.
//
// A machine that carries nothing at all in a snapshot the Controller could read
// is a viewpoint that has stopped answering, and an element that was readable
// before is told so. An element nobody ever read stays `declared`: "not
// provisioned yet" is not "unreachable", and inventing the second would be
// exactly the kind of guess this palier exists to refuse.
func TestASilentMachineIsNamedRatherThanAged(t *testing.T) {
	store, _ := externalTestStore(t)
	read := declaredElement(t, store, 5000)
	unread, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "imprimante", Kind: ExternalKindService, ProbePort: 9100,
	}, true, externalTestTime(t, "2026-08-07T10:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:01:00Z", "2026-08-07T10:00:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalAnswered})); err != nil {
		t.Fatal(err)
	}
	if err := store.AbsorbSnapshot(silentMachineSnapshot("2026-08-07T10:02:00Z")); err != nil {
		t.Fatal(err)
	}
	held := heldObservation(t, store, read.ElementID)
	if held.State != ExternalStateUnverifiable || held.Reason != ExternalReasonMachineUnreachable ||
		held.ObservedAt != "2026-08-07T10:02:00Z" {
		t.Fatalf("a silent machine left the element saying %+v", held)
	}
	if heldObservation(t, store, unread.ElementID) != nil {
		t.Fatal("an element nobody ever read was declared unreachable")
	}
}

// TestAbsorbingChangesNothingWhenNothingChanged is the property that keeps a
// read path from looking like a mutation.
//
// The same snapshot twice bumps no revision. A reading older than the one
// already held is dropped rather than stored, for the reason the Relay cache
// refuses a regressing snapshot: a state that can move backwards is a state
// somebody rewrites by replaying an old success over a fresh contradiction. And
// a port the machine reports that nobody declared is ignored — nothing here
// discovers a neighbour, names one or creates a line for one.
func TestAbsorbingChangesNothingWhenNothingChanged(t *testing.T) {
	store, _ := externalTestStore(t)
	element := declaredElement(t, store, 5000)

	fresh := readingsSnapshot("2026-08-07T10:02:00Z", "2026-08-07T10:01:50Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalNoListener},
		observation.ExternalReading{ProbePort: 7777, Outcome: observation.ExternalAnswered})
	if err := store.AbsorbSnapshot(fresh); err != nil {
		t.Fatal(err)
	}
	after := store.Snapshot()
	if len(after.Elements) != 1 {
		t.Fatalf("an undeclared port created a line: %+v", after.Elements)
	}
	revision := after.ExternalRevision

	if err := store.AbsorbSnapshot(fresh); err != nil {
		t.Fatal(err)
	}
	if store.Snapshot().ExternalRevision != revision {
		t.Fatal("absorbing the same snapshot twice moved the inventory")
	}

	stale := readingsSnapshot("2026-08-07T10:00:30Z", "2026-08-07T10:00:20Z",
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalAnswered})
	if err := store.AbsorbSnapshot(stale); err != nil {
		t.Fatal(err)
	}
	held := heldObservation(t, store, element.ElementID)
	if held.ObservedAt != "2026-08-07T10:01:50Z" || held.State != ExternalStateUnverifiable {
		t.Fatalf("an older reading replaced a fresher one: %+v", held)
	}
	if store.Snapshot().ExternalRevision != revision {
		t.Fatal("a refused reading still moved the revision")
	}

	// A machine that reports nothing about a declared port leaves the last constat
	// exactly where it was, with its own date, and lets it age honestly.
	if err := store.AbsorbSnapshot(readingsSnapshot("2026-08-07T10:03:00Z", "2026-08-07T10:02:50Z")); err != nil {
		t.Fatal(err)
	}
	if heldObservation(t, store, element.ElementID).ObservedAt != "2026-08-07T10:01:50Z" {
		t.Fatal("a machine that looked at nothing rewrote a constat")
	}
	if err := store.AbsorbSnapshot(nil); err != nil {
		t.Fatal(err)
	}
}
