package controller

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func externalTestStore(t *testing.T) (*ExternalStore, string) {
	t.Helper()
	directory := privateTestDirectory(t)
	store, err := OpenExternalStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	return store, directory
}

func externalTestTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}

// TestExternalStoreDeclaresListsAndWithdraws is the nominal life of a
// declaration: it enters, it is read back exactly as written, and withdrawing it
// removes the declaration and nothing else the store holds.
func TestExternalStoreDeclaresListsAndWithdraws(t *testing.T) {
	store, directory := externalTestStore(t)
	now := externalTestTime(t, "2026-08-07T10:00:00Z")

	element, revision, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: 5000,
	}, true, now)
	if err != nil || revision != 1 {
		t.Fatalf("the first declaration did not report its own revision: %d %v", revision, err)
	}
	if !canonicalRawURLBytes(element.ElementID, 16) || element.DeclaredAt != "2026-08-07T10:00:00Z" ||
		element.Observation != nil {
		t.Fatalf("declaration was not minted as the contract describes: %+v", element)
	}
	neighbour, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "Routeur", Kind: ExternalKindPassage, ProbePort: 443,
	}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if state.ExternalRevision != 2 || len(state.Elements) != 2 ||
		state.Elements[0].ProbePort != 443 || state.Elements[1].ProbePort != 5000 {
		t.Fatalf("the inventory is not the sorted pair that was declared: %+v", state)
	}

	// Reopening proves the declarations are durable: an inventory a human types
	// by hand may not empty itself when the Controller restarts.
	reopened, err := OpenExternalStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Snapshot().Elements) != 2 || reopened.Snapshot().ExternalRevision != 2 {
		t.Fatalf("the declared inventory did not survive a reopen: %+v", reopened.Snapshot())
	}

	withdrawn, withdrawnRevision, err := reopened.Withdraw(neighbour.ElementID)
	if err != nil || withdrawn.ElementID != neighbour.ElementID || withdrawnRevision != 3 {
		t.Fatalf("withdrawal did not return the declaration it removed: %+v %v", withdrawn, err)
	}
	after := reopened.Snapshot()
	if after.ExternalRevision != 3 || len(after.Elements) != 1 || after.Elements[0].ElementID != element.ElementID {
		t.Fatalf("withdrawing one declaration disturbed the others: %+v", after)
	}
	if _, _, err := reopened.Withdraw(neighbour.ElementID); err != errExternalElementUnknown {
		t.Fatalf("a second withdrawal reported a removal that did not happen: %v", err)
	}
}

// TestExternalStoreRefusesEveryDeclarationOutsideTheContract holds the five
// closed fields to their bound, and holds the one refusal this Controller can
// genuinely decide: the same machine and the same probe port declared twice.
func TestExternalStoreRefusesEveryDeclarationOutsideTheContract(t *testing.T) {
	store, _ := externalTestStore(t)
	now := externalTestTime(t, "2026-08-07T10:00:00Z")

	for name, declaration := range map[string]ExternalDeclaration{
		"an empty label":         {MachineID: "lab-machine-1", Label: "", Kind: ExternalKindService, ProbePort: 5000},
		"a label of 65 bytes":    {MachineID: "lab-machine-1", Label: strings.Repeat("a", 65), Kind: ExternalKindService, ProbePort: 5000},
		"a label carrying NUL":   {MachineID: "lab-machine-1", Label: "nas\x00", Kind: ExternalKindService, ProbePort: 5000},
		"a label carrying a tab": {MachineID: "lab-machine-1", Label: "nas\tsalon", Kind: ExternalKindService, ProbePort: 5000},
		"a label carrying a newline": {MachineID: "lab-machine-1", Label: "nas\nsalon",
			Kind: ExternalKindService, ProbePort: 5000},
		"a label carrying an escape": {MachineID: "lab-machine-1", Label: "nas\x1b[31m",
			Kind: ExternalKindService, ProbePort: 5000},
		"a label outside ASCII": {MachineID: "lab-machine-1", Label: "café", Kind: ExternalKindService, ProbePort: 5000},
		"a label carrying DEL":  {MachineID: "lab-machine-1", Label: "nas\x7f", Kind: ExternalKindService, ProbePort: 5000},
		"a kind outside the closed list": {MachineID: "lab-machine-1", Label: "NAS",
			Kind: "external_database", ProbePort: 5000},
		"a managed kind":             {MachineID: "lab-machine-1", Label: "NAS", Kind: "web_service", ProbePort: 5000},
		"a port below the low bound": {MachineID: "lab-machine-1", Label: "NAS", Kind: ExternalKindService, ProbePort: 0},
		"a negative port":            {MachineID: "lab-machine-1", Label: "NAS", Kind: ExternalKindService, ProbePort: -1},
		"a port beyond the high bound": {MachineID: "lab-machine-1", Label: "NAS",
			Kind: ExternalKindService, ProbePort: 65536},
		"a malformed machine": {MachineID: "Lab-Machine-1", Label: "NAS", Kind: ExternalKindService, ProbePort: 5000},
	} {
		if _, _, err := store.Declare(declaration, true, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if state := store.Snapshot(); state.ExternalRevision != 0 || len(state.Elements) != 0 {
		t.Fatalf("a refused declaration reached the inventory: %+v", state)
	}

	// A machine outside the managed inventory is refused because the machine is
	// the point of view: nobody holds a viewpoint from a machine the product has
	// never enrolled.
	if _, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-9", Label: "NAS", Kind: ExternalKindService, ProbePort: 5000,
	}, false, now); err == nil {
		t.Fatal("a declaration from an unattached machine was accepted")
	}

	if _, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: 5000,
	}, true, now); err != nil {
		t.Fatal(err)
	}
	// Same machine, same port, and neither a different label nor a different kind
	// makes it a second thing: the port on that machine is the pair that must be
	// unique.
	for name, duplicate := range map[string]ExternalDeclaration{
		"the same declaration twice": {MachineID: "lab-machine-1", Label: "NAS du salon",
			Kind: ExternalKindService, ProbePort: 5000},
		"the same port under another label": {MachineID: "lab-machine-1", Label: "Autre chose",
			Kind: ExternalKindService, ProbePort: 5000},
		"the same port under another kind": {MachineID: "lab-machine-1", Label: "NAS du salon",
			Kind: ExternalKindPassage, ProbePort: 5000},
	} {
		if _, _, err := store.Declare(duplicate, true, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// The same port seen from another machine is another thing, and is accepted:
	// the machine is the point of view, so two viewpoints are two declarations.
	if _, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-2", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: 5000,
	}, true, now); err != nil {
		t.Fatalf("the same port on another machine was refused: %v", err)
	}
	if state := store.Snapshot(); len(state.Elements) != 2 {
		t.Fatalf("the inventory is not the two declarations that were accepted: %+v", state)
	}
}

// TestExternalStoreBoundsItsInventory keeps the declared inventory as bounded as
// the managed one: a second inventory is not a place to grow without a limit.
func TestExternalStoreBoundsItsInventory(t *testing.T) {
	store, _ := externalTestStore(t)
	now := externalTestTime(t, "2026-08-07T10:00:00Z")
	for index := 0; index < maxExternalElements; index++ {
		if _, _, err := store.Declare(ExternalDeclaration{
			MachineID: "lab-machine-1", Label: "Chose", Kind: ExternalKindService, ProbePort: 1024 + index,
		}, true, now); err != nil {
			t.Fatalf("declaration %d inside the bound was refused: %v", index+1, err)
		}
	}
	if _, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "Chose", Kind: ExternalKindService, ProbePort: 60000,
	}, true, now); err == nil {
		t.Fatal("a declaration beyond the inventory bound was accepted")
	}
}

// TestExternalStoreRecordsWhatAnAdapterReported exercises the seam the read-only
// adapter of the next palier writes through, including the three states, the
// closed reasons and the refusal of a reading that moves backwards in time.
func TestExternalStoreRecordsWhatAnAdapterReported(t *testing.T) {
	store, _ := externalTestStore(t)
	first := externalTestTime(t, "2026-08-07T10:00:00Z")
	element, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: 5000,
	}, true, first)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := store.RecordObservation(element.ElementID, ExternalObservation{
		State: ExternalStateVerified, ObservedAt: "2026-08-07T10:00:30Z",
	})
	if err != nil || verified.Observation == nil || verified.Observation.State != ExternalStateVerified {
		t.Fatalf("a successful reading was not recorded: %+v %v", verified, err)
	}
	contradicted, err := store.RecordObservation(element.ElementID, ExternalObservation{
		State: ExternalStateContradicted, ObservedAt: "2026-08-07T10:01:00Z",
	})
	if err != nil || contradicted.Observation.State != ExternalStateContradicted {
		t.Fatalf("a contradiction was not recorded: %+v %v", contradicted, err)
	}
	unverifiable, err := store.RecordObservation(element.ElementID, ExternalObservation{
		State: ExternalStateUnverifiable, Reason: ExternalReasonNothingListening,
		ObservedAt: "2026-08-07T10:02:00Z",
	})
	if err != nil || unverifiable.Observation.Reason != ExternalReasonNothingListening {
		t.Fatalf("an unverifiable reading lost its reason: %+v %v", unverifiable, err)
	}

	for name, reading := range map[string]ExternalObservation{
		"a state outside the closed list": {State: "probably_up", ObservedAt: "2026-08-07T10:03:00Z"},
		"a silent unverifiable":           {State: ExternalStateUnverifiable, ObservedAt: "2026-08-07T10:03:00Z"},
		"an unverifiable naming a free reason": {State: ExternalStateUnverifiable,
			Reason: "the service said no", ObservedAt: "2026-08-07T10:03:00Z"},
		"a verified reading carrying a reason": {State: ExternalStateVerified,
			Reason: ExternalReasonNothingListening, ObservedAt: "2026-08-07T10:03:00Z"},
		"a reading without a date":        {State: ExternalStateVerified},
		"a reading dated in local time":   {State: ExternalStateVerified, ObservedAt: "2026-08-07T12:03:00+02:00"},
		"a reading dated non-canonically": {State: ExternalStateVerified, ObservedAt: "2026-08-07T10:03:00.000Z"},
		"a reading older than the one held": {State: ExternalStateVerified,
			ObservedAt: "2026-08-07T10:01:59Z"},
	} {
		if _, err := store.RecordObservation(element.ElementID, reading); err == nil {
			t.Fatalf("%s was recorded", name)
		}
	}
	if _, err := store.RecordObservation("AAAAAAAAAAAAAAAAAAAAAA", ExternalObservation{
		State: ExternalStateVerified, ObservedAt: "2026-08-07T10:03:00Z",
	}); err != errExternalElementUnknown {
		t.Fatalf("a reading against an unknown declaration was recorded: %v", err)
	}
	if held := store.Snapshot().Elements[0].Observation; held.ObservedAt != "2026-08-07T10:02:00Z" {
		t.Fatalf("a refused reading replaced the one held: %+v", held)
	}
}

// TestExternalProjectionAgesOnTheOneAnnouncedLimit is the ageing proof. The
// limit is the product's single announced one, so the boundary is the same
// boundary the machines already use, and a reading this Controller cannot place
// before now is never presented as current.
func TestExternalProjectionAgesOnTheOneAnnouncedLimit(t *testing.T) {
	if observationFreshnessLimit != 90*time.Second {
		t.Fatalf("the ageing limit drifted from the announced one: %s", observationFreshnessLimit)
	}
	observedAt := "2026-08-07T10:00:00Z"
	base := externalTestTime(t, observedAt)
	for name, check := range map[string]struct {
		now      time.Time
		expected string
	}{
		"a reading taken this instant":        {base, "recent"},
		"a reading one nanosecond inside":     {base.Add(observationFreshnessLimit - time.Nanosecond), "recent"},
		"a reading exactly at the limit":      {base.Add(observationFreshnessLimit), "recent"},
		"a reading one nanosecond beyond":     {base.Add(observationFreshnessLimit + time.Nanosecond), "old"},
		"a reading long past the limit":       {base.Add(time.Hour), "old"},
		"a reading dated after the clock now": {base.Add(-time.Second), "old"},
	} {
		inventory := ExternalInventory{
			SchemaVersion: externalSchema, ControllerID: testControllerID, InfrastructureID: testInfrastructureID,
			ExternalRevision: 2,
			Elements: []ExternalElement{{
				ElementID: "AAAAAAAAAAAAAAAAAAAAAA", MachineID: "lab-machine-1", Label: "NAS du salon",
				Kind: ExternalKindService, ProbePort: 5000, DeclaredAt: observedAt,
				Observation: &ExternalObservation{State: ExternalStateVerified, ObservedAt: observedAt},
			}},
		}
		view, err := ProjectExternalElements(inventory, check.now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		projected := view.Elements[0]
		// The state does not change with age: it keeps saying what was constated,
		// and the ageing dimension is what stops presenting it as current.
		if projected.State != ExternalStateVerified || projected.ObservationStatus != check.expected {
			t.Fatalf("%s: state=%q observation_status=%q", name, projected.State, projected.ObservationStatus)
		}
	}
}

// TestExternalProjectionSaysDeclaredWhenNobodyLooked keeps the four words of the
// contract apart and refuses to infer a fourth: an element nobody read is
// declared and absent, never "probably fine".
func TestExternalProjectionSaysDeclaredWhenNobodyLooked(t *testing.T) {
	store, _ := externalTestStore(t)
	now := externalTestTime(t, "2026-08-07T10:00:00Z")
	if _, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: 5000,
	}, true, now); err != nil {
		t.Fatal(err)
	}
	view, err := ProjectExternalElements(store.Snapshot(), now)
	if err != nil {
		t.Fatal(err)
	}
	projected := view.Elements[0]
	if projected.State != ExternalStateDeclared || projected.ObservationStatus != "absent" ||
		projected.ObservedAt != nil || projected.Reason != nil {
		t.Fatalf("an unread declaration was projected as something else: %+v", projected)
	}
}

// TestExternalStoreRefusesAForeignOrCorruptDocument keeps the second inventory
// as fail-closed as the first: a document from another installation is refused,
// and a corrupt one reduces availability rather than fabricating an empty
// inventory that would silently drop what a human typed.
func TestExternalStoreRefusesAForeignOrCorruptDocument(t *testing.T) {
	store, directory := externalTestStore(t)
	if _, _, err := store.Declare(ExternalDeclaration{
		MachineID: "lab-machine-1", Label: "NAS du salon", Kind: ExternalKindService, ProbePort: 5000,
	}, true, externalTestTime(t, "2026-08-07T10:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExternalStore(directory, testControllerID, "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("an external inventory of another infrastructure was opened")
	}
	path := filepath.Join(directory, externalFileName)
	if err := os.WriteFile(path, []byte(`{"schema_version":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExternalStore(directory, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("a corrupt external inventory was opened as an empty one")
	}
}

// TestExternalInventoryCannotReachThePlanSurface is the structural proof of the
// palier that adds no plan: the two files that hold the declared inventory
// receive nothing with which to build, freeze, sign or apply a document. It is a
// property of what they import, not a discipline of review.
func TestExternalInventoryCannotReachThePlanSurface(t *testing.T) {
	for _, name := range []string{"external.go", "external_http.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			for _, forbidden := range []string{"internal/plan", "internal/approval", "internal/auxiliary"} {
				if strings.Contains(imported.Path.Value, forbidden) {
					t.Fatalf("%s imports %s: an external element must have no path to a plan", name, forbidden)
				}
			}
		}
	}
}
