package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// The package already names one pair of test identifiers, in
// `inventory_test.go`; a second pair would be a second spelling of the same
// installation.

func testDispatchRecord(digestByte byte, machine string, sequence uint64) DispatchRecord {
	return DispatchRecord{
		ApprovalSHA256: strings.Repeat(string([]byte{'0' + digestByte%10}), 64),
		MachineID:      machine,
		Operation:      "deploy_oci_probe",
		ApprovalEpoch:  1,
		Sequence:       sequence,
		PlanSHA256:     strings.Repeat("1", 64),
		RollbackSHA256: strings.Repeat("2", 64),
		State:          DispatchInFlight,
		AcceptedAtUnix: sequence,
	}
}

func newDispatchDirectory(t *testing.T) string {
	t.Helper()
	return privateTestDirectory(t)
}

// TestDispatchRegistryRequalifiesInFlightAtOpenDurably is the honesty rule of
// the store: a record cut mid-life is `launched_unreported` before anything
// is served, and the next life reads the requalification back from disk —
// never from memory.
func TestDispatchRegistryRequalifiesInFlightAtOpenDurably(t *testing.T) {
	directory := newDispatchDirectory(t)
	store, err := OpenDispatchRegistryStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(testDispatchRecord(3, "lab-machine-1", 1)); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenDispatchRegistryStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	records := reopened.Snapshot().Records
	if len(records) != 1 || records[0].State != DispatchLaunchedUnreported {
		t.Fatalf("an in-flight record must reopen launched_unreported: %+v", records)
	}

	// The requalification was written, not just returned: the raw file says
	// the same thing to a reader that never went through the store.
	data, err := os.ReadFile(filepath.Join(directory, dispatchRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	var document DispatchRegistry
	if err := strictjson.Decode(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Records) != 1 || document.Records[0].State != DispatchLaunchedUnreported {
		t.Fatalf("the requalification did not reach the disk: %+v", document.Records)
	}
}

// TestDispatchRegistryRefusesASecondConclusion holds the one-conclusion rule:
// a dispatch that concluded cannot conclude again, whatever the state.
func TestDispatchRegistryRefusesASecondConclusion(t *testing.T) {
	store, err := OpenDispatchRegistryStore(newDispatchDirectory(t), testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	record := testDispatchRecord(4, "lab-machine-1", 1)
	if err := store.Accept(record); err != nil {
		t.Fatal(err)
	}
	if err := store.Conclude(record.ApprovalSHA256, DispatchNotLaunched, "", "unreachable", 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Conclude(record.ApprovalSHA256, DispatchLaunchedUnreported, "", "", 3); err == nil {
		t.Fatal("a second conclusion was accepted")
	}
	if err := store.Conclude(strings.Repeat("9", 64), DispatchNotLaunched, "", "", 2); err == nil {
		t.Fatal("a conclusion without an open record was accepted")
	}
}

// TestDispatchRegistryBoundsTerminalHistoryPerMachine trims the oldest
// terminal records past the named bound and never an open one.
func TestDispatchRegistryBoundsTerminalHistoryPerMachine(t *testing.T) {
	store, err := OpenDispatchRegistryStore(newDispatchDirectory(t), testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxDispatchRecordsPerMachine+2; index++ {
		record := testDispatchRecord(5, "lab-machine-1", uint64(index+1))
		record.ApprovalSHA256 = uniqueDigest(index)
		if err := store.Accept(record); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			// The very first dispatch stays open: the bound must walk around
			// it, whatever grows after it.
			continue
		}
		if err := store.Conclude(record.ApprovalSHA256, DispatchNotLaunched, "", "no engine", record.AcceptedAtUnix); err != nil {
			t.Fatal(err)
		}
	}
	records := store.Snapshot().Records
	open := 0
	terminal := 0
	for _, record := range records {
		if record.State == DispatchInFlight {
			open++
		} else {
			terminal++
		}
	}
	if open != 1 {
		t.Fatalf("the open record was trimmed: %+v", records)
	}
	if terminal != maxDispatchRecordsPerMachine {
		t.Fatalf("terminal history holds %d records for a bound of %d", terminal, maxDispatchRecordsPerMachine)
	}
	if records[0].State != DispatchInFlight {
		// Oldest first: the open record was accepted first and must lead.
		t.Fatalf("the history lost its order: %+v", records[0])
	}
}

func uniqueDigest(index int) string {
	hexadecimal := "0123456789abcdef"
	prefix := string(hexadecimal[index%16]) + string(hexadecimal[(index/16)%16])
	return prefix + strings.Repeat("f", 62)
}

// TestDispatchRegistryRefusesTwoOpenRecordsForTheSameBytes holds the document
// itself against the double-spend: even a hand-written registry cannot carry
// the same signed bytes open twice.
func TestDispatchRegistryRefusesTwoOpenRecordsForTheSameBytes(t *testing.T) {
	store, err := OpenDispatchRegistryStore(newDispatchDirectory(t), testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	record := testDispatchRecord(6, "lab-machine-1", 1)
	if err := store.Accept(record); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(record); err == nil {
		t.Fatal("two open records for the same bytes were accepted")
	}
}

// TestDispatchRegistryBelongsToItsInstallation refuses a registry copied from
// another Controller: identifiers are held at open, like every state of the
// package.
func TestDispatchRegistryBelongsToItsInstallation(t *testing.T) {
	directory := newDispatchDirectory(t)
	if _, err := OpenDispatchRegistryStore(directory, testControllerID, testInfrastructureID); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDispatchRegistryStore(directory, testInfrastructureID, testControllerID); err == nil {
		t.Fatal("a registry of another installation was opened")
	}
}
