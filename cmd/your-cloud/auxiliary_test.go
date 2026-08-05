package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
)

func TestAuxiliaryAcceptsOnlyItsOwnBoundedSubject(t *testing.T) {
	t.Parallel()
	valid, err := parseAuxiliaryArguments([]string{"approve"})
	if err != nil {
		t.Fatalf("the nominal subject was refused: %v", err)
	}
	// No argument may point the trust of this machine anywhere: both paths are
	// the fixed ones of the package, whatever was typed.
	if valid.anchorPath != approval.AnchorPath || valid.stateDir != approval.StateDirectory {
		t.Fatalf("the auxiliary read its paths from its arguments: %+v", valid)
	}
	if valid.readerLimit != approval.MaxSignedApprovalBytes {
		t.Fatalf("the auxiliary did not bound its input: %+v", valid)
	}
	if _, err := parseAuxiliaryArguments([]string{"approve", "--format=json"}); err != nil {
		t.Fatalf("the json format was refused: %v", err)
	}

	for _, arguments := range [][]string{
		nil,
		{"observation"},
		{"approve", "unexpected"},
		{"approve", "--format=yaml"},
		{"approve", "--anchor=/tmp/forged.json"},
		{"approve", "--state-dir=/tmp/forged"},
		{"approve", "--machine-id=lab-machine-1"},
	} {
		if _, err := parseAuxiliaryArguments(arguments); err == nil {
			t.Fatalf("unsafe auxiliary arguments accepted: %q", arguments)
		}
	}
}

func TestAuxiliaryRequiresLocalRootAuthority(t *testing.T) {
	t.Parallel()
	if err := requireAuxiliaryAdministrator(0); err != nil {
		t.Fatalf("root authority was refused: %v", err)
	}
	for _, identifier := range []int{1, 1000, 65534} {
		if err := requireAuxiliaryAdministrator(identifier); err == nil {
			t.Fatalf("the auxiliary ran as uid %d", identifier)
		}
	}
}

// TestTheApprovalIsBoundedBeforeItIsParsed refuses a longer document instead of
// truncating it into a shorter, differently signed one.
func TestTheApprovalIsBoundedBeforeItIsParsed(t *testing.T) {
	t.Parallel()
	exact := strings.Repeat("a", approval.MaxSignedApprovalBytes)
	document, err := readBoundedApproval(strings.NewReader(exact), approval.MaxSignedApprovalBytes)
	if err != nil || string(document) != exact {
		t.Fatalf("a document of exactly the bound was refused: %v", err)
	}
	for name, reader := range map[string]string{
		"empty":    "",
		"one over": strings.Repeat("a", approval.MaxSignedApprovalBytes+1),
		"far over": strings.Repeat("a", approval.MaxSignedApprovalBytes*4),
	} {
		if _, err := readBoundedApproval(strings.NewReader(reader), approval.MaxSignedApprovalBytes); err == nil {
			t.Fatalf("%s document was accepted", name)
		}
	}
	if _, err := readBoundedApproval(strings.NewReader("x"), 0); err == nil {
		t.Fatal("a non-positive bound was accepted")
	}
}

// TestTheAuxiliaryReportAnnouncesNoChange keeps this palier from ever reading
// as a first real action: `changed` is false and there is no field in which a
// mutation could be reported.
func TestTheAuxiliaryReportAnnouncesNoChange(t *testing.T) {
	t.Parallel()
	report := buildAuxiliaryReport(&approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationDiagnoseProtocolReadOnly,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges:     []string{approval.PrivilegeReadLocalState},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 1,
		},
	})
	if report.Changed {
		t.Fatal("this palier reported a change")
	}

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["changed"] != false {
		t.Fatalf("the reported change is not false: %v", decoded["changed"])
	}
	if _, present := decoded["plan"]; present {
		t.Fatal("the report carries the plan itself rather than its digest")
	}
	if decoded["consumed_sequence"] != float64(1) {
		t.Fatalf("the report does not name the sequence it spent: %v", decoded)
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "changed: false") {
		t.Fatalf("the text report does not state that nothing changed: %q", text.String())
	}
}
