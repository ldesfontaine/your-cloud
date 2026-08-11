package controller

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/auxiliaryreport"
)

func machineReport() auxiliaryreport.Report {
	record := reportedRecord()
	return auxiliaryreport.Report{
		SchemaVersion:    1,
		Operation:        record.Operation,
		InfrastructureID: testInfrastructureID,
		MachineID:        record.MachineID,
		ApprovalEpoch:    record.ApprovalEpoch,
		ConsumedSequence: record.Sequence,
		PlanSHA256:       record.PlanSHA256,
		RollbackSHA256:   record.RollbackSHA256,
		Privileges:       []string{"mutate_local_state"},
		Outcome:          auxiliaryreport.OutcomeApplied,
		Changed:          true,
	}
}

func rendered(t *testing.T, report auxiliaryreport.Report) []byte {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestAReportThatNamesThisDispatchIsWhatMakesItReported is the nominal read of
// the fifth link: a valid report is the only thing that turns a launch into a
// conclusion, and what the record keeps from it is what the machine decided.
func TestAReportThatNamesThisDispatchIsWhatMakesItReported(t *testing.T) {
	concluded := concludeLaunch(reportedRecord(), testInfrastructureID, commandResult{
		WroteStandardInput: true, StandardOutput: rendered(t, machineReport()),
	}, maxDispatchMachineSentenceBytes)

	if concluded.State != DispatchReported {
		t.Fatalf("a valid report did not conclude the dispatch: %+v", concluded)
	}
	if !concluded.ReportedChanged || concluded.ReportedOutcome != auxiliaryreport.OutcomeApplied {
		t.Fatalf("the record kept nothing of what the machine decided: %+v", concluded)
	}
	// A conclusion read from a report carries no sentence of its own: the error
	// channel of a machine that concluded is noise, and storing it beside a
	// conclusion would make a success look like it had something to say.
	if concluded.MachineSentence != "" || concluded.ControllerObservation != "" {
		t.Fatalf("a reported dispatch carries a statement it should not: %+v", concluded)
	}
}

// TestAForgedReportIsDiscardedAndTheDispatchStaysUnknown walks the contract's
// refusal table. The property that matters is the same in every row: a report
// that got one of these wrong is not weaker evidence about this launch, it is
// evidence about something else — so it is discarded, and the dispatch stays
// `lancé, non rapporté` rather than becoming a success nobody established.
func TestAForgedReportIsDiscardedAndTheDispatchStaysUnknown(t *testing.T) {
	for name, forge := range map[string]func(auxiliaryreport.Report) auxiliaryreport.Report{
		"another infrastructure": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.InfrastructureID = "22222222-2222-4222-8222-222222222222"
			return r
		},
		"another machine": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.MachineID = "lab-machine-2"
			return r
		},
		"another operation": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.Operation = "remove_oci_probe"
			return r
		},
		"another consumed sequence": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.ConsumedSequence = 8
			return r
		},
		"another epoch": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.ApprovalEpoch = 2
			return r
		},
		"another plan": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.PlanSHA256 = strings.Repeat("d", 64)
			return r
		},
		"another rollback": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.RollbackSHA256 = strings.Repeat("d", 64)
			return r
		},
		"an outcome nobody named": func(r auxiliaryreport.Report) auxiliaryreport.Report {
			r.Outcome = "everything_went_fine_trust_me"
			return r
		},
	} {
		concluded := concludeLaunch(reportedRecord(), testInfrastructureID, commandResult{
			WroteStandardInput: true, StandardOutput: rendered(t, forge(machineReport())),
		}, maxDispatchMachineSentenceBytes)

		if concluded.State != DispatchLaunchedUnreported {
			t.Fatalf("%s: the dispatch became %s", name, concluded.State)
		}
		if concluded.ReportedChanged || concluded.ReportedOutcome != "" {
			t.Fatalf("%s: a discarded report still left a conclusion: %+v", name, concluded)
		}
		// The reason is this Controller's own observation, never quoted as the
		// machine's sentence: a reader must be able to tell which he is reading.
		if concluded.ControllerObservation == "" || concluded.MachineSentence != "" {
			t.Fatalf("%s: %+v", name, concluded)
		}
	}
}

// TestAnAnswerThatIsNotAReportIsNotAConclusion: an unreadable document, an
// empty answer, a document carrying a field this Controller does not read and
// one past the bound all leave the same honest weaker state.
func TestAnAnswerThatIsNotAReportIsNotAConclusion(t *testing.T) {
	for name, answer := range map[string][]byte{
		"nothing at all":         nil,
		"a document that is not": []byte("not json at all"),
		"an unknown field":       []byte(`{"schema_version":1,"surprise":true}`),
		"a document past the bound": append([]byte(`{"schema_version":1,"machine_id":"`),
			append([]byte(strings.Repeat("x", maxCommandReportBytes)), []byte(`"}`)...)...),
	} {
		if _, err := ingestReport(reportedRecord(), testInfrastructureID, answer); err == nil {
			t.Fatalf("%s was read as a report", name)
		}
	}
}

// TestAReadOnlyDiagnosticConcludesWithoutNamingAnOutcome: the one honest gap in
// the vocabulary. A diagnostic changes nothing and names no outcome, and the
// record says so rather than inventing a word the machine did not write.
func TestAReadOnlyDiagnosticConcludesWithoutNamingAnOutcome(t *testing.T) {
	report := machineReport()
	report.Outcome = ""
	report.Changed = false

	changed, outcome, err := reportedConclusion(report)
	if err != nil || changed || outcome != "" {
		t.Fatalf("a diagnostic: changed=%v outcome=%q err=%v", changed, outcome, err)
	}
}

// TestOnlyTheReportPackageDefinesTheReport is the DRY rule of this trajectory
// made executable: the Controller reads the very document the machine writes,
// and neither side holds a second definition of it.
func TestOnlyTheReportPackageDefinesTheReport(t *testing.T) {
	if _, err := ingestReport(reportedRecord(), testInfrastructureID,
		rendered(t, machineReport())); err != nil {
		t.Fatalf("the Controller cannot read the document the machine renders: %v", err)
	}
}

// TestTheCommandPositionIsUncertainAfterALaunchNobodyReported is decision 3
// made executable on the reading side: the Console learns the successor it must
// sign, and it learns just as plainly when this Controller cannot vouch for it.
func TestTheCommandPositionIsUncertainAfterALaunchNobodyReported(t *testing.T) {
	directory := newDispatchDirectory(t)
	store, err := OpenDispatchRegistryStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	// A Controller that knows nothing attests nothing, and says so without
	// pretending the machine consumed nothing.
	if sequence, certain := store.CommandPosition("lab-machine-1"); sequence != 0 || !certain {
		t.Fatalf("an empty registry: sequence=%d certain=%v", sequence, certain)
	}

	reported := testDispatchRecord(1, "lab-machine-1", 4)
	if err := store.Accept(reported); err != nil {
		t.Fatal(err)
	}
	if err := store.Conclude(reported.ApprovalSHA256,
		DispatchConclusion{State: DispatchReported, ReportedChanged: true}, 5); err != nil {
		t.Fatal(err)
	}
	if sequence, certain := store.CommandPosition("lab-machine-1"); sequence != 4 || !certain {
		t.Fatalf("after a report: sequence=%d certain=%v", sequence, certain)
	}

	// A launch nobody reported: the position stays what was last reported, and
	// stops being certain. Nothing here retries, and nothing guesses.
	unknown := testDispatchRecord(2, "lab-machine-1", 5)
	if err := store.Accept(unknown); err != nil {
		t.Fatal(err)
	}
	if err := store.Conclude(unknown.ApprovalSHA256,
		DispatchConclusion{State: DispatchLaunchedUnreported, ControllerObservation: "the channel closed"},
		6); err != nil {
		t.Fatal(err)
	}
	if sequence, certain := store.CommandPosition("lab-machine-1"); sequence != 4 || certain {
		t.Fatalf("after a launch nobody reported: sequence=%d certain=%v", sequence, certain)
	}

	// A refusal by the machine and a launch that never left keep the position
	// certain: both mean the machine consumed nothing, and this Controller
	// either observed it or was told so in the machine's own words.
	for _, harmless := range []DispatchConclusion{
		{State: DispatchNotLaunched, ControllerObservation: "the host key changed"},
		{State: DispatchMachineRefused, MachineSentence: "sequence 9 is not the exact successor of 4"},
	} {
		fresh := newDispatchDirectory(t)
		clean, err := OpenDispatchRegistryStore(fresh, testControllerID, testInfrastructureID)
		if err != nil {
			t.Fatal(err)
		}
		record := testDispatchRecord(3, "lab-machine-2", 2)
		if err := clean.Accept(record); err != nil {
			t.Fatal(err)
		}
		if err := clean.Conclude(record.ApprovalSHA256, harmless, 3); err != nil {
			t.Fatal(err)
		}
		if _, certain := clean.CommandPosition("lab-machine-2"); !certain {
			t.Fatalf("%s left the position uncertain", harmless.State)
		}
	}
}

// TestARecordNamesTheRevisionItsDoorPins is the decision the Services view
// rests on, made executable: the revision comes from the approved plan, the
// fact that an instance runs it comes from the report, and the two are never
// merged into one claim.
//
// A record of a user-service door must name its revision; a record of any other
// door must name none. The pairing is refused in both directions by the
// document itself, so a projection reading it cannot find a half-named one.
func TestARecordNamesTheRevisionItsDoorPins(t *testing.T) {
	base := reportedRecord()
	base.State = DispatchNotLaunched
	base.FinishedAtUnix = 2

	for name, shape := range map[string]struct {
		record   DispatchRecord
		accepted bool
	}{
		"a user-service door naming its revision": {
			record: func() DispatchRecord {
				record := base
				record.Operation = "deploy_user_service"
				record.DefinitionSlug = "service-de-notes"
				record.DefinitionSHA256 = strings.Repeat("d", 64)
				return record
			}(),
			accepted: true,
		},
		"a user-service door naming none": {
			record: func() DispatchRecord {
				record := base
				record.Operation = "remove_user_service"
				return record
			}(),
		},
		"a user-service door with a digest that is not one": {
			record: func() DispatchRecord {
				record := base
				record.Operation = "deploy_user_service"
				record.DefinitionSlug = "service-de-notes"
				record.DefinitionSHA256 = "pas-une-empreinte"
				return record
			}(),
		},
		"another door naming a revision": {
			record: func() DispatchRecord {
				record := base
				record.DefinitionSlug = "service-de-notes"
				record.DefinitionSHA256 = strings.Repeat("d", 64)
				return record
			}(),
		},
		"another door naming none": {record: base, accepted: true},
	} {
		err := validateDispatchRegistry(DispatchRegistry{
			SchemaVersion:    dispatchRegistrySchema,
			ControllerID:     testControllerID,
			InfrastructureID: testInfrastructureID,
			Records:          []DispatchRecord{shape.record},
		})
		if shape.accepted != (err == nil) {
			t.Fatalf("%s: accepted=%v err=%v", name, shape.accepted, err)
		}
	}
}
