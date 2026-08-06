package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/auxiliary"
	"github.com/ldesfontaine/your-cloud/internal/plan"
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
	// The bound is the one the whole input may reach, which grew when the input
	// started carrying the two plan documents beside the approval. It is still
	// the package's own fixed constant rather than anything an argument said,
	// and each carried document still answers to its own narrower bound.
	if valid.readerLimit != auxiliary.MaxInputBytes {
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
	document, err := readBoundedInput(strings.NewReader(exact), approval.MaxSignedApprovalBytes)
	if err != nil || string(document) != exact {
		t.Fatalf("a document of exactly the bound was refused: %v", err)
	}
	for name, reader := range map[string]string{
		"empty":    "",
		"one over": strings.Repeat("a", approval.MaxSignedApprovalBytes+1),
		"far over": strings.Repeat("a", approval.MaxSignedApprovalBytes*4),
	} {
		if _, err := readBoundedInput(strings.NewReader(reader), approval.MaxSignedApprovalBytes); err == nil {
			t.Fatalf("%s document was accepted", name)
		}
	}
	if _, err := readBoundedInput(strings.NewReader("x"), 0); err == nil {
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
	// The answer a read-only diagnostic renders is the one the previous palier
	// proved: the fields an applied operation adds are simply not there, and
	// neither is the vocabulary a conclusion that acted is written in.
	for _, field := range []string{
		"plan_operation", "local_port", "unit_path", "service_state",
		"outcome", "rollback_attempted", "observed",
	} {
		if _, present := decoded[field]; present {
			t.Fatalf("a read-only diagnostic reported %q", field)
		}
	}
}

// TestTheAppliedReportStatesWhatChangedWithoutEchoingThePlan holds the report of
// a mutating operation to the same rule as the diagnostic one: it repeats what
// the machine concluded, and no field of the document it was given.
func TestTheAppliedReportStatesWhatChangedWithoutEchoingThePlan(t *testing.T) {
	t.Parallel()
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationDeployOCIProbe,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges: []string{
				approval.PrivilegeMutateLocalState,
				approval.PrivilegeReadLocalState,
			},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 2,
		},
	}
	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationDeployOCIProbe,
		LocalPort:    8080,
		UnitPath:     auxiliary.UnitPath(),
		ServiceState: auxiliary.ServiceStateActive,
		Changed:      true,
	})
	if !report.Changed {
		t.Fatal("an applied operation reported no change")
	}

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["changed"] != true || decoded["service_state"] != auxiliary.ServiceStateActive {
		t.Fatalf("the report does not state what the machine now holds: %v", decoded)
	}
	if decoded["unit_path"] != auxiliary.UnitPath() || decoded["local_port"] != float64(8080) {
		t.Fatalf("the report does not name the instance it applied: %v", decoded)
	}
	// Neither document travels back, and neither does any field of them beyond
	// the closed ones the machine itself decided.
	for _, field := range []string{"plan", "rollback", "image_reference", "image_digest", "unit"} {
		if _, present := decoded[field]; present {
			t.Fatalf("the applied report echoes %q", field)
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"changed: true", "service: active", "unit: " + auxiliary.UnitPath()} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}

	// A computed value is a value that can also be false: the same machinery
	// reports an operation that found the approved state already held.
	unchanged := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationRemoveOCIProbe,
		LocalPort:    8080,
		UnitPath:     auxiliary.UnitPath(),
		ServiceState: auxiliary.ServiceStateAbsent,
		Changed:      false,
	})
	if unchanged.Changed || unchanged.ServiceState != auxiliary.ServiceStateAbsent {
		t.Fatalf("an operation that changed nothing reported otherwise: %+v", unchanged)
	}
	if report.Outcome != auxiliary.OutcomeApplied || unchanged.Outcome != auxiliary.OutcomeApplied {
		t.Fatalf("an applied operation did not say so: %q %q", report.Outcome, unchanged.Outcome)
	}
	if report.RollbackAttempted || report.Observed != nil {
		t.Fatalf("an operation that succeeded reported a rollback: %+v", report)
	}
}

// TestAControlledFailureIsReportedAsOneAndNeverAsASuccess holds the vocabulary
// of the three conclusions apart in the answer a reader actually receives.
//
// A controlled failure states the failure, states that the approved rollback was
// attempted, and states what that attempt reached. When the rollback itself
// failed, the service state disappears from the answer — that certainty is
// exactly what was lost — and what replaces it is the list of what could still
// be read, and nothing more.
func TestAControlledFailureIsReportedAsOneAndNeverAsASuccess(t *testing.T) {
	t.Parallel()
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationDeployOCIProbe,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges: []string{
				approval.PrivilegeMutateLocalState,
				approval.PrivilegeReadLocalState,
			},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 3,
		},
	}

	rolledBack := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation: approval.OperationDeployOCIProbe,
		LocalPort: 8080,
		UnitPath:  auxiliary.UnitPath(),
		Outcome:   auxiliary.OutcomeRolledBack,
		Cause:     errors.New("the probe never answered"),
	})
	if rolledBack.Outcome != auxiliary.OutcomeRolledBack || !rolledBack.RollbackAttempted {
		t.Fatalf("the rollback was not reported as attempted: %+v", rolledBack)
	}
	// A failure that reached the rollback is a failure that had already changed
	// this machine, and it never reads as an operation that did nothing.
	if !rolledBack.Changed {
		t.Fatalf("a controlled failure reported that nothing changed: %+v", rolledBack)
	}
	if rolledBack.ServiceState != "" || rolledBack.Observed != nil {
		t.Fatalf("a rollback that succeeded claimed more than it reached: %+v", rolledBack)
	}

	partial := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation: approval.OperationDeployOCIProbe,
		LocalPort: 8080,
		UnitPath:  auxiliary.UnitPath(),
		Outcome:   auxiliary.OutcomePartial,
		Cause:     errors.New("the probe never answered"),
		Rollback:  errors.New("the sheet could not be removed"),
		Observed: &auxiliary.Observation{
			Account:   "present",
			UnitFile:  "present",
			Service:   "unknown",
			Container: "none",
		},
	})

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", partial); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["outcome"] != auxiliary.OutcomePartial || decoded["rollback_attempted"] != true {
		t.Fatalf("the partial state was not reported as one: %v", decoded)
	}
	if _, present := decoded["service_state"]; present {
		t.Fatalf("a partial state claimed a service state: %v", decoded)
	}
	observed, ok := decoded["observed"].(map[string]any)
	if !ok || observed["service"] != "unknown" || observed["unit_file"] != "present" {
		t.Fatalf("the report does not say what was observed: %v", decoded)
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", partial); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"outcome: " + auxiliary.OutcomePartial,
		"rollback attempted: true",
		"observed service: unknown",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}
	if strings.Contains(text.String(), "service: ") && !strings.Contains(text.String(), "observed service: ") {
		t.Fatalf("a partial state rendered a service line: %q", text.String())
	}
}

// TestAManagedWebServiceIsReportedInTheSameClosedVocabulary holds the answer a
// reader receives when the operation is one of the managed web service pair
// rather than one of the probe pair.
//
// The vocabulary does not widen with the operations: the same closed outcome
// words, the same closed fields, and still no field of any plan echoed back. The
// only things that differ are the ones the machine itself decided — which
// operation ran and where its sheet was written.
func TestAManagedWebServiceIsReportedInTheSameClosedVocabulary(t *testing.T) {
	t.Parallel()
	unitPath, known := auxiliary.ServiceUnitPath(plan.ServiceProfileBentoPDF)
	if !known {
		t.Fatal("the one service profile of this palier names no sheet")
	}
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationDeployWebService,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges: []string{
				approval.PrivilegeMutateLocalState,
				approval.PrivilegeReadLocalState,
			},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 4,
		},
	}

	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationDeployWebService,
		LocalPort:    8080,
		UnitPath:     unitPath,
		ServiceState: auxiliary.ServiceStateActive,
		Changed:      true,
	})
	if report.Outcome != auxiliary.OutcomeApplied || !report.Changed {
		t.Fatalf("an applied service operation did not say so: %+v", report)
	}
	if report.PlanOperation != approval.OperationDeployWebService || report.UnitPath != unitPath {
		t.Fatalf("the report does not name the service instance it applied: %+v", report)
	}

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["plan_operation"] != approval.OperationDeployWebService || decoded["unit_path"] != unitPath {
		t.Fatalf("the report does not name the instance it applied: %v", decoded)
	}
	// The profile, the image and the digest a service plan carries for a human
	// to read do not travel back: the report is what the machine concluded.
	for _, field := range []string{"plan", "rollback", "service_profile", "image_reference", "image_digest"} {
		if _, present := decoded[field]; present {
			t.Fatalf("the applied report echoes %q", field)
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"plan operation: " + approval.OperationDeployWebService,
		"unit: " + unitPath,
		"outcome: " + auxiliary.OutcomeApplied,
		"service: active",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}

	// A removal that found the state already held reads the same way, with the
	// one word that separates an operation which acted from one which did not.
	unchanged := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationRemoveWebService,
		LocalPort:    8080,
		UnitPath:     unitPath,
		ServiceState: auxiliary.ServiceStateAbsent,
		Changed:      false,
	})
	if unchanged.Changed || unchanged.Outcome != auxiliary.OutcomeApplied {
		t.Fatalf("a service operation that changed nothing reported otherwise: %+v", unchanged)
	}

	// And a controlled failure of a service operation carries the very same
	// outcome words as a controlled failure of the probe.
	failed := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation: approval.OperationDeployWebService,
		LocalPort: 8080,
		UnitPath:  unitPath,
		Outcome:   auxiliary.OutcomeRolledBack,
		Cause:     errors.New("the service never answered"),
	})
	if failed.Outcome != auxiliary.OutcomeRolledBack || !failed.RollbackAttempted || !failed.Changed {
		t.Fatalf("a controlled service failure was not reported as one: %+v", failed)
	}
	if failed.ServiceState != "" || failed.Observed != nil {
		t.Fatalf("a rollback that succeeded claimed more than it reached: %+v", failed)
	}
}

// TestTheEntrypointIsReportedWithoutInventingAValueItsPlanDoesNotCarry holds the
// answer a reader receives for the public entrypoint.
//
// An entrypoint plan carries no port and no host, so its report names neither: a
// local port line would be a value nobody approved, and a route line would be a
// claim about something this operation never touched. What it does name is the
// sheet it wrote and the state the machine now holds, in the very words a probe
// and a managed service are already reported in.
func TestTheEntrypointIsReportedWithoutInventingAValueItsPlanDoesNotCarry(t *testing.T) {
	t.Parallel()
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationDeployEntrypoint,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges: []string{
				approval.PrivilegeMutateLocalState,
				approval.PrivilegeReadLocalState,
			},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 5,
		},
	}
	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationDeployEntrypoint,
		UnitPath:     auxiliary.EntrypointUnitPath(),
		ServiceState: auxiliary.ServiceStateActive,
		Changed:      true,
	})
	if report.Outcome != auxiliary.OutcomeApplied || !report.Changed {
		t.Fatalf("an applied entrypoint operation did not say so: %+v", report)
	}

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["unit_path"] != auxiliary.EntrypointUnitPath() {
		t.Fatalf("the report does not name the entry it applied: %v", decoded)
	}
	for _, field := range []string{
		"local_port", "route_host", "fragment_path",
		"plan", "rollback", "image_reference", "image_digest",
	} {
		if _, present := decoded[field]; present {
			t.Fatalf("the entrypoint report carries %q", field)
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"plan operation: " + approval.OperationDeployEntrypoint,
		"unit: " + auxiliary.EntrypointUnitPath(),
		"service: active",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}
	if strings.Contains(text.String(), "route: ") || strings.Contains(text.String(), "fragment: ") {
		t.Fatalf("the entrypoint report named a route: %q", text.String())
	}
}

// TestAPublishedRouteIsReportedByItsNameAndItsFragmentAndNothingElse holds the
// answer a reader receives for a route.
//
// The two things it names are the declared host and the one file that host owns.
// What it must never name is anything about the certificate of that host: the
// key and the certificate are read from a directory this Auxiliary never writes,
// and a report of this product carries the machine's conclusions rather than the
// material it read.
func TestAPublishedRouteIsReportedByItsNameAndItsFragmentAndNothingElse(t *testing.T) {
	t.Parallel()
	const host = "lab.example.test"
	fragment := auxiliary.EntrypointFragmentDirectory() + "/" + host + ".yaml"
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationPublishRoute,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges: []string{
				approval.PrivilegeMutateLocalState,
				approval.PrivilegeReadLocalState,
			},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 6,
		},
	}
	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationPublishRoute,
		RouteHost:    host,
		FragmentPath: fragment,
		ServiceState: auxiliary.ServiceStateActive,
		Changed:      true,
	})

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["route_host"] != host || decoded["fragment_path"] != fragment {
		t.Fatalf("the report does not name the route it published: %v", decoded)
	}
	// A route has no sheet and no loopback port of its own, and nothing of a
	// certificate ever reaches this answer.
	for _, field := range []string{
		"unit_path", "local_port", "certificate", "cert_file", "key_file",
		"private_key", "plan", "rollback",
	} {
		if _, present := decoded[field]; present {
			t.Fatalf("the route report carries %q", field)
		}
	}
	for _, secret := range []string{"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", ".key", ".crt"} {
		if strings.Contains(rendered.String(), secret) {
			t.Fatalf("the route report carries certificate material: %q", rendered.String())
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"plan operation: " + approval.OperationPublishRoute,
		"route: " + host,
		"fragment: " + fragment,
		"service: active",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}

	// A retirement that found the name already unserved reads the same way, with
	// the one word that separates an operation which acted from one which did
	// not.
	unchanged := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationRetireRoute,
		RouteHost:    host,
		FragmentPath: fragment,
		ServiceState: auxiliary.ServiceStateAbsent,
		Changed:      false,
	})
	if unchanged.Changed || unchanged.Outcome != auxiliary.OutcomeApplied {
		t.Fatalf("a route operation that changed nothing reported otherwise: %+v", unchanged)
	}

	// And a controlled failure of a route carries the same outcome words as every
	// other, plus the fifth observed word only a route has.
	failed := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation:    approval.OperationPublishRoute,
		RouteHost:    host,
		FragmentPath: fragment,
		Outcome:      auxiliary.OutcomePartial,
		Cause:        errors.New("the entrypoint never served this name"),
		Rollback:     errors.New("the fragment could not be removed"),
		Observed: &auxiliary.Observation{
			Account:   "present",
			UnitFile:  "present",
			Service:   "active",
			Container: "pinned",
			Fragment:  "present",
		},
	})
	var partial bytes.Buffer
	if err := renderAuxiliaryReport(&partial, "text", failed); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"outcome: " + auxiliary.OutcomePartial,
		"rollback attempted: true",
		"observed fragment: present",
		"route: " + host,
	} {
		if !strings.Contains(partial.String(), line) {
			t.Fatalf("the partial route state does not state %q: %q", line, partial.String())
		}
	}
}

// TestTheObservedFragmentIsAbsentFromEveryAnswerThatIsNotARoute keeps the fifth
// observed word from becoming noise on the four operations that have no
// fragment: an observation says what was seen, and a word about something the
// operation never touched would be neither a fact nor an admission.
func TestTheObservedFragmentIsAbsentFromEveryAnswerThatIsNotARoute(t *testing.T) {
	t.Parallel()
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationDeployOCIProbe,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges:     []string{approval.PrivilegeMutateLocalState, approval.PrivilegeReadLocalState},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 7,
		},
	}
	report := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation: approval.OperationDeployOCIProbe,
		LocalPort: 8080,
		UnitPath:  auxiliary.UnitPath(),
		Outcome:   auxiliary.OutcomePartial,
		Cause:     errors.New("the probe never answered"),
		Rollback:  errors.New("the sheet could not be removed"),
		Observed: &auxiliary.Observation{
			Account:   "present",
			UnitFile:  "present",
			Service:   "inactive",
			Container: "none",
		},
	})
	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	observed, ok := decoded["observed"].(map[string]any)
	if !ok {
		t.Fatalf("the report says nothing about what was observed: %v", decoded)
	}
	if _, present := observed["fragment"]; present {
		t.Fatalf("a probe's observation claimed something about a fragment: %v", observed)
	}
	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "observed fragment") {
		t.Fatalf("a probe's text observation named a fragment: %q", text.String())
	}
}
