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

// TestALinkRouteIsReportedByWhatCarriesItAndNeverAsAFalseSuccess is the answer a
// reader receives for a name published through the private passage.
//
// It names itself exactly as a local route does — one declared name, one fragment
// — and adds one line no other operation has: what the name was resting on. That
// line exists because the failure of the passage must never be silent. A
// retirement run on a machine whose tunnel has fallen says so, so a human learns
// it from the answer rather than from a name that had stopped working, and the
// partial state after a failed rollback carries the word this vocabulary gained
// for it.
func TestALinkRouteIsReportedByWhatCarriesItAndNeverAsAFalseSuccess(t *testing.T) {
	t.Parallel()
	const host = "vault.lab.your-cloud.test"
	fragment := auxiliary.EntrypointFragmentDirectory() + "/" + host + ".yaml"
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationPublishLinkRoute,
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
			ConsumedSequence: 9,
		},
	}
	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationPublishLinkRoute,
		RouteHost:    host,
		FragmentPath: fragment,
		ServiceState: auxiliary.ServiceStateActive,
		PassageState: auxiliary.ServiceStateActive,
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
	if decoded["route_host"] != host || decoded["fragment_path"] != fragment ||
		decoded["passage_state"] != auxiliary.ServiceStateActive {
		t.Fatalf("the report does not name the route it published or what carries it: %v", decoded)
	}
	// It has no sheet, no loopback port, no key and nothing of the peer: the
	// address the fragment reaches is a constant of the contract and not a
	// conclusion of this machine.
	for _, field := range []string{
		"unit_path", "local_port", "link_public_key", "peer_public_key",
		"backend", "data_path", "plan", "rollback",
	} {
		if _, present := decoded[field]; present {
			t.Fatalf("the link route report carries %q", field)
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"plan operation: " + approval.OperationPublishLinkRoute,
		"route: " + host,
		"fragment: " + fragment,
		"passage: active",
		"service: active",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}

	// A retirement on a machine whose junction is gone says exactly that, and says
	// it beside a retirement that succeeded: the name is silenced, the passage was
	// not there, and nothing here reads as a repair.
	panned := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:    approval.OperationRetireLinkRoute,
		RouteHost:    host,
		FragmentPath: fragment,
		ServiceState: auxiliary.ServiceStateAbsent,
		PassageState: auxiliary.ServiceStateAbsent,
		Changed:      true,
	})
	var silenced bytes.Buffer
	if err := renderAuxiliaryReport(&silenced, "text", panned); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"service: absent", "passage: absent"} {
		if !strings.Contains(silenced.String(), line) {
			t.Fatalf("the retirement over a fallen passage does not state %q: %q", line, silenced.String())
		}
	}

	// And the partial state after a rollback that failed in its turn carries the
	// word for a name this machine publishes and nothing carries.
	failed := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation:    approval.OperationRetireLinkRoute,
		RouteHost:    host,
		FragmentPath: fragment,
		Outcome:      auxiliary.OutcomePartial,
		Cause:        errors.New("the fragment could not be removed"),
		Rollback:     errors.New("this machine holds no junction on yc-link0"),
		Observed: &auxiliary.Observation{
			Account:   "present",
			UnitFile:  "present",
			Service:   "active",
			Container: "pinned",
			Fragment:  "unbacked",
			LinkPeer:  "absent",
		},
	})
	var partial bytes.Buffer
	if err := renderAuxiliaryReport(&partial, "text", failed); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"outcome: " + auxiliary.OutcomePartial,
		"rollback attempted: true",
		"observed fragment: unbacked",
		"observed link peer: absent",
	} {
		if !strings.Contains(partial.String(), line) {
			t.Fatalf("the partial link route state does not state %q: %q", line, partial.String())
		}
	}
	// A failure reports no state of the passage: what was known stopped being
	// known, and the observation replaces it without pretending to be it.
	if strings.Contains(partial.String(), "passage: ") {
		t.Fatalf("a failed link route operation still claimed a state of the passage: %q", partial.String())
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

// TestThePassageIsReportedByItsPublicKeyAndNeverByAnythingPrivate holds the
// answer a reader receives for one side of the private passage.
//
// One value of that palier travels and exactly one: the public half of the key
// the prepared machine holds, which the Controller reads here as an observation
// and carries, readable, into the junction plan of the other machine. Its
// private half is born on that machine and never leaves it, so no field of this
// report can carry one — which is what the closed field list below is checked
// against.
func TestThePassageIsReportedByItsPublicKeyAndNeverByAnythingPrivate(t *testing.T) {
	t.Parallel()
	const publicKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationPrepareLink,
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
			ConsumedSequence: 7,
		},
	}
	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:     approval.OperationPrepareLink,
		UnitPath:      auxiliary.LinkNetdevPath(),
		LinkPublicKey: publicKey,
		ServiceState:  auxiliary.ServiceStateActive,
		Changed:       true,
	})

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["link_public_key"] != publicKey {
		t.Fatalf("the report does not carry the public key the machine established: %v", decoded)
	}
	if decoded["unit_path"] != auxiliary.LinkNetdevPath() {
		t.Fatalf("the report does not name the file the passage owns: %v", decoded)
	}
	// A passage has no loopback port, no declared name and no fragment, and no
	// report of this product has ever had a field for a private key.
	for _, field := range []string{
		"local_port", "route_host", "fragment_path",
		"link_private_key", "private_key", "plan", "rollback",
	} {
		if _, present := decoded[field]; present {
			t.Fatalf("the passage report carries %q", field)
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"plan operation: " + approval.OperationPrepareLink,
		"unit: " + auxiliary.LinkNetdevPath(),
		"link public key: " + publicKey,
		"service: active",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}
	if strings.Contains(text.String(), "route: ") || strings.Contains(text.String(), "fragment: ") {
		t.Fatalf("the passage report named a route: %q", text.String())
	}
}

// TestAPassageLeftPartialIsObservedInItsOwnWordsAndNeverByAKeysValue holds the
// other end of the same rule.
//
// A rollback that failed took away the certainty of what this machine holds, and
// what replaces it is a list of what could still be read. For a passage that
// list is a description, a key, an interface and a peer — not an account and a
// container it never had — and the key appears in it as present or absent and
// never as a value, because what a key is is not something a report of this
// product may see.
func TestAPassageLeftPartialIsObservedInItsOwnWordsAndNeverByAKeysValue(t *testing.T) {
	t.Parallel()
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationPrepareLink,
			PlanSHA256:     strings.Repeat("0", 64),
			RollbackSHA256: strings.Repeat("1", 64),
			Privileges:     []string{approval.PrivilegeMutateLocalState},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",
			MachineID:        "lab-machine-1",
			ApprovalEpoch:    1,
			ConsumedSequence: 8,
		},
	}
	report := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation: approval.OperationPrepareLink,
		UnitPath:  auxiliary.LinkNetdevPath(),
		Outcome:   auxiliary.OutcomePartial,
		Cause:     errors.New("the manager would not read it"),
		Rollback:  errors.New("and would not forget it either"),
		Observed: &auxiliary.Observation{
			UnitFile:      "absent",
			LinkKey:       "present",
			LinkInterface: "inactive",
			LinkPeer:      "absent",
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
	if !ok || observed["link_key"] != "present" || observed["unit_file"] != "absent" {
		t.Fatalf("the report does not say what the passage was left holding: %v", decoded)
	}
	// The four words of a service are absent rather than admitted unknown: a
	// passage has no account and no container, so nobody looked at either.
	for _, word := range []string{"account", "service", "container", "fragment"} {
		if _, present := observed[word]; present {
			t.Fatalf("a passage was observed as if it had a %s: %v", word, observed)
		}
	}
	if _, present := observed["link_private_key"]; present {
		t.Fatalf("an observation carried private material: %v", observed)
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"observed unit file: absent",
		"observed link key: present",
		"observed link interface: inactive",
		"observed link peer: absent",
		"rollback attempted: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}
	if strings.Contains(text.String(), "observed account") || strings.Contains(text.String(), "observed container") {
		t.Fatalf("a passage was reported as if it had an account: %q", text.String())
	}
}

// TestAPrivateServiceIsReportedByItsDataAndNeverByItsContents holds the answer
// the data-bearing profile added, and the line it added for a reason.
//
// A removal of this product takes the service away and keeps the data. A report
// that said only "absent" would leave a reader to guess which of the two happened
// to their vault, so the durable directory is named in both directions — after a
// deployment it is where the data lives, after a removal it is what this machine
// still holds — and the archives that survived are named beside it.
func TestAPrivateServiceIsReportedByItsDataAndNeverByItsContents(t *testing.T) {
	t.Parallel()
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationRemovePrivateService,
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
			ConsumedSequence: 9,
		},
	}
	unitPath, known := auxiliary.ServiceUnitPath(plan.ServiceProfileVaultwarden)
	if !known {
		t.Fatal("the private profile names no sheet")
	}
	report := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:     approval.OperationRemovePrivateService,
		LocalPort:     8080,
		UnitPath:      unitPath,
		DataPath:      auxiliary.VaultwardenDataDirectory,
		SnapshotSlots: []string{"nightly"},
		ServiceState:  auxiliary.ServiceStateAbsent,
		Changed:       true,
	})

	var rendered bytes.Buffer
	if err := renderAuxiliaryReport(&rendered, "json", report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["data_path"] != auxiliary.VaultwardenDataDirectory {
		t.Fatalf("the removal report does not name the data it kept: %v", decoded)
	}
	// A removal writes no archive, so it reports no digest, no instant and no slot
	// it acted on: a report says what happened.
	for _, field := range []string{
		"archive_sha256", "archived_at", "snapshot_slot", "previous_slot",
		"route_host", "fragment_path", "link_public_key",
	} {
		if _, present := decoded[field]; present {
			t.Fatalf("the private service report carries %q", field)
		}
	}

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"plan operation: " + approval.OperationRemovePrivateService,
		"data: " + auxiliary.VaultwardenDataDirectory,
		"snapshots held: [nightly]",
		"service: absent",
		"changed: true",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the text report does not state %q: %q", line, text.String())
		}
	}
}

// TestAnArchiveIsReportedByItsDigestAndTheReturnByBothItsSlots is the other half
// of the same answer.
//
// A snapshot reports the slot it wrote, the digest of the bytes and the instant
// — three facts the machine established, none of them a value a human could have
// approved in advance, which is why the plan of a snapshot carries no digest at
// all. A return reports one thing more: the reserved slot now holds the state it
// replaced, which is the document that undoes it, readable in the report of the
// operation it undoes.
//
// What is never reported is what an archive contains. The digest of a vault's
// data is a conclusion; the data is not.
func TestAnArchiveIsReportedByItsDigestAndTheReturnByBothItsSlots(t *testing.T) {
	t.Parallel()
	const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			Operation:      approval.OperationSnapshotService,
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
			ConsumedSequence: 10,
		},
	}
	snapshot := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:     approval.OperationSnapshotService,
		DataPath:      auxiliary.VaultwardenDataDirectory,
		SnapshotSlot:  "nightly",
		ArchiveSHA256: digest,
		ArchivedAt:    "2026-08-06T12:00:00Z",
		SnapshotSlots: []string{"nightly"},
		Changed:       true,
	})

	var text bytes.Buffer
	if err := renderAuxiliaryReport(&text, "text", snapshot); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"snapshot slot: nightly",
		"archive: " + digest,
		"archived at: 2026-08-06T12:00:00Z",
	} {
		if !strings.Contains(text.String(), line) {
			t.Fatalf("the snapshot report does not state %q: %q", line, text.String())
		}
	}
	// An archive operation announces no service state: the two words this product
	// has for a service are running and gone, and an archive returns a machine to
	// whichever it found.
	if strings.Contains(text.String(), "service: ") {
		t.Fatalf("the snapshot report announced a service state: %q", text.String())
	}

	accepted.Envelope.Operation = approval.OperationRestoreService
	returned := buildAppliedAuxiliaryReport(accepted, &auxiliary.Application{
		Operation:     approval.OperationRestoreService,
		DataPath:      auxiliary.VaultwardenDataDirectory,
		SnapshotSlot:  "nightly",
		PreviousSlot:  plan.ReservedSnapshotSlot,
		ArchiveSHA256: digest,
		ArchivedAt:    "2026-08-06T12:00:00Z",
		SnapshotSlots: []string{"nightly"},
		Changed:       true,
	})
	var back bytes.Buffer
	if err := renderAuxiliaryReport(&back, "text", returned); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"snapshot slot: nightly",
		"previous slot: " + plan.ReservedSnapshotSlot + " (it holds the state this return replaced)",
		"archive: " + digest,
	} {
		if !strings.Contains(back.String(), line) {
			t.Fatalf("the return report does not state %q: %q", line, back.String())
		}
	}

	// And a controlled failure of an archive operation names the slot it was
	// acting on, and is observed in the three words a data-bearing profile is left
	// holding.
	failed := buildFailedAuxiliaryReport(accepted, &auxiliary.ControlledFailure{
		Operation:    approval.OperationRestoreService,
		SnapshotSlot: "nightly",
		Outcome:      auxiliary.OutcomePartial,
		Cause:        errors.New("the service never answered again"),
		Rollback:     errors.New("the archive could not be read"),
		Observed: &auxiliary.Observation{
			Account:   "present",
			UnitFile:  "present",
			Service:   "inactive",
			Container: "none",
			Data:      "present",
			Egress:    "present",
			Archive:   "present",
		},
	})
	var partial bytes.Buffer
	if err := renderAuxiliaryReport(&partial, "text", failed); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"outcome: " + auxiliary.OutcomePartial,
		"snapshot slot: nightly",
		"observed data: present",
		"observed egress: present",
		"observed archive: present",
	} {
		if !strings.Contains(partial.String(), line) {
			t.Fatalf("the partial archive state does not state %q: %q", line, partial.String())
		}
	}
}
