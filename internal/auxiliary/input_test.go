package auxiliary

import (
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestTheInputCarriesEitherOneApprovalOrOneApprovedPlan is the whole framing
// decision, read from both shapes at once: a read-only approval still travels
// alone and is decoded exactly as before, and a mutating one travels with the
// two documents its digests name.
func TestTheInputCarriesEitherOneApprovalOrOneApprovedPlan(t *testing.T) {
	t.Parallel()
	frozen := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)

	alone := signedApprovalDocument(t, approval.OperationDiagnoseProtocolReadOnly, frozen, nil)
	diagnose, err := DecodeInput(alone)
	if err != nil {
		t.Fatalf("the shape the previous palier proved was refused: %v", err)
	}
	if diagnose.Kind != KindDiagnose {
		t.Fatalf("a lone approval was read as something else: %v", diagnose.Kind)
	}
	if diagnose.Signed.Envelope.Operation != approval.OperationDiagnoseProtocolReadOnly {
		t.Fatalf("the lone approval lost its operation: %+v", diagnose.Signed.Envelope)
	}
	if diagnose.PlanDocument != nil || diagnose.RollbackDocument != nil {
		t.Fatal("a lone approval carried plan documents")
	}

	wrapped, err := DecodeInput(wrapperDocument(t,
		signedApprovalDocument(t, approval.OperationDeployOCIProbe, frozen, nil),
		frozen.PlanDocument,
		frozen.RollbackDocument,
	))
	if err != nil {
		t.Fatalf("the mutating shape was refused: %v", err)
	}
	if wrapped.Kind != KindApply {
		t.Fatalf("a wrapped approval was read as something else: %v", wrapped.Kind)
	}
	if wrapped.Signed.Envelope.Operation != approval.OperationDeployOCIProbe {
		t.Fatalf("the wrapped approval lost its operation: %+v", wrapped.Signed.Envelope)
	}
	// The documents are carried as the exact bytes their digests were taken
	// over, not as an object this machine re-encoded.
	if string(wrapped.PlanDocument) != string(frozen.PlanDocument) {
		t.Fatalf("the carried plan is not the transported one: %q", wrapped.PlanDocument)
	}
	if string(wrapped.RollbackDocument) != string(frozen.RollbackDocument) {
		t.Fatalf("the carried rollback is not the transported one: %q", wrapped.RollbackDocument)
	}
}

// TestTheInputRefusesEveryShapeThatIsNeitherOfTheTwo walks the hostile forms one
// at a time, each of them a document that would have to be understood before it
// could be refused if the framing were open.
func TestTheInputRefusesEveryShapeThatIsNeitherOfTheTwo(t *testing.T) {
	t.Parallel()
	frozen := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)
	signed := string(signedApprovalDocument(t, approval.OperationDeployOCIProbe, frozen, nil))
	planDocument := string(frozen.PlanDocument)
	rollbackDocument := string(frozen.RollbackDocument)
	wrapped := func(body string) string {
		return `{"signed_approval":` + signed + `,` + body + `}`
	}
	quoted := func(document string) string { return quotedJSON(t, document) }

	for name, document := range map[string]string{
		"empty":                            "",
		"not an object":                    `["` + planDocument + `"]`,
		"a bare string":                    `"signed_approval"`,
		"two values":                       signed + signed,
		"the wrapper without its plan":     wrapped(`"rollback":` + quoted(rollbackDocument)),
		"the wrapper without its rollback": wrapped(`"plan":` + quoted(planDocument)),
		"an empty plan":                    wrapped(`"plan":"","rollback":` + quoted(rollbackDocument)),
		"an empty rollback":                wrapped(`"plan":` + quoted(planDocument) + `,"rollback":""`),
		"an unknown field beside the two documents": wrapped(
			`"plan":` + quoted(planDocument) + `,"rollback":` + quoted(rollbackDocument) + `,"unit":"/etc/forged.container"`),
		"a repeated plan": wrapped(
			`"plan":` + quoted(planDocument) + `,"plan":` + quoted(planDocument) + `,"rollback":` + quoted(rollbackDocument)),
		"a plan that is an object rather than its bytes": wrapped(
			`"plan":` + planDocument + `,"rollback":` + quoted(rollbackDocument)),
		"both shapes at once": `{"signed_approval":` + signed + `,"plan":` + quoted(planDocument) +
			`,"rollback":` + quoted(rollbackDocument) + `,"envelope":{},"signature":"x"}`,
		"a wrapper carrying no approval at all": `{"plan":` + quoted(planDocument) +
			`,"rollback":` + quoted(rollbackDocument) + `}`,
		"a plan longer than a plan may be": wrapped(
			`"plan":"` + strings.Repeat("a", plan.MaxPlanBytes+1) + `","rollback":` + quoted(rollbackDocument)),
		"an input longer than the input may be": `{"signed_approval":` + signed +
			`,"plan":"` + strings.Repeat("a", MaxInputBytes) + `","rollback":""}`,
	} {
		if _, err := DecodeInput([]byte(document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestTheApprovalInsideTheWrapperIsDecodedByItsOwnPackage keeps the wrapper from
// becoming a second, weaker way of presenting an envelope: the approval it
// carries goes through the same strict decoding as one arriving alone, and is
// refused for the same reasons.
func TestTheApprovalInsideTheWrapperIsDecodedByItsOwnPackage(t *testing.T) {
	t.Parallel()
	frozen := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)

	for name, mutate := range map[string]func(*approval.Envelope){
		"an unknown operation": func(e *approval.Envelope) { e.Operation = "install_container" },
		"a malformed machine":  func(e *approval.Envelope) { e.MachineID = "LAB" },
		"a sequence of zero":   func(e *approval.Envelope) { e.Sequence = 0 },
		"a lifetime beyond the bound": func(e *approval.Envelope) {
			e.ExpiresAtUnix = e.IssuedAtUnix + approval.MaxLifetimeSeconds + 1
		},
		"privileges its operation does not require": func(e *approval.Envelope) {
			e.Privileges = []string{approval.PrivilegeReadLocalState}
		},
		"privileges in a spelling the envelope refuses": func(e *approval.Envelope) {
			e.Privileges = []string{approval.PrivilegeReadLocalState, approval.PrivilegeMutateLocalState}
		},
	} {
		document := wrapperDocument(t,
			signedApprovalDocument(t, approval.OperationDeployOCIProbe, frozen, mutate),
			frozen.PlanDocument,
			frozen.RollbackDocument,
		)
		if _, err := DecodeInput(document); err == nil {
			t.Fatalf("a wrapper carrying %s was accepted", name)
		}
	}
}
