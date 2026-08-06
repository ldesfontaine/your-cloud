package auxiliary

// This file is the refusal matrix of the palier: the one place a reviewer reads
// to see every refusal `#14` names, each proven where it actually happens rather
// than at the gate that happens to implement it.
//
// It is divided exactly once, along the only line that matters. What a document
// alone decides is refused before this machine is even asked what it holds; what
// only the machine can answer is refused after exactly one read-only question
// and before any write. Two further refusals belong to the approval itself and
// are walked through the whole chain a real invocation takes, because an
// envelope that is expired or already spent must never reach the application at
// all.
//
// Every case below asserts the same two things: the operation was refused, and
// the fake machine recorded no effect. A refusal that tidied something away is
// not a refusal.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// approvedInput is one acceptance and one input, forged together so that each
// case below differs from the nominal, applicable operation by exactly one
// thing.
type approvedInput struct {
	accepted *approval.Acceptance
	input    *Input
}

// refusal is one line of the matrix.
type refusal struct {
	// forge turns the nominal subject into exactly one hostile one.
	forge func(*testing.T, *approvedInput)
	// named is what the refusal must say. It is required so that no case can
	// pass by being refused for a reason other than the one it exists to prove:
	// a smuggled volume refused for a digest mismatch would prove nothing about
	// smuggled volumes.
	named string
}

// TestNothingIsTouchedWhileTheApprovedDocumentsAreStillInDoubt walks every
// refusal a document alone decides.
//
// The two documents are held against the digests a human signed, then against
// this machine's own anchor, then against the closed contract of the palier —
// and all of that happens before the first read of the machine. So each case
// proves three things at once: the operation was refused, the refusal said what
// it was refusing, and the fake machine recorded neither an effect nor a read.
func TestNothingIsTouchedWhileTheApprovedDocumentsAreStillInDoubt(t *testing.T) {
	t.Parallel()
	other := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort+1)
	oversized := strings.Repeat("a", plan.MaxPlanBytes+1)

	for name, subject := range map[string]refusal{
		// The two documents against the two digests a human signed.
		"a plan that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.PlanSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a plan altered after it was signed": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort+1, nil)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a plan document swapped for another signed plan": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = other.PlanDocument
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a rollback that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.RollbackSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried rollback is not the document the approval signed",
		},
		"a rollback altered after it was signed": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = forgedPlan(t, plan.OperationRemoveOCIProbe, fixturePort+1, nil)
			},
			named: "the carried rollback is not the document the approval signed",
		},

		// The plan against this machine and against the approval that carries it.
		"a plan aimed at another machine": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.MachineID = "lab-machine-2"
			},
			named: "targets another machine than this one",
		},
		"a plan aimed at another infrastructure": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"
			},
			named: "targets another infrastructure than this machine's anchor",
		},
		"a plan describing another operation than the approval": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.Operation = plan.OperationRemoveOCIProbe
			},
			named: "the approved plan describes",
		},
		"an approval presented without its documents": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.Kind = KindDiagnose
			},
			named: "requires the plan and the rollback the approval signed",
		},

		// The rollback against the plan it claims to undo.
		"a rollback that undoes another instance": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = other.RollbackDocument
				subject.accepted.Envelope.RollbackSHA256 = other.RollbackSHA256
			},
			named: "does not undo exactly the approved plan",
		},
		"a rollback that is a second deployment rather than an undoing": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = other.PlanDocument
				subject.accepted.Envelope.RollbackSHA256 = other.PlanSHA256
			},
			named: "does not undo exactly the approved plan",
		},

		// The content against the closed contract of the palier: the image is
		// pinned by digest and by nothing else, and the port has one range.
		"a plan naming its image by a tag rather than by a digest": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"image_reference": quotedJSON(t, plan.ProbeImageReference+":v1.11.0"),
				})
			},
			named: "plan image_reference is not the pinned probe of this palier",
		},
		"a plan carrying no digest at all": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"image_digest": "",
				})
			},
			named: "plan image_digest is malformed",
		},
		"a plan whose digest is not a digest": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"image_digest": quotedJSON(t, "sha256:latest"),
				})
			},
			named: "plan image_digest is malformed",
		},
		"a plan pinning another image than this palier's probe": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"image_digest": quotedJSON(t, "sha256:"+strings.Repeat("b", 64)),
				})
			},
			named: "plan image_digest is not the pinned probe of this palier",
		},
		"a plan naming a registry this palier does not accept": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"image_reference": quotedJSON(t, "ghcr.io/traefik/whoami"),
				})
			},
			named: "plan image_reference is not the pinned probe of this palier",
		},
		"a plan asking for a privileged port": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, 80, nil)
			},
			named: "plan local_port must be within",
		},
		"a plan asking for a port beyond the range": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, 70000, nil)
			},
			named: "plan local_port must be within",
		},

		// The strongest form of the refusal: a field the schema does not have is
		// refused without its content ever being read, so no smuggled volume,
		// device, privilege, network or command is ever understood well enough
		// to be evaluated.
		"a plan smuggling a volume": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"volume": quotedJSON(t, "/etc:/etc:rw"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a plan smuggling a container privilege": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"privileged": "true",
				})
			},
			named: "does not exactly match destination schema",
		},
		"a plan smuggling a host network": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"network": quotedJSON(t, "host"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a plan smuggling a command": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedPlan(t, plan.OperationDeployOCIProbe, fixturePort, map[string]string{
					"command": quotedJSON(t, "/bin/sh -c id"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a rollback smuggling a volume": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = forgedPlan(t, plan.OperationRemoveOCIProbe, fixturePort, map[string]string{
					"volume": quotedJSON(t, "/etc:/etc:rw"),
				})
			},
			named: "does not exactly match destination schema",
		},

		// The shape, before any of the above.
		"a plan document that is not a plan at all": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = []byte(`{"schema_version":1}`)
			},
			named: "carried plan",
		},
		"a plan repeating one of its fields": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = []byte(
					`{"schema_version":1,"schema_version":1,"infrastructure_id":"` + fixtureInfrastructure + `"}`)
			},
			named: "JSON repeats field",
		},
		"a plan longer than a plan may be": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = []byte(oversized)
			},
			named: "plan document must contain",
		},
		"a rollback longer than a rollback may be": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = []byte(oversized)
			},
			named: "carried rollback",
		},
	} {
		executor := deployedMachine(t, fixturePort)
		accepted, input := approvedApplication(t, plan.OperationDeployOCIProbe, fixturePort)
		forged := &approvedInput{accepted: accepted, input: input}
		subject.forge(t, forged)

		application, err := Apply(executor, forged.accepted, forged.input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), subject.named) {
			t.Fatalf("%s was refused for another reason than its own: %v", name, err)
		}
		// A refusal is never a rollback, and never carries the vocabulary of
		// one: nothing was changed, so there is nothing to have undone.
		var controlled *ControlledFailure
		if errors.As(err, &controlled) {
			t.Fatalf("%s was reported as a controlled failure: %v", name, err)
		}
		if len(executor.effects) != 0 {
			t.Fatalf("%s changed the machine before being refused: %q", name, executor.effects)
		}
		if len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine before being refused: %q", name, executor.reads)
		}
	}
}

// TestAMachineThatCannotRunTheFlowIsRefusedBeforeAnyWrite is the other half of
// the matrix: what no document can decide and only the machine can answer.
//
// Quadlet has no fallback and this product invents none. What is missing is
// named, exactly one read-only question was asked, and the machine is left
// exactly as it was found — for a deployment and for a removal alike.
func TestAMachineThatCannotRunTheFlowIsRefusedBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	for name, capabilities := range map[string]Capabilities{
		"a machine without systemd": {
			UnifiedCgroupHierarchy: true, PodmanPresent: true,
		},
		"a machine without cgroup v2": {
			Systemd: true, PodmanPresent: true,
		},
		"a machine without podman": {
			Systemd: true, UnifiedCgroupHierarchy: true,
		},
		"an account that cannot run podman rootless": {
			Systemd: true, UnifiedCgroupHierarchy: true, PodmanPresent: true,
			AccountPresent: true, RootlessPodman: false,
		},
	} {
		for _, operation := range []string{plan.OperationDeployOCIProbe, plan.OperationRemoveOCIProbe} {
			executor := newFakeExecutor()
			executor.capabilities = capabilities
			accepted, input := approvedApplication(t, operation, fixturePort)

			if _, err := Apply(executor, accepted, input); err == nil {
				t.Fatalf("%s applied %s", name, operation)
			}
			if len(executor.effects) != 0 {
				t.Fatalf("%s was written to before being refused: %q", name, executor.effects)
			}
			if strings.Join(executor.reads, ",") != "Capabilities" {
				t.Fatalf("%s was read beyond its capabilities: %q", name, executor.reads)
			}
		}
	}
}

// TestAnApprovalThisMachineRefusesNeverReachesTheApplication walks the two
// refusals the approval itself owns, through the whole chain a real invocation
// takes rather than through an acceptance a test wrote for itself.
//
// An expired envelope is refused by the clock before the anti-replay state is
// even opened, which is why this check needs no state at all: the machine never
// gets as far as spending anything, and never gets as far as being touched.
func TestAnApprovalThisMachineRefusesNeverReachesTheApplication(t *testing.T) {
	t.Parallel()
	authority := fixtureAuthority(t)
	frozen := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)
	document := authority.approve(t, probeEnvelope(plan.OperationDeployOCIProbe, frozen, 1), frozen)

	for name, now := range map[string]uint64{
		"an approval presented at the instant it expired": fixtureExpiresAt,
		"an approval presented long after it expired":     fixtureExpiresAt + 86_400,
		"an approval presented before it was issued":      fixtureIssuedAt - 1,
	} {
		executor := deployedMachine(t, fixturePort)
		if _, err := presented(t, executor, authority, t.TempDir(), document, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if len(executor.effects) != 0 || len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine: %q %q", name, executor.effects, executor.reads)
		}
	}
}

// TestASequenceAlreadySpentStaysRefusedAfterACut is the guarantee a cut leaves
// behind, and the only one code can make about a process that is no longer
// running.
//
// The sequence is spent durably before the first effect, so the envelope that
// was in flight when the machine went down is spent whether or not anything
// happened. Presenting it again is therefore refused — and refused before any
// effect, which is the part that matters: the replay does not resume the
// mutation it interrupted, does not repair the half-written state it finds, and
// does not read the machine to decide. Resuming requires a new approval, and a
// new approval is a new sequence.
func TestASequenceAlreadySpentStaysRefusedAfterACut(t *testing.T) {
	directory := rootOwnedAntiReplayState(t)
	authority := fixtureAuthority(t)
	frozen := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)
	document := authority.approve(t, probeEnvelope(plan.OperationDeployOCIProbe, frozen, 1), frozen)

	// The run that was cut. It spent its sequence — durably, before any effect —
	// and then stopped existing partway through its mutation.
	input, err := DecodeInput(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approval.AcceptMutating(directory, authority.anchor, input.Signed, fixtureNow); err != nil {
		t.Fatalf("the first approval was refused: %v", err)
	}

	// The same envelope, presented again after the machine came back.
	half := halfWrittenMachine(t, fixturePort)
	if _, err := presented(t, half, authority, directory, document, fixtureNow); err == nil {
		t.Fatal("a sequence already spent was consumed a second time")
	}
	if len(half.effects) != 0 {
		t.Fatalf("the replay resumed the mutation it interrupted: %q", half.effects)
	}
	if len(half.reads) != 0 {
		t.Fatalf("the replay read the machine before refusing: %q", half.reads)
	}
	if !half.unitPresent || half.active {
		t.Fatalf("the replay repaired the state it found: %+v", half)
	}
}
