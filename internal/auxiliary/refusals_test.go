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
	"strconv"
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

// TestNothingIsTouchedWhileTheApprovedServiceDocumentsAreStillInDoubt is the
// same matrix over schema 2, written in the same place and in the same form.
//
// It is a second table rather than a widened first one because the two schemas
// carry different closed field lists, and a case must forge the document of the
// schema it is refusing. Everything else is identical, including what each case
// asserts: refused, refused for its own reason, and with neither an effect nor a
// read recorded — a refusal that reached the machine is not a refusal.
func TestNothingIsTouchedWhileTheApprovedServiceDocumentsAreStillInDoubt(t *testing.T) {
	t.Parallel()
	other := frozenServicePair(t, plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, fixturePort+1)

	for name, subject := range map[string]refusal{
		// The two documents against the two digests a human signed.
		"a service plan that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.PlanSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a service plan altered after it was signed": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort+1, nil)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a service rollback that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.RollbackSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried rollback is not the document the approval signed",
		},

		// The plan against this machine and against the approval that carries it.
		"a service plan aimed at another machine": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.MachineID = "lab-machine-2"
			},
			named: "targets another machine than this one",
		},
		"a service plan aimed at another infrastructure": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"
			},
			named: "targets another infrastructure than this machine's anchor",
		},
		"a service plan describing another operation than the approval": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.Operation = plan.OperationRemoveWebService
			},
			named: "the approved plan describes",
		},

		// The rollback against the plan it claims to undo.
		"a service rollback that undoes another instance": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = other.RollbackDocument
				subject.accepted.Envelope.RollbackSHA256 = other.RollbackSHA256
			},
			named: "does not undo exactly the approved plan",
		},
		"a service rollback that is a second deployment rather than an undoing": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = other.PlanDocument
				subject.accepted.Envelope.RollbackSHA256 = other.PlanSHA256
			},
			named: "does not undo exactly the approved plan",
		},

		// The content against the closed contract of the profile. The profile is
		// what decides the account, the sheet and the image, so a profile this
		// palier does not describe is refused before any of them is chosen, and
		// an image couple that is not exactly the profile's pin is refused even
		// though the plan carries it for a human to read.
		"a plan naming a service profile this palier does not describe": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"service_profile": quotedJSON(t, "vaultwarden"),
				})
			},
			named: "plan service_profile",
		},
		"a plan carrying no service profile at all": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"service_profile": "",
				})
			},
			named: "plan service_profile",
		},
		"a plan pinning another digest than the profile's": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"image_digest": quotedJSON(t, "sha256:"+strings.Repeat("b", 64)),
				})
			},
			named: "plan image_digest is not the pinned image of this palier",
		},
		"a plan naming its image by a tag rather than by a digest": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"image_reference": quotedJSON(t, plan.BentoPDFImageReference+":v1.9.0"),
				})
			},
			named: "plan image_reference is not the pinned image of this palier",
		},
		"a plan naming a registry this profile does not accept": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"image_reference": quotedJSON(t, "docker.io/alam00000/bentopdf"),
				})
			},
			named: "plan image_reference is not the pinned image of this palier",
		},
		"a plan borrowing the pinned image of another palier": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"image_reference": quotedJSON(t, plan.ProbeImageReference),
					"image_digest":    quotedJSON(t, plan.ProbeImageDigest),
				})
			},
			named: "plan image_reference is not the pinned image of this palier",
		},
		"a service plan asking for a privileged port": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, 80, nil)
			},
			named: "plan local_port must be within",
		},

		// The strongest form of the refusal, over the schema 2 field list: a
		// field the schema does not have is refused without its content ever
		// being read, whichever group it was borrowed from.
		"a service plan smuggling a volume": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"volume": quotedJSON(t, "/etc:/etc:rw"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a service plan smuggling a container privilege": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"privileged": "true",
				})
			},
			named: "does not exactly match destination schema",
		},
		"a service plan smuggling the route host of another operation group": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"route_host": quotedJSON(t, "lab.example.test"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a service rollback smuggling a volume": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = forgedServicePlan(t, plan.OperationRemoveWebService, fixturePort, map[string]string{
					"volume": quotedJSON(t, "/etc:/etc:rw"),
				})
			},
			named: "does not exactly match destination schema",
		},

		// The schema itself, before any of the above: a document of one schema
		// wearing the version of the other is refused by the decoder its version
		// named, and never retried as the schema it actually is.
		"a service plan claiming to be a probe plan": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"schema_version": strconv.Itoa(plan.SchemaVersion),
				})
				subject.input.RollbackDocument = forgedServicePlan(t, plan.OperationRemoveWebService, fixturePort, map[string]string{
					"schema_version": strconv.Itoa(plan.SchemaVersion),
				})
			},
			named: "carried plan",
		},
		"a service plan declaring no schema version at all": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
					"schema_version": "",
				})
			},
			named: "no plan schema version is declared",
		},
		"a service plan longer than a plan may be": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = []byte(strings.Repeat("a", plan.MaxPlanBytes+1))
			},
			named: "plan document must contain",
		},
	} {
		executor := deployedServiceMachine(t, fixturePort)
		accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)
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

// TestNothingIsTouchedWhileTheApprovedEntrypointDocumentsAreStillInDoubt is the
// same matrix over the entrypoint's own closed field list.
//
// An entrypoint plan is the narrowest document of the palier: four common fields
// and one pinned image, and not a single value a human chooses. So the cases
// below are exactly the ones that shape allows — the digests, the target, the
// pin, and every field borrowed from another group, refused as an unknown field
// before its content is ever read.
func TestNothingIsTouchedWhileTheApprovedEntrypointDocumentsAreStillInDoubt(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]refusal{
		"an entrypoint plan that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.PlanSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"an entrypoint rollback that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.RollbackSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried rollback is not the document the approval signed",
		},
		"an entrypoint plan aimed at another machine": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.MachineID = "lab-machine-2"
			},
			named: "targets another machine than this one",
		},
		"an entrypoint plan describing another operation than the approval": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.Operation = plan.OperationRemoveEntrypoint
			},
			named: "the approved plan describes",
		},
		"an entrypoint rollback that is a second deployment rather than an undoing": {
			forge: func(t *testing.T, subject *approvedInput) {
				frozen := frozenEntrypointPair(t, plan.OperationDeployEntrypoint)
				subject.input.RollbackDocument = frozen.PlanDocument
				subject.accepted.Envelope.RollbackSHA256 = frozen.PlanSHA256
			},
			named: "does not undo exactly the approved plan",
		},
		"an entrypoint plan naming its image by a tag rather than by a digest": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"image_reference": quotedJSON(t, plan.EntrypointImageReference+":v3.7.10"),
				})
			},
			named: "plan image_reference is not the pinned image of this palier",
		},
		"an entrypoint plan pinning another digest than the contract's": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"image_digest": quotedJSON(t, "sha256:"+strings.Repeat("b", 64)),
				})
			},
			named: "plan image_digest is not the pinned image of this palier",
		},
		"an entrypoint plan borrowing the pinned image of the service profile": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"image_reference": quotedJSON(t, plan.BentoPDFImageReference),
					"image_digest":    quotedJSON(t, plan.BentoPDFImageDigest),
				})
			},
			named: "plan image_reference is not the pinned image of this palier",
		},
		"an entrypoint plan smuggling a public port": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"local_port": "8443",
				})
			},
			named: "does not exactly match destination schema",
		},
		"an entrypoint plan smuggling a listening address": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"address": quotedJSON(t, "0.0.0.0"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"an entrypoint plan smuggling the file provider directory": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"provider_directory": quotedJSON(t, "/tmp/routes"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"an entrypoint plan smuggling a volume": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"volume": quotedJSON(t, "/etc:/etc:rw"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"an entrypoint plan smuggling an engine socket": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedEntrypointPlan(t, plan.OperationDeployEntrypoint, map[string]string{
					"provider": quotedJSON(t, "docker"),
				})
			},
			named: "does not exactly match destination schema",
		},
	} {
		executor := deployedEntrypointMachine()
		accepted, input := approvedEntrypoint(t, plan.OperationDeployEntrypoint)
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

// TestNothingIsTouchedWhileTheApprovedRouteDocumentsAreStillInDoubt is the same
// matrix over the route's closed field list.
//
// The declared name is where most of it lives, because that is the one string of
// this palier that reaches a file's name and a router's rule at once. Every case
// below is refused before this machine is read, so no hostile name is ever
// sanitised, escaped or truncated into something that would have been safe: it
// is refused for not being a name.
func TestNothingIsTouchedWhileTheApprovedRouteDocumentsAreStillInDoubt(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]refusal{
		"a route plan that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.PlanSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a route plan aimed at another machine": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.MachineID = "lab-machine-2"
			},
			named: "targets another machine than this one",
		},
		"a route rollback that retires another name": {
			forge: func(t *testing.T, subject *approvedInput) {
				other := frozenRoutePair(t, plan.OperationPublishRoute, "other.example.test", fixturePort)
				subject.input.RollbackDocument = other.RollbackDocument
				subject.accepted.Envelope.RollbackSHA256 = other.RollbackSHA256
			},
			named: "does not undo exactly the approved plan",
		},
		"a route rollback that is a second publication rather than an undoing": {
			forge: func(t *testing.T, subject *approvedInput) {
				other := frozenRoutePair(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort+1)
				subject.input.RollbackDocument = other.PlanDocument
				subject.accepted.Envelope.RollbackSHA256 = other.PlanSHA256
			},
			named: "does not undo exactly the approved plan",
		},
		"a route towards a privileged port": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, 80, nil)
			},
			named: "plan backend_port must be within",
		},
		"a route towards a port beyond the range": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, 70000, nil)
			},
			named: "plan backend_port must be within",
		},
		"a route declaring a wildcard": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, "*.example.test", fixturePort, nil)
			},
			named: "plan route_host must be",
		},
		"a route declaring an upper-case name": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, "LAB.example.test", fixturePort, nil)
			},
			named: "plan route_host must be",
		},
		"a route declaring a name with an empty label": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, "lab..test", fixturePort, nil)
			},
			named: "plan route_host must not carry an empty label",
		},
		"a route declaring a path rather than a name": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, "../../etc/passwd", fixturePort, nil)
			},
			named: "plan route_host must be",
		},
		"a route declaring a name that closes on a separator": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, "lab.example.test.", fixturePort, nil)
			},
			named: "plan route_host must be",
		},
		"a route declaring no name at all": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort, map[string]string{
					"route_host": "",
				})
			},
			named: "plan route_host must be",
		},
		"a route smuggling an image": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort, map[string]string{
					"image_reference": quotedJSON(t, plan.BentoPDFImageReference),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a route smuggling a certificate": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort, map[string]string{
					"cert_file": quotedJSON(t, "/tmp/forged.crt"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a route smuggling a middleware": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort, map[string]string{
					"middleware": quotedJSON(t, "stripPrefix"),
				})
			},
			named: "does not exactly match destination schema",
		},
		"a route smuggling a backend host beside its port": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedRoutePlan(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort, map[string]string{
					"backend_host": quotedJSON(t, "10.0.0.5"),
				})
			},
			named: "does not exactly match destination schema",
		},
	} {
		executor := publishedRouteMachine(fixtureRouteHost, fixturePort)
		accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)
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
		// The eight operations that run a container, across the two plan schemas
		// that describe one: a machine that cannot run the flow is refused for
		// the entry and for a route exactly as it is for the probe, and the
		// account each refusal names is the one that operation's own placement
		// carries. A route is in this list because it is served by a container: a
		// machine that cannot run one cannot publish a name through it either.
		//
		// The six operations of the private passage are deliberately absent. A
		// passage owns no account, no container and no image, so a machine
		// without Podman or without a unified cgroup hierarchy holds one
		// perfectly well; what it asks for instead is systemd alone, and that is
		// held in link_test.go where the rest of its conduct is.
		for _, operation := range []string{
			plan.OperationDeployOCIProbe, plan.OperationRemoveOCIProbe,
			plan.OperationDeployWebService, plan.OperationRemoveWebService,
			plan.OperationDeployEntrypoint, plan.OperationRemoveEntrypoint,
			plan.OperationPublishRoute, plan.OperationRetireRoute,
		} {
			executor := newFakeExecutor()
			executor.capabilities = capabilities
			accepted, input := approvedOperation(t, operation, fixturePort)

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
	if !half.holds(UnitPath()) || half.active {
		t.Fatalf("the replay repaired the state it found: %+v", half)
	}
}

// TestNothingIsTouchedWhileTheApprovedLinkDocumentsAreStillInDoubt is the same
// matrix over the three closed field lists of the private passage.
//
// It is a third table rather than a widened second one, for the reason the
// second is a table of its own: a case must forge the document of the schema and
// of the group it is refusing, and schema 3 carries three groups that share only
// their common head. What each case asserts is unchanged — refused, refused for
// its own reason, and with neither an effect nor a read recorded.
//
// The three groups appear together because the whole point of their separation
// is that a field of one is an unknown field of the others: an endpoint on the
// listener's junction, a role on a peer plan, a peer on a preparation. Every one
// of them is refused by the strict decoding before its value is ever read.
func TestNothingIsTouchedWhileTheApprovedLinkDocumentsAreStillInDoubt(t *testing.T) {
	t.Parallel()
	other := frozenLinkPair(t, plan.OperationPrepareLink, plan.LinkRoleInitiator)

	for name, subject := range map[string]refusal{
		// The two documents against the two digests a human signed.
		"a link plan that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.PlanSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a link plan altered after it was signed": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedLinkPlan(t, plan.OperationPrepareLink, plan.LinkRoleInitiator, nil)
			},
			named: "the carried plan is not the document the approval signed",
		},
		"a link rollback that is not the one the approval signed": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.RollbackSHA256 = strings.Repeat("0", 64)
			},
			named: "the carried rollback is not the document the approval signed",
		},

		// The plan against this machine and against the approval that carries it.
		"a link plan aimed at another machine": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.MachineID = "lab-machine-2"
			},
			named: "targets another machine than this one",
		},
		"a link plan aimed at another infrastructure": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.State.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"
			},
			named: "targets another infrastructure than this machine's anchor",
		},
		"a link plan describing another operation than the approval": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.accepted.Envelope.Operation = plan.OperationWithdrawLink
			},
			named: "the approved plan describes",
		},

		// The rollback against the plan it claims to undo. A withdrawal naming the
		// other role is not the undoing of this preparation: it is a second plan,
		// and it would leave this machine describing a side nobody approved.
		"a link rollback that withdraws the other role": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = other.RollbackDocument
				subject.accepted.Envelope.RollbackSHA256 = other.RollbackSHA256
			},
			named: "does not undo exactly the approved plan",
		},
		"a link rollback that is a second preparation rather than an undoing": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.RollbackDocument = other.PlanDocument
				subject.accepted.Envelope.RollbackSHA256 = other.PlanSHA256
			},
			named: "does not undo exactly the approved plan",
		},

		// The content against the closed contract of the passage. The role decides
		// every constant the plan does not state, so a role outside the closed list
		// is refused before a single one of them is chosen.
		"a link plan naming a role this contract does not describe": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedLinkPlan(t, plan.OperationPrepareLink, "relay", nil)
			},
			named: "plan link_role",
		},
		"a link plan carrying no role at all": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedLinkPlan(t, plan.OperationPrepareLink, plan.LinkRoleListener, map[string]string{
					"link_role": "",
				})
			},
			named: "plan link_role",
		},

		// A field of another group is an unknown field, refused before its value is
		// read. This is the whole reason the three groups are three shapes.
		"a preparation carrying a peer it has no business naming": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedLinkPlan(t, plan.OperationPrepareLink, plan.LinkRoleListener, map[string]string{
					"peer_public_key": quotedJSON(t, fixturePeerPublicKey),
				})
			},
			named: "carried plan",
		},
		"a preparation carrying a service port it has no business naming": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedLinkPlan(t, plan.OperationPrepareLink, plan.LinkRoleListener, map[string]string{
					"service_port": strconv.Itoa(fixturePort),
				})
			},
			named: "carried plan",
		},
		"a link plan declaring no schema version at all": {
			forge: func(t *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = forgedLinkPlan(t, plan.OperationPrepareLink, plan.LinkRoleListener, map[string]string{
					"schema_version": "",
				})
			},
			named: "no plan schema version is declared",
		},
		"a link plan longer than a plan may be": {
			forge: func(_ *testing.T, subject *approvedInput) {
				subject.input.PlanDocument = []byte(strings.Repeat("a", plan.MaxPlanBytes+1))
			},
			named: "plan document must contain",
		},
	} {
		executor := preparedLinkMachine(plan.LinkRoleListener)
		accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
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

// TestAJunctionCarryingAFieldOfTheOtherRoleIsRefusedBeforeItIsRead is the
// asymmetry of the contract held at the layer that enforces it.
//
// The listener has no endpoint to reach, so its junction plan has no such field
// — not empty, not ignored, absent. A document carrying one is an unknown field
// of that shape and is refused by the strict decoding, before this machine is
// read and before the value could decide anything. The mirror case is a peer
// plan carrying the role a preparation names.
func TestAJunctionCarryingAFieldOfTheOtherRoleIsRefusedBeforeItIsRead(t *testing.T) {
	t.Parallel()
	for name, forge := range map[string]func(*testing.T) []byte{
		"the listener's junction naming an endpoint": func(t *testing.T) []byte {
			return forgedListenerPeerPlan(t, plan.OperationAttachLinkPeer, fixturePort, map[string]string{
				"peer_endpoint_host": quotedJSON(t, fixtureEndpointHost),
			})
		},
		"the listener's junction naming a role": func(t *testing.T) []byte {
			return forgedListenerPeerPlan(t, plan.OperationAttachLinkPeer, fixturePort, map[string]string{
				"link_role": quotedJSON(t, plan.LinkRoleListener),
			})
		},
		"the initiator's junction carrying no endpoint at all": func(t *testing.T) []byte {
			return forgedInitiatorPeerPlan(t, plan.OperationJoinLinkPeer, fixturePort, map[string]string{
				"peer_endpoint_host": "",
			})
		},
		"a junction naming a port no managed service could listen on": func(t *testing.T) []byte {
			return forgedListenerPeerPlan(t, plan.OperationAttachLinkPeer, 80, nil)
		},
		"a junction naming a peer key with a second spelling": func(t *testing.T) []byte {
			return forgedListenerPeerPlan(t, plan.OperationAttachLinkPeer, fixturePort, map[string]string{
				"peer_public_key": quotedJSON(t, strings.Repeat("A", 43)+"="),
			})
		},
	} {
		executor := preparedLinkMachine(plan.LinkRoleListener)
		accepted, input := approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)
		input.PlanDocument = forge(t)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), "carried plan") {
			t.Fatalf("%s was refused somewhere other than the decoding of its own document: %v", name, err)
		}
		if len(executor.effects) != 0 || len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine: %q %q", name, executor.effects, executor.reads)
		}
	}
}
