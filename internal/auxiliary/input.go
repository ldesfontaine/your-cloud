// Package auxiliary applies one approved plan to the machine it runs on, and
// refuses everything else.
//
// The approval package decides whether a human authorised this machine to act.
// This package decides what acting means, and it is the only place in the
// product where a plan becomes a file, a service and a container. Its operations
// are twenty-one: the pinned OCI probe of schema 1, deployed and removed; the
// managed web service, the public entrypoint and the published route of schema 2;
// the three pairs of the private passage of schema 3; and the private profile's
// seven, also of schema 2 — the data-bearing service, the route the passage
// publishes and the three archive operations, whose return is the one undoing of
// the product that moves a field instead of reversing the operation. Every one of
// them is described by a plan document whose digest the approval signed.
//
// The third door of the product is written in schema 2 as well, and this package
// does not perform it yet. Its two operations — a service deployed and removed
// from a definition its user wrote — and the archive operations naming such a
// definition by its slug are refused by name where the shapes become instances,
// before any effect and before this machine is read at all, until `#119` lands.
// That window is deliberate and it is tested — an operation this Auxiliary does
// not perform must refuse, never guess — and it is the same window `#90`, `#91`,
// `#96`, `#102` and `#103` each opened and closed in turn.
//
// Everything a profile means on a machine — its account, its home, its sheet,
// its container and its pinned image — lives in one placement per profile rather
// than in the flow, so the two profiles share one machinery and share nothing on
// a machine.
//
// Two rules shape everything below. The first is that no plan-derived string
// ever reaches a shell: every effect goes through the Executor interface as
// typed arguments, and the values that end up in the unit file are the pinned
// constants of the profile plus one integer the plan validation already bound.
// The second is that nothing is written before everything is verified — the
// approval, then the schema the two documents declare, then the documents
// against their signed digests, then the target, then the content, then the
// capabilities of the machine. A machine that cannot run the flow is refused
// while it is still untouched.
package auxiliary

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// inputSlack is what the wrapper itself costs beyond the three documents it
	// carries: its field names, its quoting and the escaping a transport may
	// apply to the two plan documents it holds as strings.
	inputSlack = 1024

	// MaxInputBytes bounds the whole document read on the standard input before
	// anything is parsed. It is the sum of the bounds the three carried
	// documents already have, and not a new freedom: each of them is still held
	// against its own bound by the package that owns it.
	MaxInputBytes = approval.MaxSignedApprovalBytes + 2*plan.MaxPlanBytes + inputSlack

	// wrapperDiscriminator is the field whose presence at the top level says
	// which of the two closed shapes was sent. The two shapes share no field
	// name, so the choice is made by the document rather than guessed by trying
	// to parse it twice.
	wrapperDiscriminator = "signed_approval"
)

// Kind is which of the two closed input shapes was presented.
type Kind int

const (
	// KindDiagnose is the shape this Auxiliary has always read: one signed
	// approval and nothing else. It stays byte-identical to what the previous
	// palier proved, because a read-only diagnostic needs no plan to read.
	KindDiagnose Kind = iota + 1
	// KindApply is the shape a mutating operation requires: the same signed
	// approval, plus the exact canonical bytes of the two documents its digests
	// name. An operation that will change the machine cannot be carried by an
	// envelope alone — the envelope says only that a human approved two hashes.
	KindApply
)

// Input is one accepted shape of the standard input, decoded and bounded.
//
// The two plan documents are raw bytes here and nothing more: they have not yet
// been held against the digests the envelope signed, so nothing in this package
// reads their content until they have.
type Input struct {
	Kind             Kind
	Signed           *approval.SignedApproval
	PlanDocument     []byte
	RollbackDocument []byte
}

// applyWrapper is the closed schema of the mutating shape.
//
// The signed approval is kept as its own received bytes rather than decoded
// here, so that it goes through exactly the same strict decoding as when it
// arrives alone. The two plan documents travel as strings carrying their exact
// canonical bytes, which is the one transport form the contract describes: the
// machine hashes what it was given instead of re-encoding what it understood.
type applyWrapper struct {
	SignedApproval json.RawMessage `json:"signed_approval"`
	Plan           string          `json:"plan"`
	Rollback       string          `json:"rollback"`
}

// DecodeInput accepts exactly one of the two closed shapes, fully validated.
//
// A caller holding an Input may assume the approval inside it is a complete,
// well-formed signed envelope. It may assume nothing at all about the two plan
// documents beyond their bounds: they are still untrusted bytes until Apply
// holds them against the digests a human signed.
func DecodeInput(document []byte) (*Input, error) {
	if len(document) == 0 || len(document) > MaxInputBytes {
		return nil, fmt.Errorf("auxiliary input must contain 1..%d bytes", MaxInputBytes)
	}
	wrapped, err := carriesPlanDocuments(document)
	if err != nil {
		return nil, err
	}
	if !wrapped {
		signed, err := approval.DecodeSigned(document)
		if err != nil {
			return nil, err
		}
		return &Input{Kind: KindDiagnose, Signed: signed}, nil
	}

	var wrapper applyWrapper
	if err := strictjson.Decode(document, &wrapper); err != nil {
		return nil, fmt.Errorf("decode auxiliary input: %w", err)
	}
	signed, err := approval.DecodeSigned(wrapper.SignedApproval)
	if err != nil {
		return nil, err
	}
	if len(wrapper.Plan) == 0 || len(wrapper.Plan) > plan.MaxPlanBytes {
		return nil, fmt.Errorf("carried plan must contain 1..%d bytes", plan.MaxPlanBytes)
	}
	if len(wrapper.Rollback) == 0 || len(wrapper.Rollback) > plan.MaxPlanBytes {
		return nil, fmt.Errorf("carried rollback must contain 1..%d bytes", plan.MaxPlanBytes)
	}
	return &Input{
		Kind:             KindApply,
		Signed:           signed,
		PlanDocument:     []byte(wrapper.Plan),
		RollbackDocument: []byte(wrapper.Rollback),
	}, nil
}

// carriesPlanDocuments reads only the top-level field names, and decides from
// them alone.
//
// Deciding by one named field rather than by attempting each schema in turn is
// what keeps the two shapes from covering for one another: a document that mixes
// them is classified by its discriminator and then refused as an unknown field
// by the strict decoding of the shape it claimed, instead of quietly succeeding
// as the other one.
func carriesPlanDocuments(document []byte) (bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		return false, errors.New("auxiliary input must be one JSON object")
	}
	_, wrapped := fields[wrapperDiscriminator]
	return wrapped, nil
}
