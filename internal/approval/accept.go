package approval

import (
	"errors"
	"fmt"
)

// Acceptance is what one accepted approval leaves behind: the envelope that was
// verified, and the anti-replay position the machine now holds.
//
// It carries no output of the operation and no plan. The operation runs after
// this, on the caller's side, and it runs at most once because the sequence is
// already spent when this value exists.
type Acceptance struct {
	Envelope *Envelope
	State    *State
}

// Accept verifies one read-only approval against this machine's own anchor and
// spends its sequence, in that order.
//
// Nothing here consults the Controller, and nothing here trusts a field for
// being present in the document. The order is the architecture's: the signature
// and every link of the envelope are checked first, so a forged document never
// reaches the state at all; then the sequence is consumed atomically, so an
// interruption after this point has still spent it.
//
// A refusal is always a refusal to act. There is no partial acceptance, no
// downgraded operation and no acceptance that consumed nothing.
func Accept(directory string, anchor *Anchor, signed *SignedApproval, nowUnixSeconds uint64) (*Acceptance, error) {
	return accept(directory, anchor, signed, nowUnixSeconds, requireReadOnlyDiagnostic)
}

// AcceptMutating verifies one approval for an operation that will change this
// machine, under exactly the same anchor, epoch, expiry and anti-replay rules.
//
// It is a second subject rather than a relaxation of the first: the read-only
// subject keeps refusing every mutation, and this one refuses every envelope
// naming an operation outside the closed list of mutations, so neither can be
// reached by an envelope meant for the other. What the mutation may actually do
// is not decided here at all — this returns an acceptance, and the caller still
// has to hold the plan documents against the digests this envelope signed before
// touching anything.
func AcceptMutating(directory string, anchor *Anchor, signed *SignedApproval, nowUnixSeconds uint64) (*Acceptance, error) {
	return accept(directory, anchor, signed, nowUnixSeconds, requireAppliedMutation)
}

// requireReadOnlyDiagnostic is the limit of the read-only subject, checked on
// the operation that is about to run rather than only in the schema, so that no
// future operation reaches the state by being added to the privilege table
// without being thought about.
func requireReadOnlyDiagnostic(envelope *Envelope) error {
	if envelope.IsMutating() {
		return errors.New("this Auxiliary performs no mutation: the approval asks for one")
	}
	if envelope.Operation != OperationDiagnoseProtocolReadOnly {
		return fmt.Errorf("approval operation %q is not one this Auxiliary performs", envelope.Operation)
	}
	return nil
}

// requireAppliedMutation is the symmetric limit of the mutating subject: exactly
// the closed list of operations that may change the machine, and only while the
// envelope actually asks for the privilege that changing it requires.
func requireAppliedMutation(envelope *Envelope) error {
	if _, known := mutatingOperations[envelope.Operation]; !known {
		return fmt.Errorf("approval operation %q is not one this Auxiliary applies", envelope.Operation)
	}
	if !envelope.IsMutating() {
		return errors.New("an applied operation must carry the privilege to mutate this machine")
	}
	return nil
}

func accept(
	directory string,
	anchor *Anchor,
	signed *SignedApproval,
	nowUnixSeconds uint64,
	requireSubject func(*Envelope) error,
) (*Acceptance, error) {
	if anchor == nil || signed == nil {
		return nil, errors.New("an anchor and a signed approval are required")
	}
	envelope := &signed.Envelope

	// The anchor decides the infrastructure, the machine, the active epoch and
	// the key. An App recovered with a new human key therefore fails right
	// here, and stays failing until the Assistant rotates this file over the
	// personal SSH access: the Controller cannot perform that rotation, so it
	// cannot lift the lock on its own.
	if err := anchor.Binds(envelope); err != nil {
		return nil, err
	}

	// The subject decides which operations may run at all, before the clock and
	// before the state: an envelope presented to the wrong subject is refused
	// for being the wrong kind of approval, not for being late or replayed.
	if err := requireSubject(envelope); err != nil {
		return nil, err
	}

	if nowUnixSeconds < envelope.IssuedAtUnix {
		return nil, errors.New("approval is not valid yet on this machine's clock")
	}
	if nowUnixSeconds >= envelope.ExpiresAtUnix {
		return nil, errors.New("approval has expired")
	}

	anchoredKey, err := anchor.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := signed.VerifySignature(anchoredKey); err != nil {
		return nil, err
	}

	state, err := Consume(directory, anchor, envelope)
	if err != nil {
		return nil, err
	}
	return &Acceptance{Envelope: envelope, State: state}, nil
}
