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

// Accept verifies one approval against this machine's own anchor and spends its
// sequence, in that order.
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
	if anchor == nil || signed == nil {
		return nil, errors.New("an anchor and a signed approval are required")
	}
	envelope := &signed.Envelope

	// The anchor decides the infrastructure, the machine, the active epoch and
	// the key. A Console recovered with a new human key therefore fails right
	// here, and stays failing until the Assistant rotates this file over the
	// personal SSH access: the Controller cannot perform that rotation, so it
	// cannot lift the lock on its own.
	if err := anchor.Binds(envelope); err != nil {
		return nil, err
	}

	// Every mutation is still refused in this palier. The check is here rather
	// than only in the schema so that it is a refusal of the *operation about to
	// run*, and so that no future operation can reach the state by being added
	// to the table without being thought about.
	if envelope.IsMutating() {
		return nil, errors.New("this Auxiliary performs no mutation: the approval asks for one")
	}
	if envelope.Operation != OperationDiagnoseProtocolReadOnly {
		return nil, fmt.Errorf("approval operation %q is not one this Auxiliary performs", envelope.Operation)
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
