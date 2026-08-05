package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// signedVector builds the whole document the Controller would transport, signed
// by the synthetic vector key.
func signedVector(t *testing.T, mutate func(*Envelope)) *SignedApproval {
	t.Helper()
	envelope := vectorEnvelope()
	if mutate != nil {
		mutate(&envelope)
	}
	return &SignedApproval{Envelope: envelope, Signature: signVector(t, envelope)}
}

const nowInsideWindow = uint64(vectorIssuedAt + 10)

// TestAcceptRunsOnceAndRefusesEveryReplay is the observable result of the
// palier, end to end: one approval is accepted exactly once, and presenting it
// again is refused by the machine itself.
func TestAcceptRunsOnceAndRefusesEveryReplay(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()
	signed := signedVector(t, nil)

	accepted, err := Accept(directory, anchor, signed, nowInsideWindow)
	if err != nil {
		t.Fatalf("the nominal approval must be accepted: %v", err)
	}
	if accepted.State.ConsumedSequence != 1 || accepted.Envelope.Operation != OperationDiagnoseProtocolReadOnly {
		t.Fatalf("unexpected acceptance: %+v", accepted)
	}

	if _, err := Accept(directory, anchor, signed, nowInsideWindow); err == nil {
		t.Fatal("the very same approval was accepted twice")
	}

	// The successor, correctly signed, is still accepted afterwards: the
	// refusal above is about replay, not about the machine being closed.
	next := signedVector(t, func(e *Envelope) { e.Sequence = 2 })
	if _, err := Accept(directory, anchor, next, nowInsideWindow); err != nil {
		t.Fatalf("the exact successor must remain acceptable: %v", err)
	}
}

// TestAcceptRefusesEveryWrongTargetKeyEpochSequenceSignatureAndExpiry walks the
// acceptance criterion of the issue one refusal at a time, each beside the
// positive control that shows only that one thing was wrong.
func TestAcceptRefusesEveryWrongTargetKeyEpochSequenceSignatureAndExpiry(t *testing.T) {
	anchor := vectorAnchor()
	forger := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	forgerPublic := base64.RawURLEncoding.EncodeToString(forger.Public().(ed25519.PublicKey))

	cases := map[string]struct {
		signed *SignedApproval
		now    uint64
	}{
		"wrong machine": {
			signed: func() *SignedApproval {
				return signedVector(t, func(e *Envelope) { e.MachineID = "lab-machine-2" })
			}(),
			now: nowInsideWindow,
		},
		"wrong infrastructure": {
			signed: func() *SignedApproval {
				return signedVector(t, func(e *Envelope) {
					e.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"
				})
			}(),
			now: nowInsideWindow,
		},
		"wrong epoch": {
			signed: func() *SignedApproval {
				return signedVector(t, func(e *Envelope) { e.ApprovalEpoch = 2 })
			}(),
			now: nowInsideWindow,
		},
		"wrong key": {
			signed: func() *SignedApproval {
				envelope := vectorEnvelope()
				envelope.ApprovalPublicKey = forgerPublic
				transcript, err := envelope.SigningTranscript()
				if err != nil {
					t.Fatal(err)
				}
				return &SignedApproval{
					Envelope:  envelope,
					Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(forger, transcript)),
				}
			}(),
			now: nowInsideWindow,
		},
		"wrong sequence": {
			signed: func() *SignedApproval {
				return signedVector(t, func(e *Envelope) { e.Sequence = 7 })
			}(),
			now: nowInsideWindow,
		},
		"broken signature": {
			signed: func() *SignedApproval {
				signed := signedVector(t, nil)
				signed.Signature = base64.RawURLEncoding.EncodeToString(
					make([]byte, ed25519.SignatureSize),
				)
				return signed
			}(),
			now: nowInsideWindow,
		},
		"expired": {
			signed: signedVector(t, nil),
			now:    vectorExpires,
		},
		"not valid yet": {
			signed: signedVector(t, nil),
			now:    vectorIssuedAt - 1,
		},
	}

	for name, scenario := range cases {
		directory := requireRootLAB(t)
		// Positive control on this very directory: the untouched approval is
		// accepted, so each refusal below is about its own single difference.
		if _, err := Accept(directory, anchor, signedVector(t, nil), nowInsideWindow); err != nil {
			t.Fatalf("positive control refused before %q: %v", name, err)
		}

		fresh := requireRootLAB(t)
		if _, err := Accept(fresh, anchor, scenario.signed, scenario.now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		// A refusal spends nothing: the first sequence is still available.
		if _, err := Accept(fresh, anchor, signedVector(t, nil), nowInsideWindow); err != nil {
			t.Fatalf("%s spent the sequence it was refused on: %v", name, err)
		}
	}
}

// TestAcceptRefusesEveryMutation is the palier's own limit, checked on the
// operation that is about to run rather than only on the schema.
func TestAcceptRefusesEveryMutation(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	mutating := signedVector(t, func(e *Envelope) {
		e.Privileges = []string{PrivilegeMutateLocalState}
	})
	if _, err := Accept(directory, anchor, mutating, nowInsideWindow); err == nil {
		t.Fatal("an approval carrying a mutating privilege was accepted")
	}

	foreign := signedVector(t, func(e *Envelope) { e.Operation = "install_container" })
	if _, err := Accept(directory, anchor, foreign, nowInsideWindow); err == nil {
		t.Fatal("an approval naming an operation this Auxiliary does not perform was accepted")
	}

	// Neither of them spent anything, and the read-only approval still works.
	accepted, err := Accept(directory, anchor, signedVector(t, nil), nowInsideWindow)
	if err != nil {
		t.Fatalf("the read-only approval must remain acceptable: %v", err)
	}
	if accepted.Envelope.IsMutating() {
		t.Fatal("an accepted approval of this palier reported a mutation")
	}
}

// TestANewHumanKeyLeavesTheActionLockedUntilTheAnchorIsRotated is the recovery
// rule: replacing the Console's human key restores nothing on a machine until
// the Assistant rotates that machine's anchor over the personal SSH access.
//
// The Controller is never given that power here: what lifts the lock is a new
// anchor file, which only root on the machine can install.
func TestANewHumanKeyLeavesTheActionLockedUntilTheAnchorIsRotated(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	if _, err := Accept(directory, anchor, signedVector(t, nil), nowInsideWindow); err != nil {
		t.Fatalf("the association must work before the recovery: %v", err)
	}

	// The Console is recovered on another device and its human key changes.
	recoveredSeed := make([]byte, ed25519.SeedSize)
	for index := range recoveredSeed {
		recoveredSeed[index] = 5
	}
	recovered := ed25519.NewKeyFromSeed(recoveredSeed)
	recoveredPublic := base64.RawURLEncoding.EncodeToString(recovered.Public().(ed25519.PublicKey))

	signWith := func(envelope Envelope) *SignedApproval {
		transcript, err := envelope.SigningTranscript()
		if err != nil {
			t.Fatal(err)
		}
		return &SignedApproval{
			Envelope:  envelope,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(recovered, transcript)),
		}
	}

	afterRecovery := vectorEnvelope()
	afterRecovery.Sequence = 2
	afterRecovery.ApprovalPublicKey = recoveredPublic
	if _, err := Accept(directory, anchor, signWith(afterRecovery), nowInsideWindow); err == nil {
		t.Fatal("a recovered Console acted before its anchor was rotated")
	}

	// Keeping the old declared key while signing with the new one does not help
	// either: the signature is what the anchor checks.
	pretending := vectorEnvelope()
	pretending.Sequence = 2
	if _, err := Accept(directory, anchor, signWith(pretending), nowInsideWindow); err == nil {
		t.Fatal("a recovered Console acted by keeping the previous declared key")
	}

	// The Assistant rotates the anchor, machine by machine, over the personal
	// access: new epoch, new key. Only then does the path reopen.
	rotated := &Anchor{
		SchemaVersion:     SchemaVersion,
		InfrastructureID:  vectorInfrastructure,
		MachineID:         vectorMachine,
		ApprovalEpoch:     2,
		ApprovalPublicKey: recoveredPublic,
	}
	reopened := vectorEnvelope()
	reopened.ApprovalEpoch = 2
	reopened.Sequence = 1
	reopened.ApprovalPublicKey = recoveredPublic
	accepted, err := Accept(directory, rotated, signWith(reopened), nowInsideWindow)
	if err != nil {
		t.Fatalf("the rotated anchor must reopen the path: %v", err)
	}
	if accepted.State.ApprovalEpoch != 2 || accepted.State.ConsumedSequence != 1 {
		t.Fatalf("unexpected position after rotation: %+v", accepted.State)
	}

	// And the previous authority is gone rather than kept beside the new one.
	if _, err := Accept(directory, anchor, signedVector(t, func(e *Envelope) { e.Sequence = 2 }), nowInsideWindow); err == nil {
		t.Fatal("the previous approval key still acted after the rotation")
	}
}
