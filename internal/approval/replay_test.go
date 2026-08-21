package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// requireRootLAB keeps every check of this file honest: the anchor and the
// anti-replay state are only meaningful under the ownership and modes the
// isolated root runner really has.
func requireRootLAB(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require the isolated root LAB runner")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func vectorAnchor() *Anchor {
	return &Anchor{
		SchemaVersion:     SchemaVersion,
		InfrastructureID:  vectorInfrastructure,
		MachineID:         vectorMachine,
		ApprovalEpoch:     1,
		ApprovalPublicKey: vectorPublicKey,
	}
}

func envelopeAt(epoch, sequence uint64) *Envelope {
	envelope := vectorEnvelope()
	envelope.ApprovalEpoch = epoch
	envelope.Sequence = sequence
	return &envelope
}

// TestOnlyTheExactSuccessorIsEverConsumed walks the one accepted series and, at
// each step, holds every neighbouring sequence against it.
func TestOnlyTheExactSuccessorIsEverConsumed(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	// A machine that consumed nothing opens at one and at nothing else.
	for _, sequence := range []uint64{2, 3, 42} {
		if _, err := Consume(directory, anchor, envelopeAt(1, sequence)); err == nil {
			t.Fatalf("sequence %d opened a series on a machine that consumed none", sequence)
		}
	}
	state, err := Consume(directory, anchor, envelopeAt(1, 1))
	if err != nil {
		t.Fatalf("the first sequence must be accepted: %v", err)
	}
	if state.ConsumedSequence != 1 || state.ApprovalEpoch != 1 {
		t.Fatalf("unexpected position after the first approval: %+v", state)
	}

	// Replay, older, and skipped are three different refusals of the same rule.
	for name, sequence := range map[string]uint64{"replayed": 1, "skipped": 3, "far ahead": 1000} {
		if _, err := Consume(directory, anchor, envelopeAt(1, sequence)); err == nil {
			t.Fatalf("a %s sequence was consumed", name)
		}
	}

	if _, err := Consume(directory, anchor, envelopeAt(1, 2)); err != nil {
		t.Fatalf("the exact successor must be accepted: %v", err)
	}
	// And the sequence that was just the successor is now a replay.
	if _, err := Consume(directory, anchor, envelopeAt(1, 2)); err == nil {
		t.Fatal("the successor was consumed twice")
	}
	// An older one stays refused for good.
	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err == nil {
		t.Fatal("an older sequence was reopened")
	}
}

// TestTheAntiReplayPositionSurvivesTheProcessThatWroteIt is the unit-level
// counterpart of the LAB reboot: the position is re-read from the filesystem by
// a caller that shares nothing with the one that wrote it.
//
// A real reboot of a LAB machine proves the same property against a real power
// cycle; this one proves it on every run of the suite, and it is the assertion
// the mutation proof of this palier is aimed at.
func TestTheAntiReplayPositionSurvivesTheProcessThatWroteIt(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err != nil {
		t.Fatal(err)
	}
	// Nothing of the first call is carried over: the file is all there is.
	persisted, err := readState(directory)
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil || persisted.ConsumedSequence != 1 {
		t.Fatalf("the position was not persisted: %+v", persisted)
	}
	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err == nil {
		t.Fatal("a sequence was replayed against the persisted position")
	}
	if _, err := Consume(directory, anchor, envelopeAt(1, 2)); err != nil {
		t.Fatalf("the successor of the persisted position must be accepted: %v", err)
	}
}

// TestConsumingIsAtomicAndExclusive proves the two properties of the write: a
// second Auxiliary holding the same instant is refused rather than queued, and
// the file left behind is always one whole position.
func TestConsumingIsAtomicAndExclusive(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	held, err := acquire(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err == nil {
		held.release()
		t.Fatal("a concurrent approval was consumed while another held the lock")
	}
	held.release()

	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err != nil {
		t.Fatalf("the approval must be accepted once the lock is free: %v", err)
	}
	// No temporary file survives a successful write.
	if _, err := os.Stat(StatePath(directory) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("a temporary anti-replay state survived the rename")
	}
	info, err := os.Stat(StatePath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the anti-replay state is readable or writable outside root: %v", info.Mode())
	}
}

// TestANewEpochInvalidatesTheOldOneInsteadOfCoexisting is the rule that keeps a
// replaced App from leaving two signers behind.
func TestANewEpochInvalidatesTheOldOneInsteadOfCoexisting(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	for sequence := uint64(1); sequence <= 3; sequence++ {
		if _, err := Consume(directory, anchor, envelopeAt(1, sequence)); err != nil {
			t.Fatal(err)
		}
	}

	rotated := vectorAnchor()
	rotated.ApprovalEpoch = 2
	rotated.ApprovalPublicKey = base64.RawURLEncoding.EncodeToString(
		ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey),
	)

	// The new epoch starts over at one, and only at one.
	if _, err := Consume(directory, rotated, envelopeAt(2, 4)); err == nil {
		t.Fatal("the new epoch continued the previous series")
	}
	rotatedEnvelope := envelopeAt(2, 1)
	rotatedEnvelope.ApprovalPublicKey = rotated.ApprovalPublicKey
	if _, err := Consume(directory, rotated, rotatedEnvelope); err != nil {
		t.Fatalf("the first sequence of the new epoch must be accepted: %v", err)
	}

	// The previous epoch is gone: even an anchor rolled back to it cannot
	// resurrect a sequence it had already spent, nor open a fresh one.
	for _, sequence := range []uint64{1, 4, 5} {
		if _, err := Consume(directory, anchor, envelopeAt(1, sequence)); err == nil {
			t.Fatalf("epoch 1 sequence %d was accepted after epoch 2 was activated", sequence)
		}
	}
}

// TestTheStateIsBoundToTheMachineItBelongsTo refuses a position copied from
// another machine or another infrastructure instead of continuing its series.
func TestTheStateIsBoundToTheMachineItBelongsTo(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()
	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err != nil {
		t.Fatal(err)
	}

	foreign := vectorAnchor()
	foreign.MachineID = "lab-machine-2"
	foreignEnvelope := envelopeAt(1, 2)
	foreignEnvelope.MachineID = "lab-machine-2"
	if _, err := Consume(directory, foreign, foreignEnvelope); err == nil {
		t.Fatal("a position of another machine was continued")
	}

	otherInfrastructure := vectorAnchor()
	otherInfrastructure.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"
	otherEnvelope := envelopeAt(1, 2)
	otherEnvelope.InfrastructureID = otherInfrastructure.InfrastructureID
	if _, err := Consume(directory, otherInfrastructure, otherEnvelope); err == nil {
		t.Fatal("a position of another infrastructure was continued")
	}
}

// TestAnEnvelopeIsRefusedBeforeItReachesTheState keeps the anchor's own
// bindings in front of the sequence: an approval for another target must never
// be able to spend this machine's numbers.
func TestAnEnvelopeIsRefusedBeforeItReachesTheState(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	elsewhere := envelopeAt(1, 1)
	elsewhere.MachineID = "lab-machine-2"
	if _, err := Consume(directory, anchor, elsewhere); err == nil {
		t.Fatal("an approval for another machine was consumed")
	}
	if state, err := readState(directory); err != nil || state != nil {
		t.Fatalf("a refused approval left a position behind: %+v %v", state, err)
	}
	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err != nil {
		t.Fatalf("the refusal must not have spent the first sequence: %v", err)
	}
}

// TestAnUnreadableStateIsNeverAnAbsentOne closes the way a corrupted file could
// otherwise reopen a spent series.
func TestAnUnreadableStateIsNeverAnAbsentOne(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()
	if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err != nil {
		t.Fatal(err)
	}

	for _, corrupted := range []string{
		"",
		"{",
		`{"schema_version":2,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":1,"consumed_sequence":1}`,
		`{"schema_version":1,"infrastructure_id":"forged","machine_id":"` + vectorMachine + `","approval_epoch":1,"consumed_sequence":1}`,
		`{"schema_version":1,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":0,"consumed_sequence":1}`,
		`{"schema_version":1,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":1,"consumed_sequence":1,"forged":true}`,
	} {
		if err := os.WriteFile(StatePath(directory), []byte(corrupted), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Consume(directory, anchor, envelopeAt(1, 1)); err == nil {
			t.Fatalf("a corrupted state was read as an absent one: %q", corrupted)
		}
	}
}

// TestTheStateDirectoryMustBeRootOwned refuses to keep an anti-replay position
// anywhere a non-root account could rewrite it.
func TestTheStateDirectoryMustBeRootOwned(t *testing.T) {
	directory := requireRootLAB(t)
	anchor := vectorAnchor()

	writable := filepath.Join(directory, "open")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Consume(writable, anchor, envelopeAt(1, 1)); err == nil {
		t.Fatal("a world-writable directory was used to hold the anti-replay state")
	}

	linked := filepath.Join(directory, "linked")
	if err := os.Symlink(directory, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Consume(linked, anchor, envelopeAt(1, 1)); err == nil {
		t.Fatal("a symbolic link was accepted as the anti-replay directory")
	}
	for _, path := range []string{"relative", "/var/lib/../lib/your-cloud-auxiliary"} {
		if _, err := Consume(path, anchor, envelopeAt(1, 1)); err == nil {
			t.Fatalf("%q was accepted as the anti-replay directory", path)
		}
	}
}

func TestReadAnchorRefusesEveryAnchorOutsideTheSchema(t *testing.T) {
	directory := requireRootLAB(t)
	path := filepath.Join(directory, "approval-anchor.json")

	nominal := fmt.Sprintf(
		`{"schema_version":1,"infrastructure_id":%q,"machine_id":%q,"approval_epoch":1,"approval_public_key":%q}`,
		vectorInfrastructure, vectorMachine, vectorPublicKey,
	)
	if err := os.WriteFile(path, []byte(nominal), 0o600); err != nil {
		t.Fatal(err)
	}
	anchor, err := ReadAnchor(path)
	if err != nil {
		t.Fatalf("the nominal anchor must be read: %v", err)
	}
	if _, err := anchor.PublicKey(); err != nil {
		t.Fatal(err)
	}
	if err := anchor.Binds(envelopeAt(1, 1)); err != nil {
		t.Fatalf("the nominal anchor must bind its own envelope: %v", err)
	}

	for name, document := range map[string]string{
		"unsupported schema":    `{"schema_version":2,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":1,"approval_public_key":"` + vectorPublicKey + `"}`,
		"forged infrastructure": `{"schema_version":1,"infrastructure_id":"forged","machine_id":"` + vectorMachine + `","approval_epoch":1,"approval_public_key":"` + vectorPublicKey + `"}`,
		"traversal machine":     `{"schema_version":1,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"../../root","approval_epoch":1,"approval_public_key":"` + vectorPublicKey + `"}`,
		"zero epoch":            `{"schema_version":1,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":0,"approval_public_key":"` + vectorPublicKey + `"}`,
		"short key":             `{"schema_version":1,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":1,"approval_public_key":"AAAA"}`,
		"unknown field":         `{"schema_version":1,"infrastructure_id":"` + vectorInfrastructure + `","machine_id":"` + vectorMachine + `","approval_epoch":1,"approval_public_key":"` + vectorPublicKey + `","forged":true}`,
	} {
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadAnchor(path); err == nil {
			t.Fatalf("%s anchor was accepted", name)
		}
	}

	// A group-writable anchor is not this machine's anchor.
	if err := os.WriteFile(path, []byte(nominal), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnchor(path); err == nil {
		t.Fatal("a group-writable anchor was accepted")
	}
}

// TestTheAnchorBindsEveryTargetFieldOfTheEnvelope holds each binding on its own
// so that no single one of them is silently carrying the other three.
func TestTheAnchorBindsEveryTargetFieldOfTheEnvelope(t *testing.T) {
	t.Parallel()
	anchor := vectorAnchor()
	if err := anchor.Binds(envelopeAt(1, 1)); err != nil {
		t.Fatalf("the positive control must bind: %v", err)
	}
	for name, mutate := range map[string]func(*Envelope){
		"infrastructure": func(e *Envelope) { e.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3" },
		"machine":        func(e *Envelope) { e.MachineID = "lab-machine-2" },
		"epoch":          func(e *Envelope) { e.ApprovalEpoch = 2 },
		"key": func(e *Envelope) {
			e.ApprovalPublicKey = base64.RawURLEncoding.EncodeToString(
				ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey),
			)
		},
	} {
		envelope := envelopeAt(1, 1)
		mutate(envelope)
		if err := anchor.Binds(envelope); err == nil {
			t.Fatalf("an approval with another %s was bound to this machine", name)
		}
	}
}
