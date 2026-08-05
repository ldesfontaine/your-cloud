// Package approval verifies a human approval on the machine it is presented
// to, without trusting the Controller that carried it.
//
// The Controller builds the plan and transports the envelope. This package
// assumes it may also have rewritten it, replayed it or invented it, and gives
// it exactly one power: delivering bytes. Everything an approval means is
// re-derived here from the fields, checked against the machine's own root-owned
// anchor, and spent once in the machine's own root-owned anti-replay state.
//
// The transcript below is the counterpart of the one written in
// console/src-tauri/crates/bootstrap-protocol/src/approval.rs. The two are held
// against one another by deterministic vectors on both sides rather than by
// reading, because a canonical encoding that exists in two implementations is
// only canonical while the two agree byte for byte.
package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// SchemaVersion is the one envelope version this palier reads.
	SchemaVersion = 1

	// TranscriptDomain separates this signature from every other transcript the
	// same human key signs. Its terminating NUL cannot appear in any textual
	// field, so no prefix of one transcript is a prefix of another.
	TranscriptDomain = "your-cloud/approval-envelope.v1\x00"

	// DigestBytes is the length of the plan and rollback digests.
	DigestBytes = 32

	// MaxSignedApprovalBytes bounds the document before it is parsed. The
	// envelope is a fixed set of bounded fields; this is the size they reach.
	MaxSignedApprovalBytes = 1024

	// MaxLifetimeSeconds bounds how long an approval may remain presentable.
	MaxLifetimeSeconds = 900

	// MaxPrivileges is the size of the closed privilege set below.
	MaxPrivileges = 2

	// OperationDiagnoseProtocolReadOnly is the one operation this palier
	// approves. It reads and reports; it changes nothing.
	OperationDiagnoseProtocolReadOnly = "diagnose_protocol_read_only"

	// PrivilegeReadLocalState allows reading what the machine already holds.
	PrivilegeReadLocalState = "read_local_state"
	// PrivilegeMutateLocalState allows changing the machine. No operation of
	// this palier requires it, and every envelope naming it is refused. It is
	// named here so that refusal is something a document can actually run into
	// rather than the absence of a feature.
	PrivilegeMutateLocalState = "mutate_local_state"
)

// requiredPrivileges is the exact list each operation must carry. Equality is
// required rather than inclusion: an envelope asking for less than its
// operation needs is not a narrower approval, it is an unrecognised one.
var requiredPrivileges = map[string][]string{
	OperationDiagnoseProtocolReadOnly: {PrivilegeReadLocalState},
}

var (
	canonicalUUIDv4  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	canonicalDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	canonicalMachine = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
)

// Envelope is exactly what the Console signed. Every field below is inside the
// transcript, and no field of an approval lives outside it.
type Envelope struct {
	SchemaVersion     int      `json:"schema_version"`
	InfrastructureID  string   `json:"infrastructure_id"`
	MachineID         string   `json:"machine_id"`
	ApprovalEpoch     uint64   `json:"approval_epoch"`
	Sequence          uint64   `json:"sequence"`
	Operation         string   `json:"operation"`
	PlanSHA256        string   `json:"plan_sha256"`
	RollbackSHA256    string   `json:"rollback_sha256"`
	Privileges        []string `json:"privileges"`
	IssuedAtUnix      uint64   `json:"issued_at_unix_seconds"`
	ExpiresAtUnix     uint64   `json:"expires_at_unix_seconds"`
	ApprovalPublicKey string   `json:"approval_public_key"`
}

// SignedApproval is the whole document the Controller transports.
type SignedApproval struct {
	Envelope  Envelope `json:"envelope"`
	Signature string   `json:"signature"`
}

// DecodeSigned accepts one bounded, strict, fully validated document.
//
// It never returns a partially checked envelope: a caller that holds one may
// assume every field is inside its own bounds, which is what lets the checks
// that follow be about authority rather than about shape.
func DecodeSigned(document []byte) (*SignedApproval, error) {
	if len(document) == 0 || len(document) > MaxSignedApprovalBytes {
		return nil, fmt.Errorf("signed approval must contain 1..%d bytes", MaxSignedApprovalBytes)
	}
	var signed SignedApproval
	if err := strictjson.Decode(document, &signed); err != nil {
		return nil, fmt.Errorf("decode signed approval: %w", err)
	}
	if _, err := decodeRawURL(signed.Signature, ed25519.SignatureSize); err != nil {
		return nil, fmt.Errorf("approval signature: %w", err)
	}
	if err := signed.Envelope.validate(); err != nil {
		return nil, err
	}
	return &signed, nil
}

func (envelope *Envelope) validate() error {
	if envelope.SchemaVersion != SchemaVersion {
		return errors.New("approval envelope schema version is unsupported")
	}
	if !canonicalUUIDv4.MatchString(envelope.InfrastructureID) {
		return errors.New("approval infrastructure_id must be a canonical lower-case UUIDv4")
	}
	if !canonicalMachine.MatchString(envelope.MachineID) {
		return errors.New("approval machine_id is malformed")
	}
	if envelope.ApprovalEpoch == 0 {
		return errors.New("approval epoch must be positive")
	}
	if envelope.Sequence == 0 {
		return errors.New("approval sequence must be positive")
	}
	if !canonicalDigest.MatchString(envelope.PlanSHA256) {
		return errors.New("approval plan_sha256 must be lower-case hexadecimal SHA-256")
	}
	if !canonicalDigest.MatchString(envelope.RollbackSHA256) {
		return errors.New("approval rollback_sha256 must be lower-case hexadecimal SHA-256")
	}
	if err := envelope.validatePrivileges(); err != nil {
		return err
	}
	if envelope.IssuedAtUnix == 0 || envelope.ExpiresAtUnix <= envelope.IssuedAtUnix {
		return errors.New("approval must expire strictly after it was issued")
	}
	if envelope.ExpiresAtUnix-envelope.IssuedAtUnix > MaxLifetimeSeconds {
		return fmt.Errorf("approval may not live longer than %d seconds", MaxLifetimeSeconds)
	}
	if _, err := decodeRawURL(envelope.ApprovalPublicKey, ed25519.PublicKeySize); err != nil {
		return fmt.Errorf("approval public key: %w", err)
	}
	return nil
}

// validatePrivileges requires the exact canonical list the operation declares.
//
// The list must be strictly increasing, which removes both repetition and
// ordering: two envelopes granting the same set have the same bytes, so a
// transport cannot build a second valid document by permuting the first.
func (envelope *Envelope) validatePrivileges() error {
	required, known := requiredPrivileges[envelope.Operation]
	if !known {
		return fmt.Errorf("approval operation %q is not one this Auxiliary performs", envelope.Operation)
	}
	if len(envelope.Privileges) == 0 || len(envelope.Privileges) > MaxPrivileges {
		return fmt.Errorf("approval must carry 1..%d privileges", MaxPrivileges)
	}
	for index := 1; index < len(envelope.Privileges); index++ {
		if envelope.Privileges[index-1] >= envelope.Privileges[index] {
			return errors.New("approval privileges must be a strictly increasing set")
		}
	}
	if len(envelope.Privileges) != len(required) {
		return fmt.Errorf("approval operation %q requires exactly its own privileges", envelope.Operation)
	}
	for index, privilege := range required {
		if envelope.Privileges[index] != privilege {
			return fmt.Errorf("approval operation %q requires exactly its own privileges", envelope.Operation)
		}
	}
	return nil
}

// IsMutating reports whether the envelope asks for anything that could change
// the machine. Nothing this palier performs may, so this is a refusal and not
// a branch.
func (envelope *Envelope) IsMutating() bool {
	for _, privilege := range envelope.Privileges {
		if privilege == PrivilegeMutateLocalState {
			return true
		}
	}
	return false
}

// SigningTranscript rebuilds the exact bytes the Console signed.
//
// It is built from the parsed fields and never from the received document, so
// a Controller that reindents or reorders the JSON transports the same
// approval, while a Controller that changes one value transports a document
// whose signature no longer verifies.
func (envelope *Envelope) SigningTranscript() ([]byte, error) {
	publicKey, err := decodeRawURL(envelope.ApprovalPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("approval public key: %w", err)
	}
	plan, err := hex.DecodeString(envelope.PlanSHA256)
	if err != nil || len(plan) != DigestBytes {
		return nil, errors.New("approval plan digest is malformed")
	}
	rollback, err := hex.DecodeString(envelope.RollbackSHA256)
	if err != nil || len(rollback) != DigestBytes {
		return nil, errors.New("approval rollback digest is malformed")
	}
	if envelope.SchemaVersion < 0 || envelope.SchemaVersion > 255 {
		return nil, errors.New("approval schema version does not fit its field")
	}

	transcript := make([]byte, 0, len(TranscriptDomain)+256)
	transcript = append(transcript, TranscriptDomain...)
	transcript = append(transcript, byte(envelope.SchemaVersion))
	transcript = appendField(transcript, []byte(envelope.InfrastructureID))
	transcript = appendField(transcript, []byte(envelope.MachineID))
	transcript = appendUint64(transcript, envelope.ApprovalEpoch)
	transcript = appendUint64(transcript, envelope.Sequence)
	transcript = appendField(transcript, []byte(envelope.Operation))
	transcript = appendField(transcript, plan)
	transcript = appendField(transcript, rollback)
	transcript = appendUint32(transcript, uint32(len(envelope.Privileges)))
	for _, privilege := range envelope.Privileges {
		transcript = appendField(transcript, []byte(privilege))
	}
	transcript = appendUint64(transcript, envelope.IssuedAtUnix)
	transcript = appendUint64(transcript, envelope.ExpiresAtUnix)
	transcript = appendField(transcript, publicKey)
	return transcript, nil
}

// VerifySignature checks the document against the key the caller decided to
// trust, which is never the key the document itself names.
//
// The envelope carries its own public key so that a mismatch with the anchor is
// visible, but trusting that key would make the signature a decoration: whoever
// can write the document can write the key beside it. The anchor is therefore
// the only argument here.
func (signed *SignedApproval) VerifySignature(anchoredKey ed25519.PublicKey) error {
	if len(anchoredKey) != ed25519.PublicKeySize {
		return errors.New("anchored approval key is malformed")
	}
	declared, err := decodeRawURL(signed.Envelope.ApprovalPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("approval public key: %w", err)
	}
	if !equalBytes(declared, anchoredKey) {
		return errors.New("approval was signed for a key this machine does not anchor")
	}
	transcript, err := signed.Envelope.SigningTranscript()
	if err != nil {
		return err
	}
	signature, err := decodeRawURL(signed.Signature, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("approval signature: %w", err)
	}
	if !ed25519.Verify(anchoredKey, transcript, signature) {
		return errors.New("approval signature does not cover this envelope")
	}
	return nil
}

func appendField(buffer []byte, value []byte) []byte {
	buffer = appendUint32(buffer, uint32(len(value)))
	return append(buffer, value...)
}

func appendUint32(buffer []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func appendUint64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}

// decodeRawURL accepts raw-URL base64 of exactly the expected length and
// refuses every other spelling of the same bytes, padding included.
func decodeRawURL(value string, expected int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("value must be canonical raw-URL base64")
	}
	if len(decoded) != expected {
		return nil, fmt.Errorf("value must decode to exactly %d bytes", expected)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("value must be canonical raw-URL base64")
	}
	return decoded, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
