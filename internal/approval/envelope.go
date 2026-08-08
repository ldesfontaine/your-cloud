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

	// OperationDiagnoseProtocolReadOnly reads and reports; it changes nothing,
	// and it stays the only operation the read-only subject performs.
	OperationDiagnoseProtocolReadOnly = "diagnose_protocol_read_only"

	// OperationDeployOCIProbe asks for the pinned probe to be present on this
	// machine, and OperationRemoveOCIProbe for that exact instance to be
	// absent. They are the first two operations of the product that may change
	// anything, and what they may change is described by a plan document whose
	// digest this envelope signs — never by the envelope itself.
	OperationDeployOCIProbe = "deploy_oci_probe"
	OperationRemoveOCIProbe = "remove_oci_probe"

	// The six operations of the public profile. Each of them mutates, each of
	// them is described by a plan document of schema 2 whose digest this
	// envelope signs, and each of them is named here beside the probe pair
	// rather than derived from it: an operation this Auxiliary may act on is a
	// decision written once, in a list a reader can count.
	OperationDeployWebService = "deploy_web_service"
	OperationRemoveWebService = "remove_web_service"
	OperationDeployEntrypoint = "deploy_entrypoint"
	OperationRemoveEntrypoint = "remove_entrypoint"
	OperationPublishRoute     = "publish_route"
	OperationRetireRoute      = "retire_route"

	// The six operations of the private passage. Each of them mutates, each of
	// them is described by a plan document of schema 3 whose digest this envelope
	// signs, and each of them is named here in the same closed list as the others
	// rather than derived from anything: an operation this Auxiliary may act on
	// is a decision written once, in a list a reader can count.
	//
	// Naming them here does not make them applicable. The envelope decides that a
	// human approved two digests for one operation; what acting on them means is
	// the Auxiliary's, and until the issues that own it land, an approval of one
	// of these six is refused there by name before any effect.
	OperationPrepareLink    = "prepare_link"
	OperationWithdrawLink   = "withdraw_link"
	OperationAttachLinkPeer = "attach_link_peer"
	OperationDetachLinkPeer = "detach_link_peer"
	OperationJoinLinkPeer   = "join_link_peer"
	OperationLeaveLinkPeer  = "leave_link_peer"

	// The seven operations of the private profile. Each of them is described by a
	// plan document of schema 2 whose digest this envelope signs, and each of them
	// mutates — the archive operations included: a snapshot stops the service,
	// writes an archive and starts it again, which is three changes to the machine
	// however read-only the word sounds.
	//
	// Naming them here does not make them applicable. The envelope decides that a
	// human approved two digests for one operation; what acting on them means is
	// the Auxiliary's, and until the issues that own it land, an approval of one
	// of these seven is refused there by name before any effect.
	OperationDeployPrivateService = "deploy_private_service"
	OperationRemovePrivateService = "remove_private_service"
	OperationPublishLinkRoute     = "publish_link_route"
	OperationRetireLinkRoute      = "retire_link_route"
	OperationSnapshotService      = "snapshot_service"
	OperationDiscardSnapshot      = "discard_snapshot"
	OperationRestoreService       = "restore_service"

	// The two operations of the third door. Both mutate, both are described by a
	// plan document of schema 2 whose digest this envelope signs, and both are
	// named here in the same closed list as the others rather than derived from
	// anything: an operation this Auxiliary may act on is a decision written once,
	// in a list a reader can count.
	//
	// They are the first operations of the product whose effects are described by
	// a document its user wrote. That changes nothing here: this envelope decides
	// that a human approved two digests for one operation, and it has never known
	// what those digests cover. Naming them does not make them applicable — until
	// `#119` lands, an approval of either is refused by the Auxiliary by name,
	// before any effect.
	OperationDeployUserService = "deploy_user_service"
	OperationRemoveUserService = "remove_user_service"

	// PrivilegeReadLocalState allows reading what the machine already holds.
	PrivilegeReadLocalState = "read_local_state"
	// PrivilegeMutateLocalState allows changing the machine. The read-only
	// operation still refuses every envelope naming it; the two probe
	// operations require it, and require it beside the read privilege, because
	// deciding whether a state already holds is itself a local read.
	PrivilegeMutateLocalState = "mutate_local_state"
)

// requiredPrivileges is the exact list each operation must carry. Equality is
// required rather than inclusion: an envelope asking for less than its
// operation needs is not a narrower approval, it is an unrecognised one.
//
// Each list is written in the strictly increasing order the envelope requires,
// so that the table cannot describe a set the validation would refuse. The Rust
// side pins the same two lists in the same order, and vectors on both sides hold
// the two spellings against one another.
var requiredPrivileges = map[string][]string{
	OperationDiagnoseProtocolReadOnly: {PrivilegeReadLocalState},
	OperationDeployOCIProbe:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRemoveOCIProbe:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationDeployWebService:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRemoveWebService:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationDeployEntrypoint:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRemoveEntrypoint:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationPublishRoute:             {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRetireRoute:              {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationPrepareLink:              {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationWithdrawLink:             {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationAttachLinkPeer:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationDetachLinkPeer:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationJoinLinkPeer:             {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationLeaveLinkPeer:            {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationDeployPrivateService:     {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRemovePrivateService:     {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationPublishLinkRoute:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRetireLinkRoute:          {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationSnapshotService:          {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationDiscardSnapshot:          {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRestoreService:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationDeployUserService:        {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	OperationRemoveUserService:        {PrivilegeMutateLocalState, PrivilegeReadLocalState},
}

// mutatingOperations is the closed list of operations that are allowed to reach
// a mutating acceptance. Holding it beside requiredPrivileges rather than
// deriving it from the privileges is deliberate: an operation added to the table
// above does not silently become one this machine will act on.
var mutatingOperations = map[string]struct{}{
	OperationDeployOCIProbe:   {},
	OperationRemoveOCIProbe:   {},
	OperationDeployWebService: {},
	OperationRemoveWebService: {},
	OperationDeployEntrypoint: {},
	OperationRemoveEntrypoint: {},
	OperationPublishRoute:     {},
	OperationRetireRoute:      {},
	OperationPrepareLink:      {},
	OperationWithdrawLink:     {},
	OperationAttachLinkPeer:   {},
	OperationDetachLinkPeer:   {},
	OperationJoinLinkPeer:     {},
	OperationLeaveLinkPeer:    {},
	// The private profile's seven. A snapshot is here beside the deployments
	// because it mutates: it stops the service, writes an archive and starts it
	// again.
	OperationDeployPrivateService: {},
	OperationRemovePrivateService: {},
	OperationPublishLinkRoute:     {},
	OperationRetireLinkRoute:      {},
	OperationSnapshotService:      {},
	OperationDiscardSnapshot:      {},
	OperationRestoreService:       {},
	// The third door's two. A user service is deployed and removed by the very
	// machinery the delivered profiles use, so its operations mutate exactly as
	// theirs do.
	OperationDeployUserService: {},
	OperationRemoveUserService: {},
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
// the machine.
//
// It is not a branch that selects what to do: each acceptance subject states
// which answer it requires, the read-only one refusing every mutation and the
// probe one refusing every envelope that would act without asking for it.
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
