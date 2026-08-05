package approval

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/securefile"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// AnchorPath is fixed so that no argument, environment variable or transported
// field can point this machine's trust at a file somebody else owns.
//
// The Assistant installs it over the personal SSH access, as root, and the
// Controller never writes it. That is the whole separation this palier rests
// on: the Controller may transport an approval, but it cannot decide which key
// approves.
const AnchorPath = "/etc/your-cloud/approval-anchor.json"

// MaxAnchorBytes bounds the anchor before it is parsed.
const MaxAnchorBytes = 512

// Anchor is what one machine believes about who may approve on it.
//
// It names an infrastructure, itself, one epoch and one key. There is no list:
// activating a new epoch replaces this file instead of adding a second signer,
// so two approval authorities are never simultaneously valid on one machine.
type Anchor struct {
	SchemaVersion     int    `json:"schema_version"`
	InfrastructureID  string `json:"infrastructure_id"`
	MachineID         string `json:"machine_id"`
	ApprovalEpoch     uint64 `json:"approval_epoch"`
	ApprovalPublicKey string `json:"approval_public_key"`
}

// ReadAnchor loads the anchor from a canonical, root-owned, non-group-writable
// file reached through one descriptor and no final symbolic link.
func ReadAnchor(path string) (*Anchor, error) {
	data, err := securefile.ReadRootOwned(path, MaxAnchorBytes)
	if err != nil {
		return nil, fmt.Errorf("approval anchor: %w", err)
	}
	return DecodeAnchor(data)
}

// DecodeAnchor accepts one strict, fully validated anchor document.
func DecodeAnchor(document []byte) (*Anchor, error) {
	if len(document) == 0 || len(document) > MaxAnchorBytes {
		return nil, fmt.Errorf("approval anchor must contain 1..%d bytes", MaxAnchorBytes)
	}
	var anchor Anchor
	if err := strictjson.Decode(document, &anchor); err != nil {
		return nil, fmt.Errorf("decode approval anchor: %w", err)
	}
	if anchor.SchemaVersion != SchemaVersion {
		return nil, errors.New("approval anchor schema version is unsupported")
	}
	if !canonicalUUIDv4.MatchString(anchor.InfrastructureID) {
		return nil, errors.New("approval anchor infrastructure_id must be a canonical lower-case UUIDv4")
	}
	if !canonicalMachine.MatchString(anchor.MachineID) {
		return nil, errors.New("approval anchor machine_id is malformed")
	}
	if anchor.ApprovalEpoch == 0 {
		return nil, errors.New("approval anchor epoch must be positive")
	}
	if _, err := decodeRawURL(anchor.ApprovalPublicKey, ed25519.PublicKeySize); err != nil {
		return nil, fmt.Errorf("approval anchor public key: %w", err)
	}
	return &anchor, nil
}

// PublicKey returns the one key this machine accepts approvals from.
func (anchor *Anchor) PublicKey() (ed25519.PublicKey, error) {
	decoded, err := decodeRawURL(anchor.ApprovalPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("approval anchor public key: %w", err)
	}
	return ed25519.PublicKey(decoded), nil
}

// Binds checks that an envelope is addressed to this very machine under this
// very authority.
//
// Target, infrastructure and epoch are checked together because each of them
// alone would leave a way in: an approval for another machine of the same
// infrastructure, an approval for the same machine name in another
// infrastructure, and an approval from an epoch this machine has replaced.
func (anchor *Anchor) Binds(envelope *Envelope) error {
	if envelope.InfrastructureID != anchor.InfrastructureID {
		return errors.New("approval names another infrastructure than this machine's anchor")
	}
	if envelope.MachineID != anchor.MachineID {
		return errors.New("approval names another machine than this one")
	}
	if envelope.ApprovalEpoch != anchor.ApprovalEpoch {
		return errors.New("approval names another authority epoch than this machine's anchor")
	}
	if envelope.ApprovalPublicKey != anchor.ApprovalPublicKey {
		return errors.New("approval was signed for a key this machine does not anchor")
	}
	return nil
}
