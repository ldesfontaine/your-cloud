package controller

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/protocol"
)

type RecoveryKeyMutation struct {
	SchemaVersion         int    `json:"schema_version"`
	OperationID           string `json:"operation_id"`
	NextRecoveryEpoch     uint64 `json:"next_recovery_epoch"`
	NextRecoverySalt      string `json:"next_recovery_salt"`
	NextRecoveryPublicKey string `json:"next_recovery_public_key"`
}

type RecoveryKeyRotationResponse struct {
	SchemaVersion    int    `json:"schema_version"`
	OperationID      string `json:"operation_id"`
	RecoveryEpoch    uint64 `json:"recovery_epoch"`
	IdentityRevision uint64 `json:"identity_revision"`
}

func (store *AuthorityStore) RecoveryKeyReceipt(
	operationID string,
	requestDigest [32]byte,
	now time.Time,
) (RecoveryKeyRotationResponse, bool, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, receipt := range store.state.Receipts {
		if receipt.OperationID != operationID {
			continue
		}
		committed, err := parseCanonicalUTC(receipt.CommittedAt)
		if err != nil || committed.Before(now.Add(-24*time.Hour)) {
			return RecoveryKeyRotationResponse{}, false, nil
		}
		if receipt.Result != "recovery_key_rotated" || receipt.RequestSHA256 != hex.EncodeToString(requestDigest[:]) ||
			store.state.Active == nil || receipt.CertificateSHA256 != store.state.Active.CertificateSHA256 {
			return RecoveryKeyRotationResponse{}, false, errors.New("recovery key operation conflicts with its receipt")
		}
		return recoveryKeyResponse(store.state, operationID), true, nil
	}
	return RecoveryKeyRotationResponse{}, false, nil
}

func (store *AuthorityStore) RotateRecoveryKey(
	mutation RecoveryKeyMutation,
	requestDigest [32]byte,
	currentSignatureText string,
	nextSignatureText string,
	now time.Time,
) (RecoveryKeyRotationResponse, error) {
	if mutation.SchemaVersion != 1 || !canonicalRawURLBytes(mutation.OperationID, 16) ||
		!canonicalRawURLBytes(mutation.NextRecoverySalt, 32) ||
		!canonicalRawURLBytes(mutation.NextRecoveryPublicKey, ed25519.PublicKeySize) ||
		mutation.NextRecoveryEpoch == 0 {
		return RecoveryKeyRotationResponse{}, errors.New("recovery key mutation is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	candidate := cloneAuthorityState(store.state)
	cutoff := now.Add(-24 * time.Hour)
	receipts := candidate.Receipts[:0]
	for _, receipt := range candidate.Receipts {
		committed, err := parseCanonicalUTC(receipt.CommittedAt)
		if err == nil && !committed.Before(cutoff) {
			receipts = append(receipts, receipt)
		}
	}
	candidate.Receipts = receipts
	for _, receipt := range candidate.Receipts {
		if receipt.OperationID != mutation.OperationID {
			continue
		}
		if receipt.Result != "recovery_key_rotated" || receipt.RequestSHA256 != hex.EncodeToString(requestDigest[:]) ||
			candidate.Active == nil || receipt.CertificateSHA256 != candidate.Active.CertificateSHA256 ||
			candidate.Active.RecoveryEpoch != mutation.NextRecoveryEpoch {
			return RecoveryKeyRotationResponse{}, errors.New("recovery key operation conflicts with its receipt")
		}
		return recoveryKeyResponse(candidate, mutation.OperationID), nil
	}
	if candidate.Active == nil || candidate.Active.RecoveryEpoch == math.MaxUint64 ||
		candidate.Active.RecoveryEpoch+1 != mutation.NextRecoveryEpoch {
		return RecoveryKeyRotationResponse{}, errors.New("recovery key epoch is stale or saturated")
	}
	currentPublic, err := decodeFixed(candidate.Active.RecoveryPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return RecoveryKeyRotationResponse{}, err
	}
	nextPublic, err := decodeFixed(mutation.NextRecoveryPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return RecoveryKeyRotationResponse{}, err
	}
	currentSignature, currentErr := decodeFixed(currentSignatureText, ed25519.SignatureSize)
	nextSignature, nextErr := decodeFixed(nextSignatureText, ed25519.SignatureSize)
	transcript := recoveryKeyTranscript(candidate, mutation)
	if currentErr != nil || nextErr != nil ||
		subtle.ConstantTimeCompare(currentPublic, nextPublic) == 1 ||
		!ed25519.Verify(ed25519.PublicKey(currentPublic), transcript, currentSignature) ||
		!ed25519.Verify(ed25519.PublicKey(nextPublic), transcript, nextSignature) {
		return RecoveryKeyRotationResponse{}, errors.New("recovery key possession proof is invalid")
	}
	active := *candidate.Active
	active.RecoverySalt = mutation.NextRecoverySalt
	active.RecoveryEpoch = mutation.NextRecoveryEpoch
	active.RecoveryPublicKey = mutation.NextRecoveryPublicKey
	candidate.Active = &active
	if len(candidate.Receipts) == 32 {
		candidate.Receipts = candidate.Receipts[1:]
	}
	candidate.Receipts = append(candidate.Receipts, IdempotenceReceipt{
		OperationID: mutation.OperationID, RequestSHA256: hex.EncodeToString(requestDigest[:]),
		Result: "recovery_key_rotated", IdentityRevision: candidate.IdentityRevision,
		CertificateSHA256: active.CertificateSHA256, CommittedAt: now.UTC().Format(time.RFC3339Nano),
	})
	if err := validateAuthorityState(candidate, now.UTC()); err != nil {
		return RecoveryKeyRotationResponse{}, err
	}
	if err := store.writeState(candidate); err != nil {
		return RecoveryKeyRotationResponse{}, err
	}
	store.state = candidate
	return recoveryKeyResponse(candidate, mutation.OperationID), nil
}

func recoveryKeyTranscript(state AuthorityState, mutation RecoveryKeyMutation) []byte {
	buffer := bytes.NewBuffer(nil)
	buffer.WriteString(protocol.RecoveryKeyDomain)
	appendTranscriptField(buffer, []byte(mutation.OperationID))
	appendTranscriptField(buffer, []byte(state.ControllerID))
	appendTranscriptField(buffer, []byte(state.InfrastructureID))
	appendTranscriptField(buffer, []byte(state.Active.DeviceID))
	appendTranscriptField(buffer, []byte(state.Active.CertificateSHA256))
	appendTranscriptField(buffer, []byte(state.Active.RecoverySalt))
	_ = binary.Write(buffer, binary.BigEndian, state.Active.RecoveryEpoch)
	appendTranscriptField(buffer, []byte(state.Active.RecoveryPublicKey))
	appendTranscriptField(buffer, []byte(mutation.NextRecoverySalt))
	_ = binary.Write(buffer, binary.BigEndian, mutation.NextRecoveryEpoch)
	appendTranscriptField(buffer, []byte(mutation.NextRecoveryPublicKey))
	return buffer.Bytes()
}

func recoveryKeyResponse(state AuthorityState, operationID string) RecoveryKeyRotationResponse {
	return RecoveryKeyRotationResponse{
		SchemaVersion: 1, OperationID: operationID, RecoveryEpoch: state.Active.RecoveryEpoch,
		IdentityRevision: state.IdentityRevision,
	}
}
