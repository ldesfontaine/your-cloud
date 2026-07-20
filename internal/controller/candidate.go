package controller

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	candidateFileName = "identity-candidate.json"
	maxCandidateBytes = int64(16 * 1024)
)

type durableCandidate struct {
	SchemaVersion       int          `json:"schema_version"`
	TransactionID       string       `json:"transaction_id"`
	Mode                string       `json:"mode"`
	PreviousFingerprint string       `json:"previous_fingerprint"`
	RequestSHA256       string       `json:"request_sha256"`
	Record              DeviceRecord `json:"record"`
	CertificatePEM      string       `json:"certificate_pem"`
	ExpiresAt           string       `json:"expires_at"`
}

func (store *AuthorityStore) loadCandidate() (*pendingCandidate, error) {
	path := filepath.Join(store.directory, candidateFileName)
	encoded, err := readPrivateStateFile(path, maxCandidateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var durable durableCandidate
	if err := strictjson.Decode(encoded, &durable); err != nil {
		return nil, err
	}
	candidate, committed, err := decodeDurableCandidate(durable, store.Snapshot())
	if err != nil {
		return nil, err
	}
	if committed {
		if err := store.removeCandidate(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return candidate, nil
}

func (store *AuthorityStore) persistCandidate(candidate pendingCandidate) error {
	durable := durableCandidate{
		SchemaVersion:       1,
		TransactionID:       candidate.transactionID,
		Mode:                candidate.mode,
		PreviousFingerprint: candidate.previousFingerprint,
		RequestSHA256:       hex.EncodeToString(candidate.requestDigest[:]),
		Record:              candidate.certificate.Record,
		CertificatePEM:      candidate.certificate.CertificatePEM,
		ExpiresAt:           candidate.expires.UTC().Format(time.RFC3339Nano),
	}
	if _, committed, err := decodeDurableCandidate(durable, store.Snapshot()); err != nil || committed {
		if err == nil {
			err = errors.New("Controller identity candidate is already committed")
		}
		return err
	}
	path := filepath.Join(store.directory, candidateFileName)
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("Controller identity candidate already exists or cannot be inspected")
	}
	encoded, err := json.Marshal(durable)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > maxCandidateBytes {
		return errors.New("Controller identity candidate cannot be encoded within its bound")
	}
	return persistPrivateDocument(store.directory, path, ".identity-candidate-", encoded)
}

func (store *AuthorityStore) removeCandidate() error {
	path := filepath.Join(store.directory, candidateFileName)
	if _, err := readPrivateStateFile(path, maxCandidateBytes); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(store.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func decodeDurableCandidate(durable durableCandidate, authority AuthorityState) (*pendingCandidate, bool, error) {
	if durable.SchemaVersion != 1 || !canonicalRawURLBytes(durable.TransactionID, 16) ||
		durable.Mode != "enrollment" && durable.Mode != "recovery" && durable.Mode != "rotation" ||
		!lowerHex(durable.RequestSHA256, 64, 64) {
		return nil, false, errors.New("Controller identity candidate envelope is invalid")
	}
	committed := candidateReceiptExists(durable, authority)
	if durable.Mode == "enrollment" {
		if durable.PreviousFingerprint != "" || authority.Active != nil &&
			(!committed || authority.Active.CertificateSHA256 != durable.Record.CertificateSHA256) {
			return nil, false, errors.New("Controller enrollment candidate conflicts with active identity")
		}
	} else if !lowerHex(durable.PreviousFingerprint, 64, 64) || authority.Active == nil ||
		authority.Active.CertificateSHA256 != durable.PreviousFingerprint &&
			(!committed || authority.Active.CertificateSHA256 != durable.Record.CertificateSHA256) {
		return nil, false, errors.New("Controller recovery candidate conflicts with active identity")
	}
	if err := validateDeviceRecord(durable.Record, "active"); err != nil {
		return nil, false, err
	}
	expires, err := parseCanonicalUTC(durable.ExpiresAt)
	if err != nil {
		return nil, false, errors.New("Controller identity candidate expiry is invalid")
	}
	block, rest := pem.Decode(bytes.TrimSpace([]byte(durable.CertificatePEM)))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, false, errors.New("Controller identity candidate certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, errors.New("Controller identity candidate certificate is invalid")
	}
	deviceCA, err := parseOneCertificate([]byte(authority.DeviceCACertificate))
	if err != nil || certificate.CheckSignatureFrom(deviceCA) != nil ||
		validatePresentedDevice(certificate, authority.InfrastructureID, &durable.Record, certificate.NotBefore) != nil {
		return nil, false, errors.New("Controller identity candidate certificate is invalid")
	}
	requestDigest, err := hex.DecodeString(durable.RequestSHA256)
	if err != nil || len(requestDigest) != sha256.Size {
		return nil, false, errors.New("Controller identity candidate request digest is invalid")
	}
	var digest [sha256.Size]byte
	copy(digest[:], requestDigest)
	return &pendingCandidate{
		transactionID:       durable.TransactionID,
		mode:                durable.Mode,
		previousFingerprint: durable.PreviousFingerprint,
		requestDigest:       digest,
		certificate: CandidateCertificate{
			Record: durable.Record, CertificatePEM: durable.CertificatePEM,
			CertificateDER: append([]byte(nil), block.Bytes...),
			ExpiresAt:      certificate.NotAfter.UTC().Format(time.RFC3339Nano),
		},
		expires: expires,
	}, committed, nil
}

func candidateReceiptExists(candidate durableCandidate, authority AuthorityState) bool {
	for _, receipt := range authority.Receipts {
		if receipt.OperationID == candidate.TransactionID && receipt.Result == candidate.Mode+"_activated" &&
			receipt.CertificateSHA256 == candidate.Record.CertificateSHA256 {
			return true
		}
	}
	return false
}

func persistPrivateDocument(directory, path, prefix string, encoded []byte) error {
	temporary, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}
