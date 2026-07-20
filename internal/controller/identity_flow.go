package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
)

const (
	windowLifetime    = 10 * time.Minute
	challengeLifetime = 2 * time.Minute
	maxCSRBytes       = 2 * 1024
)

var windowBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type WindowSheet struct {
	SchemaVersion    int    `json:"schema_version"`
	Mode             string `json:"mode"`
	Origin           string `json:"origin"`
	TemporaryOrigin  string `json:"temporary_origin"`
	ControllerID     string `json:"controller_id"`
	InfrastructureID string `json:"infrastructure_id"`
	ServerCAPEM      string `json:"server_ca_pem"`
	ServerSPKISHA256 string `json:"server_spki_sha256"`
	WindowID         string `json:"window_id"`
	WindowCode       string `json:"window_code"`
	ExpiresAt        string `json:"expires_at"`
}

type IdentityChallengeRequest struct {
	SchemaVersion int    `json:"schema_version"`
	WindowID      string `json:"window_id"`
	WindowCode    string `json:"window_code"`
	RequestID     string `json:"request_id"`
}

type IdentityChallengeResponse struct {
	SchemaVersion            int    `json:"schema_version"`
	TransactionID            string `json:"transaction_id"`
	DeviceID                 string `json:"device_id"`
	Challenge                string `json:"challenge"`
	CreatedAt                string `json:"created_at"`
	ExpiresAt                string `json:"expires_at"`
	NextRecoverySalt         string `json:"next_recovery_salt"`
	NextRecoveryEpoch        uint64 `json:"next_recovery_epoch"`
	CurrentRecoverySalt      string `json:"current_recovery_salt,omitempty"`
	CurrentRecoveryEpoch     uint64 `json:"current_recovery_epoch,omitempty"`
	CurrentRecoveryPublicKey string `json:"current_recovery_public_key,omitempty"`
}

type IdentityCompletionRequest struct {
	SchemaVersion            int    `json:"schema_version"`
	TransactionID            string `json:"transaction_id"`
	DeviceCSR                string `json:"device_csr"`
	HumanPublicKey           string `json:"human_public_key"`
	NextRecoveryPublicKey    string `json:"next_recovery_public_key"`
	HumanSignature           string `json:"human_signature"`
	NextRecoverySignature    string `json:"next_recovery_signature"`
	CurrentRecoverySignature string `json:"current_recovery_signature,omitempty"`
}

type IdentityCompletionResponse struct {
	SchemaVersion  int    `json:"schema_version"`
	TransactionID  string `json:"transaction_id"`
	DeviceID       string `json:"device_id"`
	CertificatePEM string `json:"certificate_pem"`
	ExpiresAt      string `json:"expires_at"`
}

type IdentityActivationResponse struct {
	SchemaVersion        int    `json:"schema_version"`
	ControllerID         string `json:"controller_id"`
	InfrastructureID     string `json:"infrastructure_id"`
	DeviceID             string `json:"device_id"`
	DeviceStatus         string `json:"device_status"`
	CertificateExpiresAt string `json:"certificate_expires_at"`
	IdentityRevision     uint64 `json:"identity_revision"`
}

type identityWindow struct {
	mode         string
	id           string
	codeDigest   [32]byte
	created      time.Time
	expires      time.Time
	failedProofs uint8
	transaction  *identityTransaction
}

type identityTransaction struct {
	mode                     string
	requestID                string
	requestDigest            [32]byte
	transactionID            string
	deviceID                 string
	challenge                [32]byte
	created                  time.Time
	expires                  time.Time
	nextRecoverySalt         [32]byte
	nextRecoveryEpoch        uint64
	currentRecoverySalt      []byte
	currentRecoveryEpoch     uint64
	currentRecoveryPublicKey []byte
}

type pendingCandidate struct {
	transactionID       string
	mode                string
	previousFingerprint string
	requestDigest       [32]byte
	certificate         CandidateCertificate
	expires             time.Time
}

type PairingManager struct {
	mu        sync.Mutex
	authority *AuthorityStore
	now       func() time.Time
	window    *identityWindow
	candidate *pendingCandidate
}

func NewPairingManager(authority *AuthorityStore) (*PairingManager, error) {
	if authority == nil {
		return nil, errors.New("Controller authority is required")
	}
	candidate, err := authority.loadCandidate()
	if err != nil {
		return nil, fmt.Errorf("load Controller identity candidate: %w", err)
	}
	return &PairingManager{authority: authority, now: time.Now, candidate: candidate}, nil
}

func (manager *PairingManager) OpenWindow(mode string) (WindowSheet, error) {
	if mode != "enrollment" && mode != "recovery" {
		return WindowSheet{}, errors.New("window mode is unsupported")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state := manager.authority.Snapshot()
	if err := manager.pruneCandidateLocked(manager.now()); err != nil {
		return WindowSheet{}, err
	}
	if manager.window != nil || manager.candidate != nil || mode == "enrollment" && state.Active != nil || mode == "recovery" && state.Active == nil {
		return WindowSheet{}, errors.New("Controller identity state conflicts with requested window")
	}
	now := manager.now()
	windowID, err := randomRawURL(16)
	if err != nil {
		return WindowSheet{}, err
	}
	codeBytes := make([]byte, 16)
	if _, err := rand.Read(codeBytes); err != nil {
		return WindowSheet{}, err
	}
	code := windowBase32.EncodeToString(codeBytes)
	manager.window = &identityWindow{
		mode: mode, id: windowID, codeDigest: sha256.Sum256(codeBytes), created: now, expires: now.Add(windowLifetime),
	}
	for index := range codeBytes {
		codeBytes[index] = 0
	}
	pin, err := manager.authority.ServerCASPKISHA256()
	if err != nil {
		manager.window = nil
		return WindowSheet{}, err
	}
	host := controllerServerName(state.InfrastructureID)
	return WindowSheet{
		SchemaVersion: 1, Mode: mode,
		Origin: "https://" + host + ":9443", TemporaryOrigin: "https://" + host + ":9444",
		ControllerID: state.ControllerID, InfrastructureID: state.InfrastructureID,
		ServerCAPEM: state.ServerCACertificate, ServerSPKISHA256: pin,
		WindowID: windowID, WindowCode: groupWindowCode(code), ExpiresAt: manager.window.expires.UTC().Format(time.RFC3339Nano),
	}, nil
}

func (manager *PairingManager) Begin(mode string, request IdentityChallengeRequest) (IdentityChallengeResponse, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.now()
	window, err := manager.validWindow(mode, request.WindowID, request.WindowCode, now)
	if err != nil {
		return IdentityChallengeResponse{}, err
	}
	if request.SchemaVersion != 1 || !canonicalRawURLBytes(request.RequestID, 16) {
		return IdentityChallengeResponse{}, errors.New("identity challenge request is invalid")
	}
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	if window.transaction != nil {
		if window.transaction.requestID != request.RequestID || subtle.ConstantTimeCompare(window.transaction.requestDigest[:], digest[:]) != 1 {
			return IdentityChallengeResponse{}, errors.New("identity transaction conflicts with active request")
		}
		return challengeResponse(window.transaction), nil
	}
	transactionID, err := randomRawURL(16)
	if err != nil {
		return IdentityChallengeResponse{}, err
	}
	deviceID, err := manager.newDeviceID()
	if err != nil {
		return IdentityChallengeResponse{}, err
	}
	transaction := &identityTransaction{
		mode: mode, requestID: request.RequestID, requestDigest: digest,
		transactionID: transactionID, deviceID: deviceID, created: now, expires: now.Add(challengeLifetime),
	}
	if _, err := rand.Read(transaction.challenge[:]); err != nil {
		return IdentityChallengeResponse{}, err
	}
	if _, err := rand.Read(transaction.nextRecoverySalt[:]); err != nil {
		return IdentityChallengeResponse{}, err
	}
	state := manager.authority.Snapshot()
	if mode == "enrollment" {
		transaction.nextRecoveryEpoch = 1
	} else {
		if state.Active.RecoveryEpoch == math.MaxUint64 {
			return IdentityChallengeResponse{}, errors.New("recovery epoch is saturated")
		}
		transaction.nextRecoveryEpoch = state.Active.RecoveryEpoch + 1
		transaction.currentRecoveryEpoch = state.Active.RecoveryEpoch
		transaction.currentRecoverySalt, _ = base64.RawURLEncoding.DecodeString(state.Active.RecoverySalt)
		transaction.currentRecoveryPublicKey, _ = base64.RawURLEncoding.DecodeString(state.Active.RecoveryPublicKey)
	}
	window.transaction = transaction
	return challengeResponse(transaction), nil
}

func (manager *PairingManager) Complete(mode string, request IdentityCompletionRequest) (IdentityCompletionResponse, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.now()
	if manager.window == nil || manager.window.mode != mode || now.After(manager.window.expires) || manager.window.transaction == nil {
		manager.window = nil
		return IdentityCompletionResponse{}, errors.New("identity window is unavailable")
	}
	transaction := manager.window.transaction
	if now.After(transaction.expires) || request.SchemaVersion != 1 || request.TransactionID != transaction.transactionID {
		return IdentityCompletionResponse{}, manager.proofFailed(errors.New("identity transaction is invalid or expired"))
	}
	csr, csrDER, err := parseDeviceCSR(request.DeviceCSR, manager.authority.Snapshot().InfrastructureID, transaction.deviceID)
	if err != nil {
		return IdentityCompletionResponse{}, manager.proofFailed(err)
	}
	humanPublic, err := decodeFixed(request.HumanPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return IdentityCompletionResponse{}, manager.proofFailed(err)
	}
	nextRecoveryPublic, err := decodeFixed(request.NextRecoveryPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return IdentityCompletionResponse{}, manager.proofFailed(err)
	}
	transcript := manager.identityTranscript(transaction, csrDER, humanPublic, nextRecoveryPublic)
	humanSignature, err := decodeFixed(request.HumanSignature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(humanPublic), transcript, humanSignature) {
		return IdentityCompletionResponse{}, manager.proofFailed(errors.New("human proof is invalid"))
	}
	nextSignature, err := decodeFixed(request.NextRecoverySignature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(nextRecoveryPublic), transcript, nextSignature) {
		return IdentityCompletionResponse{}, manager.proofFailed(errors.New("next recovery proof is invalid"))
	}
	if mode == "recovery" {
		currentSignature, decodeErr := decodeFixed(request.CurrentRecoverySignature, ed25519.SignatureSize)
		if decodeErr != nil || !ed25519.Verify(ed25519.PublicKey(transaction.currentRecoveryPublicKey), transcript, currentSignature) {
			return IdentityCompletionResponse{}, manager.proofFailed(errors.New("current recovery proof is invalid"))
		}
	} else if request.CurrentRecoverySignature != "" {
		return IdentityCompletionResponse{}, manager.proofFailed(errors.New("unexpected current recovery proof"))
	}
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return IdentityCompletionResponse{}, manager.proofFailed(errors.New("CSR key is not P-256"))
	}
	issued, err := manager.authority.IssueDeviceCertificate(transaction.deviceID, public, now)
	if err != nil {
		return IdentityCompletionResponse{}, err
	}
	issued.Record.HumanPublicKey = base64.RawURLEncoding.EncodeToString(humanPublic)
	issued.Record.RecoverySalt = base64.RawURLEncoding.EncodeToString(transaction.nextRecoverySalt[:])
	issued.Record.RecoveryEpoch = transaction.nextRecoveryEpoch
	issued.Record.RecoveryPublicKey = base64.RawURLEncoding.EncodeToString(nextRecoveryPublic)
	previous := ""
	if active := manager.authority.Snapshot().Active; active != nil {
		previous = active.CertificateSHA256
	}
	candidate := pendingCandidate{
		transactionID: transaction.transactionID, mode: mode, previousFingerprint: previous,
		requestDigest: sha256.Sum256(mustJSON(request)),
		certificate:   issued, expires: manager.window.expires,
	}
	if err := manager.authority.persistCandidate(candidate); err != nil {
		return IdentityCompletionResponse{}, err
	}
	manager.candidate = &candidate
	manager.window = nil
	return IdentityCompletionResponse{
		SchemaVersion: 1, TransactionID: transaction.transactionID, DeviceID: transaction.deviceID,
		CertificatePEM: issued.CertificatePEM, ExpiresAt: issued.ExpiresAt,
	}, nil
}

func (manager *PairingManager) Activate(transactionID string, certificate *x509.Certificate, requestDigest [32]byte) (IdentityActivationResponse, error) {
	return manager.activate("", transactionID, certificate, requestDigest)
}

func (manager *PairingManager) ActivateForMode(mode, transactionID string, certificate *x509.Certificate, requestDigest [32]byte) (IdentityActivationResponse, error) {
	if mode != "enrollment" && mode != "recovery" && mode != "rotation" {
		return IdentityActivationResponse{}, errors.New("identity activation mode is unsupported")
	}
	return manager.activate(mode, transactionID, certificate, requestDigest)
}

func (manager *PairingManager) activate(mode, transactionID string, certificate *x509.Certificate, requestDigest [32]byte) (IdentityActivationResponse, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.now()
	if err := manager.pruneCandidateLocked(now); err != nil {
		return IdentityActivationResponse{}, err
	}
	state := manager.authority.Snapshot()
	if manager.candidate == nil {
		for _, receipt := range state.Receipts {
			committed, timeErr := parseCanonicalUTC(receipt.CommittedAt)
			modeMatches := mode == "" || receipt.Result == mode+"_activated"
			if timeErr == nil && !committed.Before(now.Add(-24*time.Hour)) && modeMatches &&
				receipt.OperationID == transactionID && receipt.RequestSHA256 == hex.EncodeToString(requestDigest[:]) &&
				state.Active != nil && validatePresentedDevice(certificate, state.InfrastructureID, state.Active, now) == nil {
				return activationResponse(state, certificate.NotAfter), nil
			}
		}
		return IdentityActivationResponse{}, errors.New("identity candidate is unavailable")
	}
	candidate := manager.candidate
	if mode != "" && candidate.mode != mode || candidate.transactionID != transactionID || now.After(candidate.expires) ||
		validatePresentedDevice(certificate, state.InfrastructureID, &candidate.certificate.Record, now) != nil {
		return IdentityActivationResponse{}, errors.New("identity candidate is invalid or expired")
	}
	if err := manager.authority.activateCandidate(*candidate, requestDigest, now); err != nil {
		return IdentityActivationResponse{}, err
	}
	manager.candidate = nil
	if err := manager.authority.removeCandidate(); err != nil {
		return IdentityActivationResponse{}, err
	}
	return activationResponse(manager.authority.Snapshot(), certificate.NotAfter), nil
}

func (manager *PairingManager) CandidateAuthorized(certificate *x509.Certificate, transactionID string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.pruneCandidateLocked(manager.now()); err != nil {
		return err
	}
	if manager.candidate == nil || manager.candidate.transactionID != transactionID || manager.now().After(manager.candidate.expires) {
		return errors.New("candidate is unavailable")
	}
	state := manager.authority.Snapshot()
	return validatePresentedDevice(certificate, state.InfrastructureID, &manager.candidate.certificate.Record, manager.now())
}

func (manager *PairingManager) PrepareDeviceRotation(rotationID, encodedCSR string, requestDigest [32]byte) (IdentityCompletionResponse, error) {
	if !canonicalRawURLBytes(rotationID, 16) {
		return IdentityCompletionResponse{}, errors.New("device rotation identifier is invalid")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.now()
	if err := manager.pruneCandidateLocked(now); err != nil {
		return IdentityCompletionResponse{}, err
	}
	if manager.candidate != nil {
		candidate := manager.candidate
		if candidate.mode != "rotation" || candidate.transactionID != rotationID ||
			subtle.ConstantTimeCompare(candidate.requestDigest[:], requestDigest[:]) != 1 {
			return IdentityCompletionResponse{}, errors.New("another identity candidate is already active")
		}
		return completionResponse(*candidate), nil
	}
	state := manager.authority.Snapshot()
	if state.Active == nil {
		return IdentityCompletionResponse{}, errors.New("active device is unavailable")
	}
	csr, _, err := parseDeviceCSR(encodedCSR, state.InfrastructureID, state.Active.DeviceID)
	if err != nil {
		return IdentityCompletionResponse{}, err
	}
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return IdentityCompletionResponse{}, errors.New("CSR key is not P-256")
	}
	issued, err := manager.authority.IssueDeviceCertificate(state.Active.DeviceID, public, now)
	if err != nil {
		return IdentityCompletionResponse{}, err
	}
	issued.Record.HumanPublicKey = state.Active.HumanPublicKey
	issued.Record.RecoverySalt = state.Active.RecoverySalt
	issued.Record.RecoveryEpoch = state.Active.RecoveryEpoch
	issued.Record.RecoveryPublicKey = state.Active.RecoveryPublicKey
	candidate := pendingCandidate{
		transactionID: rotationID, mode: "rotation", previousFingerprint: state.Active.CertificateSHA256,
		requestDigest: requestDigest, certificate: issued, expires: now.Add(windowLifetime),
	}
	if err := manager.authority.persistCandidate(candidate); err != nil {
		return IdentityCompletionResponse{}, err
	}
	manager.candidate = &candidate
	return completionResponse(candidate), nil
}

func (manager *PairingManager) DeviceRotationCandidate(rotationID string, requestDigest [32]byte) (IdentityCompletionResponse, bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.pruneCandidateLocked(manager.now()); err != nil {
		return IdentityCompletionResponse{}, false, err
	}
	if manager.candidate == nil {
		return IdentityCompletionResponse{}, false, nil
	}
	candidate := manager.candidate
	if candidate.mode != "rotation" || candidate.transactionID != rotationID ||
		subtle.ConstantTimeCompare(candidate.requestDigest[:], requestDigest[:]) != 1 {
		return IdentityCompletionResponse{}, false, errors.New("device rotation conflicts with active identity candidate")
	}
	return completionResponse(*candidate), true, nil
}

func completionResponse(candidate pendingCandidate) IdentityCompletionResponse {
	return IdentityCompletionResponse{
		SchemaVersion: 1, TransactionID: candidate.transactionID,
		DeviceID:       candidate.certificate.Record.DeviceID,
		CertificatePEM: candidate.certificate.CertificatePEM,
		ExpiresAt:      candidate.certificate.ExpiresAt,
	}
}

func (manager *PairingManager) pruneCandidateLocked(now time.Time) error {
	if manager.candidate == nil || !now.After(manager.candidate.expires) {
		return nil
	}
	if err := manager.authority.removeCandidate(); err != nil {
		return err
	}
	manager.candidate = nil
	return nil
}

func (manager *PairingManager) WindowCredentialsValid(mode, windowID, windowCode string) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	_, err := manager.validWindow(mode, windowID, windowCode, manager.now())
	return err == nil
}

func (manager *PairingManager) WindowOpen(mode string) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.window == nil || manager.window.mode != mode || manager.now().After(manager.window.expires) {
		manager.window = nil
		return false
	}
	return true
}

func (manager *PairingManager) validWindow(mode, windowID, windowCode string, now time.Time) (*identityWindow, error) {
	if manager.window == nil || manager.window.mode != mode || now.After(manager.window.expires) {
		manager.window = nil
		return nil, errors.New("identity window is unavailable")
	}
	code, err := parseWindowCode(windowCode)
	if err != nil || manager.window.id != windowID || !canonicalRawURLBytes(windowID, 16) {
		return nil, errors.New("identity window authentication failed")
	}
	digest := sha256.Sum256(code)
	for index := range code {
		code[index] = 0
	}
	if subtle.ConstantTimeCompare(digest[:], manager.window.codeDigest[:]) != 1 {
		return nil, errors.New("identity window authentication failed")
	}
	return manager.window, nil
}

func (manager *PairingManager) proofFailed(cause error) error {
	if manager.window != nil {
		manager.window.failedProofs++
		if manager.window.failedProofs >= 5 {
			manager.window = nil
		}
	}
	return cause
}

func (manager *PairingManager) newDeviceID() (string, error) {
	state := manager.authority.Snapshot()
	for attempts := 0; attempts < 16; attempts++ {
		candidate, err := identifier.NewUUIDv4()
		if err != nil {
			return "", err
		}
		used := state.Active != nil && state.Active.DeviceID == candidate
		for _, revoked := range state.Revoked {
			used = used || revoked.DeviceID == candidate
		}
		if !used {
			return candidate, nil
		}
	}
	return "", errors.New("cannot allocate a unique device identifier")
}

func challengeResponse(transaction *identityTransaction) IdentityChallengeResponse {
	response := IdentityChallengeResponse{
		SchemaVersion: 1, TransactionID: transaction.transactionID, DeviceID: transaction.deviceID,
		Challenge: base64.RawURLEncoding.EncodeToString(transaction.challenge[:]),
		CreatedAt: transaction.created.UTC().Format(time.RFC3339Nano), ExpiresAt: transaction.expires.UTC().Format(time.RFC3339Nano),
		NextRecoverySalt: base64.RawURLEncoding.EncodeToString(transaction.nextRecoverySalt[:]), NextRecoveryEpoch: transaction.nextRecoveryEpoch,
	}
	if transaction.mode == "recovery" {
		response.CurrentRecoverySalt = base64.RawURLEncoding.EncodeToString(transaction.currentRecoverySalt)
		response.CurrentRecoveryEpoch = transaction.currentRecoveryEpoch
		response.CurrentRecoveryPublicKey = base64.RawURLEncoding.EncodeToString(transaction.currentRecoveryPublicKey)
	}
	return response
}

func (manager *PairingManager) identityTranscript(transaction *identityTransaction, csrDER, humanPublic, nextRecoveryPublic []byte) []byte {
	state := manager.authority.Snapshot()
	methodRoute := "PUT /v0/enrollment"
	if transaction.mode == "recovery" {
		methodRoute = "PUT /v0/recovery"
	}
	buffer := bytes.NewBuffer(nil)
	buffer.WriteString("your-cloud/v0.0.3/identity-transcript\x00")
	appendTranscriptField(buffer, []byte(transaction.mode))
	appendTranscriptField(buffer, []byte("https://"+controllerServerName(state.InfrastructureID)+":9444"))
	appendTranscriptField(buffer, []byte(methodRoute))
	appendTranscriptField(buffer, []byte(manager.window.id))
	appendTranscriptField(buffer, []byte(transaction.requestID))
	appendTranscriptField(buffer, []byte(transaction.transactionID))
	appendTranscriptField(buffer, []byte(state.ControllerID))
	appendTranscriptField(buffer, []byte(state.InfrastructureID))
	appendTranscriptField(buffer, []byte(transaction.deviceID))
	appendTranscriptField(buffer, transaction.challenge[:])
	appendTranscriptField(buffer, []byte(transaction.created.UTC().Format(time.RFC3339Nano)))
	appendTranscriptField(buffer, []byte(transaction.expires.UTC().Format(time.RFC3339Nano)))
	appendTranscriptField(buffer, transaction.currentRecoverySalt)
	_ = binary.Write(buffer, binary.BigEndian, transaction.currentRecoveryEpoch)
	appendTranscriptField(buffer, transaction.nextRecoverySalt[:])
	_ = binary.Write(buffer, binary.BigEndian, transaction.nextRecoveryEpoch)
	csrDigest := sha256.Sum256(csrDER)
	appendTranscriptField(buffer, csrDigest[:])
	appendTranscriptField(buffer, humanPublic)
	appendTranscriptField(buffer, transaction.currentRecoveryPublicKey)
	appendTranscriptField(buffer, nextRecoveryPublic)
	return buffer.Bytes()
}

func appendTranscriptField(buffer *bytes.Buffer, value []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	_, _ = buffer.Write(value)
}

func parseDeviceCSR(encoded, infrastructureID, deviceID string) (*x509.CertificateRequest, []byte, error) {
	if len(encoded) == 0 || len(encoded) > 4*maxCSRBytes {
		return nil, nil, errors.New("CSR encoding is outside its bound")
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(der) == 0 || len(der) > maxCSRBytes || base64.RawURLEncoding.EncodeToString(der) != encoded {
		return nil, nil, errors.New("CSR encoding is not canonical")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, nil, errors.New("CSR signature is invalid")
	}
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 1 || csr.URIs[0].String() != deviceURI(infrastructureID, deviceID) {
		return nil, nil, errors.New("CSR identity or key type is invalid")
	}
	if len(csr.Subject.Names) != 0 || len(csr.Subject.ExtraNames) != 0 {
		return nil, nil, errors.New("CSR subject must be empty")
	}
	return csr, der, nil
}

func (store *AuthorityStore) activateCandidate(candidate pendingCandidate, requestDigest [32]byte, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state := cloneAuthorityState(store.state)
	if candidate.mode == "enrollment" {
		if state.Active != nil {
			return errors.New("an active device already exists")
		}
	} else if candidate.mode == "recovery" || candidate.mode == "rotation" {
		if state.Active == nil || state.Active.CertificateSHA256 != candidate.previousFingerprint || len(state.Revoked) >= 64 {
			return errors.New("replacement no longer matches active identity")
		}
		revoked := *state.Active
		revoked.Status = "revoked"
		state.Revoked = append(state.Revoked, revoked)
		sortRevoked(state.Revoked)
	} else {
		return errors.New("identity candidate mode is invalid")
	}
	if state.IdentityRevision == math.MaxUint64 {
		return errors.New("identity revision is saturated")
	}
	state.IdentityRevision++
	active := candidate.certificate.Record
	active.Status = "active"
	state.Active = &active
	cutoff := now.Add(-24 * time.Hour)
	receipts := state.Receipts[:0]
	for _, receipt := range state.Receipts {
		committed, err := parseCanonicalUTC(receipt.CommittedAt)
		if err == nil && !committed.Before(cutoff) {
			receipts = append(receipts, receipt)
		}
	}
	state.Receipts = receipts
	if len(state.Receipts) == 32 {
		state.Receipts = state.Receipts[1:]
	}
	state.Receipts = append(state.Receipts, IdempotenceReceipt{
		OperationID: candidate.transactionID, RequestSHA256: hex.EncodeToString(requestDigest[:]), Result: candidate.mode + "_activated",
		IdentityRevision: state.IdentityRevision, CertificateSHA256: active.CertificateSHA256,
		CommittedAt: now.UTC().Format(time.RFC3339Nano),
	})
	if err := validateAuthorityState(state, now.UTC()); err != nil {
		return err
	}
	if err := store.writeState(state); err != nil {
		return err
	}
	store.state = state
	return nil
}

func activationResponse(state AuthorityState, expires time.Time) IdentityActivationResponse {
	return IdentityActivationResponse{
		SchemaVersion: 1, ControllerID: state.ControllerID, InfrastructureID: state.InfrastructureID,
		DeviceID: state.Active.DeviceID, DeviceStatus: "active", CertificateExpiresAt: expires.UTC().Format(time.RFC3339Nano),
		IdentityRevision: state.IdentityRevision,
	}
}

func parseWindowCode(raw string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 64 || !isASCII(raw) {
		return nil, errors.New("window code is invalid")
	}
	upper := strings.ToUpper(raw)
	canonical := upper
	if len(upper) == 30 {
		parts := strings.Split(upper, "-")
		if len(parts) != 5 || len(parts[0]) != 5 || len(parts[1]) != 5 || len(parts[2]) != 5 || len(parts[3]) != 5 || len(parts[4]) != 6 {
			return nil, errors.New("window code grouping is invalid")
		}
		canonical = strings.Join(parts, "")
	} else if len(upper) != 26 || strings.Contains(upper, "-") {
		return nil, errors.New("window code form is invalid")
	}
	decoded, err := windowBase32.DecodeString(canonical)
	if err != nil || len(decoded) != 16 || windowBase32.EncodeToString(decoded) != canonical {
		return nil, errors.New("window code encoding is invalid")
	}
	return decoded, nil
}

func groupWindowCode(code string) string {
	return code[:5] + "-" + code[5:10] + "-" + code[10:15] + "-" + code[15:20] + "-" + code[20:]
}

func randomRawURL(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func decodeFixed(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("cryptographic field has invalid encoding or length")
	}
	return decoded, nil
}

func isASCII(value string) bool {
	for index := range len(value) {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}
