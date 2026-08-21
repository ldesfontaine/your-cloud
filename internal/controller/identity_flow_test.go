package controller

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testAppIdentity struct {
	devicePrivate   *ecdsa.PrivateKey
	humanPublic     ed25519.PublicKey
	humanPrivate    ed25519.PrivateKey
	recoveryPublic  ed25519.PublicKey
	recoveryPrivate ed25519.PrivateKey
}

func newTestAppIdentity(t *testing.T) testAppIdentity {
	t.Helper()
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recoveryPublic, recoveryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testAppIdentity{device, humanPublic, humanPrivate, recoveryPublic, recoveryPrivate}
}

func TestEnrollmentActivationAndRecoveryAreTwoPhaseAndSeparated(t *testing.T) {
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	if _, err := InitializeAuthority(directory, now); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenAuthorityStore(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPairingManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	first := newTestAppIdentity(t)
	firstCertificate := enrollTestIdentity(t, manager, "enrollment", nil, first)
	if _, err := authority.AuthorizeActive(firstCertificate, now); err != nil {
		t.Fatalf("activated enrollment certificate was refused: %v", err)
	}

	second := newTestAppIdentity(t)
	secondCertificate := enrollTestIdentity(t, manager, "recovery", first.recoveryPrivate, second)
	if _, err := authority.AuthorizeActive(secondCertificate, now); err != nil {
		t.Fatalf("activated recovery certificate was refused: %v", err)
	}
	if _, err := authority.AuthorizeActive(firstCertificate, now); err == nil {
		t.Fatal("old certificate remained active after recovery")
	}
	state := authority.Snapshot()
	if state.IdentityRevision != 2 || len(state.Revoked) != 1 || state.Revoked[0].DeviceID == state.Active.DeviceID || state.Active.RecoveryEpoch != 2 {
		t.Fatalf("recovery did not atomically replace authority: %#v", state)
	}
}

func enrollTestIdentity(t *testing.T, manager *PairingManager, mode string, currentRecovery ed25519.PrivateKey, identity testAppIdentity) *x509.Certificate {
	t.Helper()
	sheet, err := manager.OpenWindow(mode)
	if err != nil {
		t.Fatal(err)
	}
	requestID := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	challenge, err := manager.Begin(mode, IdentityChallengeRequest{
		SchemaVersion: 1, WindowID: sheet.WindowID, WindowCode: sheet.WindowCode, RequestID: requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	csr := testDeviceCSR(t, sheet.InfrastructureID, challenge.DeviceID, identity.devicePrivate)
	manager.mu.Lock()
	transaction := manager.window.transaction
	transcript := manager.identityTranscript(transaction, csr,
		identity.humanPublic, identity.recoveryPublic)
	manager.mu.Unlock()
	request := IdentityCompletionRequest{
		SchemaVersion: 1, TransactionID: challenge.TransactionID,
		DeviceCSR:             base64.RawURLEncoding.EncodeToString(csr),
		HumanPublicKey:        base64.RawURLEncoding.EncodeToString(identity.humanPublic),
		NextRecoveryPublicKey: base64.RawURLEncoding.EncodeToString(identity.recoveryPublic),
		HumanSignature:        base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript)),
		NextRecoverySignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.recoveryPrivate, transcript)),
	}
	if mode == "recovery" {
		request.CurrentRecoverySignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(currentRecovery, transcript))
	}
	completed, err := manager.Complete(mode, request)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(completed.CertificatePEM))
	if block == nil || len(rest) != 0 {
		t.Fatal("candidate certificate PEM is malformed")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	originalManager := manager
	restarted, err := NewPairingManager(manager.authority)
	if err != nil {
		t.Fatalf("durable candidate did not survive manager restart: %v", err)
	}
	restarted.now = manager.now
	manager = restarted
	if _, err := manager.authority.AuthorizeActive(certificate, manager.now()); err == nil {
		t.Fatal("candidate was active before activation")
	}
	activationDigest := sha256.Sum256([]byte(`{"schema_version":1}`))
	wrongMode := "recovery"
	if mode == "recovery" {
		wrongMode = "enrollment"
	}
	if _, err := manager.ActivateForMode(wrongMode, challenge.TransactionID, certificate, activationDigest); err == nil {
		t.Fatal("candidate activation through the other mode route was accepted")
	}
	response, err := manager.Activate(challenge.TransactionID, certificate, activationDigest)
	if err != nil || response.DeviceStatus != "active" {
		t.Fatalf("candidate activation failed: %#v %v", response, err)
	}
	if replay, err := manager.Activate(challenge.TransactionID, certificate, activationDigest); err != nil || replay.IdentityRevision != response.IdentityRevision {
		t.Fatalf("exact activation replay failed: %#v %v", replay, err)
	}
	if _, err := os.Lstat(filepath.Join(manager.authority.directory, candidateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed candidate file remains present: %v", err)
	}
	originalManager.mu.Lock()
	originalManager.candidate = nil
	originalManager.mu.Unlock()
	wrongDigest := sha256.Sum256([]byte(`{"schema_version":2}`))
	if _, err := manager.Activate(challenge.TransactionID, certificate, wrongDigest); err == nil {
		t.Fatal("activation replay with different body was accepted")
	}
	return certificate
}

func TestFiveCryptographicFailuresCloseWindowWithoutAuthority(t *testing.T) {
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	if _, err := InitializeAuthority(directory, now); err != nil {
		t.Fatal(err)
	}
	authority, _ := OpenAuthorityStore(directory, now)
	manager, _ := NewPairingManager(authority)
	manager.now = func() time.Time { return now }
	sheet, err := manager.OpenWindow("enrollment")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := manager.Begin("enrollment", IdentityChallengeRequest{
		SchemaVersion: 1, WindowID: sheet.WindowID, WindowCode: sheet.WindowCode,
		RequestID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := manager.Complete("enrollment", IdentityCompletionRequest{SchemaVersion: 1, TransactionID: challenge.TransactionID}); err == nil {
			t.Fatal("invalid cryptographic completion was accepted")
		}
	}
	if manager.window != nil || authority.Snapshot().Active != nil {
		t.Fatal("fifth failure did not close the window cleanly")
	}
}

func testDeviceCSR(t *testing.T, infrastructureID, deviceID string, private *ecdsa.PrivateKey) []byte {
	t.Helper()
	identity, err := url.Parse(deviceURI(infrastructureID, deviceID))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{identity},
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
