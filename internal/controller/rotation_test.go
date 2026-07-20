package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"
)

func TestDeviceRotationRequiresFreshHumanProofAndSurvivesRestart(t *testing.T) {
	authority, oldCertificate, identity, now := activeSessionFixture(t)
	sessions, context := seededSession(t, authority, now)
	state := authority.Snapshot()
	rotationID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 16))
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := base64.RawURLEncoding.EncodeToString(testDeviceCSR(t, state.InfrastructureID, state.Active.DeviceID, private))
	core := deviceRotationCore{SchemaVersion: 1, RotationID: rotationID, DeviceCSR: csr}
	digest := sha256.Sum256(mustJSON(core))
	challenge, err := sessions.Challenge(oldCertificate, SessionChallengeRequest{
		SchemaVersion: 1, Purpose: "rotate_device", TargetMethod: "PUT", TargetRoute: "/v0/device-rotations",
		BodySHA256: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, &context)
	if err != nil {
		t.Fatal(err)
	}
	sessions.mu.Lock()
	stored := sessions.challenges[state.Active.DeviceID+"\x00rotate_device"]
	transcript := sessionTranscript(state, stored)
	sessions.mu.Unlock()
	wrongDigest := sha256.Sum256([]byte("crossed operation"))
	if err := sessions.VerifySensitive(oldCertificate, context, "rotate_device", wrongDigest, challenge.ChallengeID,
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript))); err == nil {
		t.Fatal("fresh human proof was accepted for another operation")
	}
	if err := sessions.VerifySensitive(oldCertificate, context, "rotate_device", digest, challenge.ChallengeID,
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript))); err != nil {
		t.Fatal(err)
	}
	if err := sessions.VerifySensitive(oldCertificate, context, "rotate_device", digest, challenge.ChallengeID,
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript))); err == nil {
		t.Fatal("fresh human proof was replayed")
	}

	pairing, err := NewPairingManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	pairing.now = func() time.Time { return now }
	candidate, err := pairing.PrepareDeviceRotation(rotationID, csr, digest)
	if err != nil {
		t.Fatal(err)
	}
	newCertificate := parseCandidateCertificate(t, candidate.CertificatePEM)
	if _, err := authority.AuthorizeActive(newCertificate, now); err == nil {
		t.Fatal("rotation candidate became active before activation")
	}
	restarted, err := NewPairingManager(authority)
	if err != nil {
		t.Fatalf("rotation candidate did not survive restart: %v", err)
	}
	restarted.now = func() time.Time { return now }
	activationDigest := sha256.Sum256([]byte(`{"schema_version":1}`))
	restarted.mu.Lock()
	durableCandidate := *restarted.candidate
	restarted.mu.Unlock()
	if err := authority.activateCandidate(durableCandidate, activationDigest, now); err != nil {
		t.Fatalf("rotation commit before simulated crash failed: %v", err)
	}
	afterCrash, err := NewPairingManager(authority)
	if err != nil {
		t.Fatalf("restart after committed rotation did not recover: %v", err)
	}
	afterCrash.now = func() time.Time { return now }
	activated, err := afterCrash.ActivateForMode("rotation", rotationID, newCertificate, activationDigest)
	if err != nil || activated.IdentityRevision != state.IdentityRevision+1 {
		t.Fatalf("rotation activation receipt after restart failed: %#v %v", activated, err)
	}
	if _, err := authority.AuthorizeActive(oldCertificate, now); err == nil {
		t.Fatal("old device certificate remained active after rotation")
	}
	if _, err := authority.AuthorizeActive(newCertificate, now); err != nil {
		t.Fatalf("rotated device certificate was refused: %v", err)
	}
	if err := sessions.Touch(context); err == nil {
		t.Fatal("old session survived device rotation")
	}
	if replay, err := afterCrash.ActivateForMode("rotation", rotationID, newCertificate, activationDigest); err != nil ||
		replay.IdentityRevision != activated.IdentityRevision {
		t.Fatalf("rotation activation receipt was not replayable: %#v %v", replay, err)
	}
}

func TestRecoveryKeyRotationKeepsDeviceAndSessionAndPersistsReceipt(t *testing.T) {
	authority, _, identity, now := activeSessionFixture(t)
	sessions, context := seededSession(t, authority, now)
	before := authority.Snapshot()
	operationID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 16))
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mutation := RecoveryKeyMutation{
		SchemaVersion: 1, OperationID: operationID,
		NextRecoveryEpoch:     before.Active.RecoveryEpoch + 1,
		NextRecoverySalt:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 32)),
		NextRecoveryPublicKey: base64.RawURLEncoding.EncodeToString(nextPublic),
	}
	digest := sha256.Sum256(mustJSON(mutation))
	transcript := recoveryKeyTranscript(before, mutation)
	result, err := authority.RotateRecoveryKey(
		mutation, digest,
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.recoveryPrivate, transcript)),
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(nextPrivate, transcript)), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	after := authority.Snapshot()
	if result.RecoveryEpoch != mutation.NextRecoveryEpoch || after.IdentityRevision != before.IdentityRevision ||
		after.Active.CertificateSHA256 != before.Active.CertificateSHA256 || after.Active.RecoveryPublicKey != mutation.NextRecoveryPublicKey {
		t.Fatalf("recovery key rotation changed the wrong authority: %#v", after)
	}
	if err := sessions.Touch(context); err != nil {
		t.Fatalf("valid session was invalidated by recovery key rotation: %v", err)
	}
	if replay, found, err := authority.RecoveryKeyReceipt(operationID, digest, now); err != nil || !found || replay != result {
		t.Fatalf("exact recovery key receipt was not replayable: %#v %t %v", replay, found, err)
	}
	reopened, err := OpenAuthorityStore(authority.directory, now)
	if err != nil {
		t.Fatal(err)
	}
	if replay, found, err := reopened.RecoveryKeyReceipt(operationID, digest, now); err != nil || !found || replay != result {
		t.Fatalf("durable recovery key receipt was not replayable: %#v %t %v", replay, found, err)
	}
	conflict := digest
	conflict[0] ^= 0xff
	if _, _, err := reopened.RecoveryKeyReceipt(operationID, conflict, now); err == nil {
		t.Fatal("recovery key operation identifier accepted a different digest")
	}
}

func seededSession(t *testing.T, authority *AuthorityStore, now time.Time) (*SessionManager, SessionContext) {
	t.Helper()
	manager, err := NewSessionManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	state := authority.Snapshot()
	tokenDigest := sha256.Sum256(bytes.Repeat([]byte{0x44}, 32))
	manager.sessions[state.Active.DeviceID] = &activeSession{
		tokenDigest: tokenDigest, deviceID: state.Active.DeviceID,
		certificateSHA256: state.Active.CertificateSHA256, certificateSerial: state.Active.CertificateSerial,
		humanPublicKey: state.Active.HumanPublicKey, controllerID: state.ControllerID,
		infrastructureID: state.InfrastructureID, identityRevision: state.IdentityRevision,
		created: now, lastUsed: now, absoluteExpires: now.Add(sessionAbsoluteLifetime),
	}
	return manager, SessionContext{
		DeviceID: state.Active.DeviceID, CertificateSHA256: state.Active.CertificateSHA256,
		IdentityRevision: state.IdentityRevision, tokenDigest: tokenDigest,
	}
}

func parseCandidateCertificate(t *testing.T, encoded string) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(rest) != 0 {
		t.Fatal("candidate certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
