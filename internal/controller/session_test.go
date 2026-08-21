package controller

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func activeSessionFixture(t *testing.T) (*AuthorityStore, *x509.Certificate, testAppIdentity, time.Time) {
	t.Helper()
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	if _, err := InitializeAuthority(directory, now); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenAuthorityStore(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	pairing, _ := NewPairingManager(authority)
	pairing.now = func() time.Time { return now }
	identity := newTestAppIdentity(t)
	certificate := enrollTestIdentity(t, pairing, "enrollment", nil, identity)
	return authority, certificate, identity, now
}

func TestSensitiveChallengeRequiresMatchingActiveSession(t *testing.T) {
	authority, certificate, identity, initial := activeSessionFixture(t)
	manager, _ := NewSessionManager(authority)
	manager.now = func() time.Time { return initial }
	bodyDigest := sha256.Sum256([]byte(`{"schema_version":1}`))
	openRequest := SessionChallengeRequest{
		SchemaVersion: 1, Purpose: "open_session", TargetMethod: "POST", TargetRoute: "/v0/session",
		BodySHA256: base64.RawURLEncoding.EncodeToString(bodyDigest[:]),
	}
	challenge, err := manager.Challenge(certificate, openRequest, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	transcript := sessionTranscript(authority.Snapshot(), manager.challenges[authority.Snapshot().Active.DeviceID+"\x00open_session"])
	manager.mu.Unlock()
	opened, err := manager.Open(certificate, SessionOpenRequest{
		SchemaVersion: 1, ChallengeID: challenge.ChallengeID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript)),
	})
	if err != nil {
		t.Fatal(err)
	}
	context, err := manager.Authenticate(certificate, "Bearer "+opened.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	rotateDigest := sha256.Sum256([]byte(`{"schema_version":1,"csr":"candidate"}`))
	rotateRequest := SessionChallengeRequest{
		SchemaVersion: 1, Purpose: "rotate_device", TargetMethod: "PUT", TargetRoute: "/v0/device-rotations",
		BodySHA256: base64.RawURLEncoding.EncodeToString(rotateDigest[:]),
	}
	if _, err := manager.Challenge(certificate, rotateRequest, nil); err == nil {
		t.Fatal("sensitive challenge without active session was accepted")
	}
	wrong := context
	wrong.DeviceID = "00000000-0000-4000-8000-000000000000"
	if _, err := manager.Challenge(certificate, rotateRequest, &wrong); err == nil {
		t.Fatal("sensitive challenge with a mismatched session was accepted")
	}
	if _, err := manager.Challenge(certificate, rotateRequest, &context); err != nil {
		t.Fatalf("sensitive challenge with matching session failed: %v", err)
	}
}

func TestSessionChallengeSignatureBindingLifetimeAndLogout(t *testing.T) {
	authority, certificate, identity, initial := activeSessionFixture(t)
	current := initial
	manager, _ := NewSessionManager(authority)
	manager.now = func() time.Time { return current }
	bodyDigest := sha256.Sum256([]byte(`{"schema_version":1}`))
	challengeRequest := SessionChallengeRequest{
		SchemaVersion: 1, Purpose: "open_session", TargetMethod: "POST", TargetRoute: "/v0/session",
		BodySHA256: base64.RawURLEncoding.EncodeToString(bodyDigest[:]),
	}
	challenge, err := manager.Challenge(certificate, challengeRequest, nil)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := manager.Challenge(certificate, challengeRequest, nil)
	if err != nil || replay.ChallengeID != challenge.ChallengeID || replay.Challenge != challenge.Challenge {
		t.Fatal("identical active challenge was not replayed")
	}
	manager.mu.Lock()
	stored := manager.challenges[authority.Snapshot().Active.DeviceID+"\x00open_session"]
	transcript := sessionTranscript(authority.Snapshot(), stored)
	manager.mu.Unlock()
	opened, err := manager.Open(certificate, SessionOpenRequest{
		SchemaVersion: 1, ChallengeID: challenge.ChallengeID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript)),
	})
	if err != nil || !canonicalRawURLBytes(opened.SessionToken, 32) {
		t.Fatalf("valid human proof did not open a session: %#v %v", opened, err)
	}
	context, err := manager.Authenticate(certificate, "Bearer "+opened.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(29 * time.Minute)
	if err := manager.Touch(context); err != nil {
		t.Fatalf("accepted request did not extend inactivity: %v", err)
	}
	current = current.Add(30 * time.Minute)
	if _, err := manager.Authenticate(certificate, "Bearer "+opened.SessionToken); err != nil {
		t.Fatal("inclusive 30-minute inactivity boundary was rejected")
	}
	current = current.Add(time.Nanosecond)
	if _, err := manager.Authenticate(certificate, "Bearer "+opened.SessionToken); err == nil {
		t.Fatal("session beyond inactivity bound was accepted")
	}

	current = initial
	challenge, _ = manager.Challenge(certificate, challengeRequest, nil)
	manager.mu.Lock()
	stored = manager.challenges[authority.Snapshot().Active.DeviceID+"\x00open_session"]
	transcript = sessionTranscript(authority.Snapshot(), stored)
	manager.mu.Unlock()
	opened, err = manager.Open(certificate, SessionOpenRequest{SchemaVersion: 1, ChallengeID: challenge.ChallengeID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.humanPrivate, transcript))})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Logout(certificate, "Bearer "+opened.SessionToken); err != nil {
		t.Fatal(err)
	}
	if err := manager.Logout(certificate, "Bearer "+opened.SessionToken); err != nil {
		t.Fatal("exact logout replay was not idempotent")
	}
	if _, err := manager.Authenticate(certificate, "Bearer "+opened.SessionToken); err == nil {
		t.Fatal("logged-out token remained valid")
	}
}

func TestInvalidHumanSignaturesUseProgressiveDelayAndBlock(t *testing.T) {
	authority, certificate, _, initial := activeSessionFixture(t)
	current := initial
	manager, _ := NewSessionManager(authority)
	manager.now = func() time.Time { return current }
	bodyDigest := sha256.Sum256([]byte(`{"schema_version":1}`))
	request := SessionChallengeRequest{
		SchemaVersion: 1, Purpose: "open_session", TargetMethod: "POST", TargetRoute: "/v0/session",
		BodySHA256: base64.RawURLEncoding.EncodeToString(bodyDigest[:]),
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	for attempt, delay := range want {
		challenge, err := manager.Challenge(certificate, request, nil)
		if err != nil {
			t.Fatalf("challenge %d failed: %v", attempt+1, err)
		}
		_, err = manager.Open(certificate, SessionOpenRequest{
			SchemaVersion: 1, ChallengeID: challenge.ChallengeID,
			Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		})
		var delayed AuthenticationDelayError
		if !errors.As(err, &delayed) || delayed.Delay != delay {
			t.Fatalf("failure %d delay=%s err=%v, want %s", attempt+1, delayed.Delay, err, delay)
		}
	}
	if _, err := manager.Challenge(certificate, request, nil); err == nil {
		t.Fatal("challenge rate did not also bound repeated failures")
	}
	manager.mu.Lock()
	block := manager.blockDelayLocked(authority.Snapshot().Active.DeviceID, current)
	manager.mu.Unlock()
	if block != 5*time.Minute {
		t.Fatalf("fifth failure block=%s, want 5m", block)
	}
}
