package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
)

func TestInitializeAuthorityCreatesImmutableSeparatePKI(t *testing.T) {
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	state, err := InitializeAuthority(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	if identifier.ValidateUUIDv4(state.ControllerID) != nil || identifier.ValidateUUIDv4(state.InfrastructureID) != nil || state.ControllerID == state.InfrastructureID {
		t.Fatal("Controller identifiers are invalid or reused")
	}
	serverCA, err := parseOneCertificate([]byte(state.ServerCACertificate))
	if err != nil {
		t.Fatal(err)
	}
	deviceCA, err := parseOneCertificate([]byte(state.DeviceCACertificate))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(serverCA.Raw, deviceCA.Raw) {
		t.Fatal("server and device authorities were reused")
	}
	store, err := OpenAuthorityStore(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.ServerIdentity()
	if err != nil || len(pair.Certificate) != 1 {
		t.Fatalf("server identity is unavailable: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != controllerServerName(state.InfrastructureID) {
		t.Fatal("server name is not bound to the infrastructure")
	}
	encodedSPKI, err := x509.MarshalPKIXPublicKey(serverCA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encodedSPKI)
	got, err := store.ServerCASPKISHA256()
	if err != nil || got != hex.EncodeToString(digest[:]) {
		t.Fatal("server authority SPKI pin is incorrect")
	}
	if _, err := InitializeAuthority(directory, now); err == nil {
		t.Fatal("existing identity authority was replaced")
	}
}

func TestAuthorityRejectsUnknownFieldsAndCrossedServerName(t *testing.T) {
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	state, err := InitializeAuthority(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, authorityFileName)
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuthorityStore(directory, now); err == nil {
		t.Fatal("unknown authority field was accepted")
	}
}

func TestAuthorityRejectsSubstitutedPrivateKey(t *testing.T) {
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	state, err := InitializeAuthority(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(state.ServerCAPrivateKey))
	if block == nil {
		t.Fatal("test authority key is malformed")
	}
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	state.ServerCAPrivateKey = string(pem.EncodeToMemory(block))
	if err := validateAuthorityState(state, now); err == nil {
		t.Fatal("substituted authority key was accepted")
	}
}

func TestIssuedCertificateExpirationMatchesItsEncodedCertificate(t *testing.T) {
	directory := privateTestDirectory(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 987654321, time.UTC)
	if _, err := InitializeAuthority(directory, now); err != nil {
		t.Fatal(err)
	}
	store, err := OpenAuthorityStore(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.IssueDeviceCertificate("00000000-0000-4000-8000-000000000000", &private.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(candidate.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	want := certificate.NotAfter.UTC().Format(time.RFC3339Nano)
	if candidate.ExpiresAt != want {
		t.Fatalf("candidate expiration %q does not match encoded certificate %q", candidate.ExpiresAt, want)
	}
}

func TestRevokeActiveDeviceIsDurableAndRefusesTheOldCertificate(t *testing.T) {
	store, certificate, _, now := activeSessionFixture(t)
	original := store.Snapshot()
	revoked, err := store.RevokeActiveDevice(now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != "revoked" || original.Active == nil || revoked.DeviceID != original.Active.DeviceID {
		t.Fatalf("unexpected revoked record: %#v", revoked)
	}
	if _, err := store.AuthorizeActive(certificate, now.Add(time.Minute)); err == nil {
		t.Fatal("revoked device certificate remained authorized")
	}

	reopened, err := OpenAuthorityStore(store.directory, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	persisted := reopened.Snapshot()
	if persisted.Active != nil || persisted.IdentityRevision != original.IdentityRevision+1 || len(persisted.Revoked) != len(original.Revoked)+1 {
		t.Fatalf("revocation was not durably persisted: %#v", persisted)
	}
	if _, err := reopened.RevokeActiveDevice(now.Add(2 * time.Minute)); err == nil {
		t.Fatal("repeated revocation without an active device was accepted")
	}
}
