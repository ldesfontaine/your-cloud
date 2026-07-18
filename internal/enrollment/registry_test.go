package enrollment

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryAuthorizesExactActiveCertificate(t *testing.T) {
	t.Parallel()
	certificate := testCertificate(t, "lab-machine-1", 42, []byte("exact certificate"))
	registry := testRegistry(t, certificate, "active")

	machineID, err := registry.Authorize(certificate)
	if err != nil || machineID != "lab-machine-1" {
		t.Fatalf("active certificate rejected: machine=%q error=%v", machineID, err)
	}
}

func TestRegistryRejectsUnknownRevokedAndMismatchedCertificates(t *testing.T) {
	t.Parallel()
	certificate := testCertificate(t, "lab-machine-1", 42, []byte("exact certificate"))

	revoked := testRegistry(t, certificate, "revoked")
	if _, err := revoked.Authorize(certificate); err == nil {
		t.Fatal("revoked certificate accepted")
	}

	unknown := testRegistry(t, testCertificate(t, "lab-coordinateur", 43, []byte("other")), "active")
	if _, err := unknown.Authorize(certificate); err == nil {
		t.Fatal("unknown certificate accepted")
	}

	mismatched := *certificate
	mismatched.Raw = []byte("changed certificate")
	if _, err := testRegistry(t, certificate, "active").Authorize(&mismatched); err == nil {
		t.Fatal("mismatched fingerprint accepted")
	}

	wrongRole := *certificate
	wrongRole.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err := testRegistry(t, certificate, "active").Authorize(&wrongRole); err == nil {
		t.Fatal("server certificate accepted as a daemon")
	}

	dualRole := *certificate
	dualRole.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if _, err := testRegistry(t, certificate, "active").Authorize(&dualRole); err == nil {
		t.Fatal("dual-use certificate accepted as a daemon")
	}
}

func TestRegistryRejectsAmbiguousOrFreeEntries(t *testing.T) {
	t.Parallel()
	for _, document := range []string{
		`{}`,
		`{"schema":1,"machines":[]}`,
		`{"schema":1,"schema":1,"machines":[]}`,
		`{"schema":1,"machines":[{"machine_id":"../root","certificate_serial":"1","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"active"}]}`,
		`{"schema":1,"machines":[{"machine_id":"lab-machine-1","certificate_serial":"1","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"pending"}]}`,
		`{"schema":1,"machines":[{"machine_id":"lab-machine-1","certificate_serial":"1","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"active","command":"id"}]}`,
	} {
		if registry, err := Decode([]byte(document)); err == nil {
			t.Fatalf("hostile registry accepted: %#v", registry)
		}
	}
}

func TestStoreReloadAppliesRevocationAndKeepsPreviousPolicyOnFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require the isolated root LAB runner")
	}
	certificate := testCertificate(t, "lab-machine-1", 42, []byte("exact certificate"))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "enrollment.json")
	writeRegistry := func(status string) {
		t.Helper()
		registry := testRegistry(t, certificate, status)
		encoded, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeRegistry("active")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authorize(certificate); err != nil {
		t.Fatal(err)
	}
	writeRegistry("revoked")
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authorize(certificate); err == nil {
		t.Fatal("revocation reload did not take effect")
	}
	if err := os.WriteFile(path, []byte(`{"schema":1,"machines":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("invalid replacement policy accepted")
	}
	if _, err := store.Authorize(certificate); err == nil {
		t.Fatal("failed reload restored or widened the revoked policy")
	}
}

func testCertificate(t *testing.T, machineID string, serial int64, raw []byte) *x509.Certificate {
	t.Helper()
	identity, err := DaemonURI(machineID)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		Raw:          raw,
		SerialNumber: big.NewInt(serial),
		URIs:         []*url.URL{identity},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func testRegistry(t *testing.T, certificate *x509.Certificate, status string) *Registry {
	t.Helper()
	digest := sha256.Sum256(certificate.Raw)
	document := fmt.Sprintf(
		`{"schema":1,"machines":[{"machine_id":"%s","certificate_serial":"%s","certificate_sha256":"%s","status":"%s"}]}`,
		certificate.URIs[0].String()[len(identityPrefix):],
		canonicalSerial(certificate.SerialNumber),
		hex.EncodeToString(digest[:]),
		status,
	)
	registry, err := Decode([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}
