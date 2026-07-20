package readeridentity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"
)

const (
	testControllerID     = "22222222-2222-4222-8222-222222222222"
	testInfrastructureID = "11111111-1111-4111-8111-111111111111"
)

func TestManifestAuthorizesOnlyExactActiveReader(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	certificate := testReaderCertificate(t, now)
	digest := sha256.Sum256(certificate.Raw)
	document := fmt.Sprintf(
		`{"schema_version":1,"controller_id":"%s","infrastructure_id":"%s","uri":"%s","certificate_serial":"2a","certificate_sha256":"%s","status":"active"}`,
		testControllerID,
		testInfrastructureID,
		URI(testInfrastructureID, testControllerID),
		hex.EncodeToString(digest[:]),
	)
	manifest, err := Decode([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Authorize(certificate, now); err != nil {
		t.Fatalf("exact reader rejected: %v", err)
	}

	revoked := *manifest
	revoked.Status = "revoked"
	if err := revoked.Authorize(certificate, now); err == nil {
		t.Fatal("revoked reader accepted")
	}
	wrongRole := *certificate
	wrongRole.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if err := manifest.Authorize(&wrongRole, now); err == nil {
		t.Fatal("server certificate accepted as reader")
	}
	if err := manifest.Authorize(certificate, certificate.NotAfter.Add(time.Nanosecond)); err == nil {
		t.Fatal("expired reader accepted")
	}
}

func TestManifestRejectsAmbiguousOrCrossedIdentity(t *testing.T) {
	t.Parallel()
	for _, document := range []string{
		`{}`,
		`{"schema_version":1,"schema_version":1,"controller_id":"22222222-2222-4222-8222-222222222222","infrastructure_id":"11111111-1111-4111-8111-111111111111","uri":"urn:your-cloud:controller-reader:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222","certificate_serial":"2a","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"active"}`,
		`{"schema_version":1,"controller_id":"22222222-2222-4222-8222-222222222222","infrastructure_id":"11111111-1111-4111-8111-111111111111","uri":"urn:your-cloud:controller-reader:33333333-3333-4333-8333-333333333333:22222222-2222-4222-8222-222222222222","certificate_serial":"2a","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"active"}`,
		`{"schema_version":1,"controller_id":"22222222-2222-4222-8222-222222222222","infrastructure_id":"11111111-1111-4111-8111-111111111111","uri":"urn:your-cloud:controller-reader:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222","certificate_serial":"2a","certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"pending"}`,
	} {
		if manifest, err := Decode([]byte(document)); err == nil {
			t.Fatalf("hostile manifest accepted: %#v", manifest)
		}
	}
}

func testReaderCertificate(t *testing.T, now time.Time) *x509.Certificate {
	t.Helper()
	identity, err := url.Parse(URI(testInfrastructureID, testControllerID))
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		Raw:          []byte("exact reader certificate"),
		SerialNumber: big.NewInt(42),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identity},
	}
}
