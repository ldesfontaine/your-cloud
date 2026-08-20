// Package readeridentity binds the one Controller reader to one Relay.
package readeridentity

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/securefile"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// ManifestPath is fixed so the Relay cannot be pointed at arbitrary policy.
	ManifestPath = "/etc/your-cloud/relay-reader.json"
	// MaxManifestBytes bounds the root-owned reader authorization policy.
	MaxManifestBytes = 4 * 1024
	manifestSchema   = 1
)

var (
	hexSerial      = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
	hexFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Manifest pins the only reader certificate accepted by an infrastructure.
type Manifest struct {
	SchemaVersion     int    `json:"schema_version"`
	ControllerID      string `json:"controller_id"`
	InfrastructureID  string `json:"infrastructure_id"`
	URI               string `json:"uri"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

// Decode rejects ambiguous documents and validates the complete manifest.
func Decode(data []byte) (*Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return nil, errors.New("reader manifest size is outside the allowed range")
	}
	var manifest Manifest
	if err := strictjson.Decode(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode reader manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (manifest *Manifest) validate() error {
	if manifest.SchemaVersion != manifestSchema {
		return errors.New("unsupported reader manifest schema_version")
	}
	if err := identifier.ValidateUUIDv4(manifest.ControllerID); err != nil {
		return fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(manifest.InfrastructureID); err != nil {
		return fmt.Errorf("infrastructure_id: %w", err)
	}
	expectedURI := URI(manifest.InfrastructureID, manifest.ControllerID)
	if manifest.URI != expectedURI {
		return errors.New("reader URI does not match controller and infrastructure identifiers")
	}
	if !hexSerial.MatchString(manifest.CertificateSerial) {
		return errors.New("certificate_serial must be canonical lower-case hexadecimal")
	}
	if !hexFingerprint.MatchString(manifest.CertificateSHA256) {
		return errors.New("certificate_sha256 must be 64 lower-case hexadecimal characters")
	}
	if manifest.Status != "active" && manifest.Status != "revoked" {
		return errors.New("reader status must be active or revoked")
	}
	return nil
}

// URI returns the one canonical SAN permitted for a Controller reader.
func URI(infrastructureID, controllerID string) string {
	return "urn:your-cloud:controller-reader:" + infrastructureID + ":" + controllerID
}

// Authorize rechecks role, identity, period and exact public certificate pin.
func (manifest *Manifest) Authorize(certificate *x509.Certificate, now time.Time) error {
	if manifest == nil || certificate == nil {
		return errors.New("reader identity is unavailable")
	}
	if manifest.Status != "active" {
		return errors.New("reader identity is revoked")
	}
	if certificate.IsCA || certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(certificate.UnknownExtKeyUsage) != 0 {
		return errors.New("reader certificate has the wrong role")
	}
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return errors.New("reader certificate is outside its validity period")
	}
	if len(certificate.URIs) != 1 || canonicalURI(certificate.URIs[0]) != manifest.URI {
		return errors.New("reader certificate URI does not match manifest")
	}
	if CanonicalSerial(certificate.SerialNumber) != manifest.CertificateSerial {
		return errors.New("reader certificate serial does not match manifest")
	}
	digest := sha256.Sum256(certificate.Raw)
	expected, _ := hex.DecodeString(manifest.CertificateSHA256)
	if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return errors.New("reader certificate fingerprint does not match manifest")
	}
	return nil
}

func canonicalURI(identity *url.URL) string {
	if identity == nil || identity.Scheme != "urn" || identity.Opaque == "" ||
		identity.RawQuery != "" || identity.Fragment != "" || identity.Host != "" {
		return ""
	}
	rendered := identity.String()
	if !strings.HasPrefix(rendered, "urn:your-cloud:controller-reader:") {
		return ""
	}
	return rendered
}

// CanonicalSerial renders the one serial form this module pins and the mint
// prints — lowercase hexadecimal, no padding. Exported so the birth of a
// reader identity and its authorization read the same canon from the same
// place: a second rendering elsewhere would eventually diverge from this one.
func CanonicalSerial(serial *big.Int) string {
	if serial == nil || serial.Sign() <= 0 {
		return ""
	}
	return strings.ToLower(serial.Text(16))
}

// Store swaps a complete valid root-owned manifest on explicit reload.
type Store struct {
	mu       sync.RWMutex
	path     string
	manifest *Manifest
}

// OpenStore loads the initial manifest before the reader listener opens.
func OpenStore(path string) (*Store, error) {
	store := &Store{path: path}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload keeps the previous policy when the candidate is invalid.
func (store *Store) Reload() error {
	if store == nil || store.path == "" {
		return errors.New("reader manifest path is required")
	}
	data, err := securefile.ReadRootOwned(store.path, MaxManifestBytes)
	if err != nil {
		return err
	}
	manifest, err := Decode(data)
	if err != nil {
		return err
	}
	store.mu.Lock()
	if store.manifest != nil &&
		(store.manifest.ControllerID != manifest.ControllerID || store.manifest.InfrastructureID != manifest.InfrastructureID) {
		store.mu.Unlock()
		return errors.New("reader manifest identifiers are immutable")
	}
	store.manifest = manifest
	store.mu.Unlock()
	return nil
}

// Authorize checks the current manifest on every TLS and HTTP request.
func (store *Store) Authorize(certificate *x509.Certificate, now time.Time) error {
	store.mu.RLock()
	manifest := store.manifest
	store.mu.RUnlock()
	return manifest.Authorize(certificate, now)
}

// Snapshot returns public identities needed in the snapshot response.
func (store *Store) Snapshot() (Manifest, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.manifest == nil {
		return Manifest{}, errors.New("reader manifest is unavailable")
	}
	return *store.manifest, nil
}
