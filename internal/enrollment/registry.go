// Package enrollment binds an authenticated client certificate to one machine.
package enrollment

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
	"sort"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// SchemaVersion identifies the only registry format accepted by v0.0.2.
	SchemaVersion = 1
	// MaxRegistryBytes bounds the root-provisioned authorization document.
	MaxRegistryBytes = 16 * 1024
	identityPrefix   = "urn:your-cloud:daemon:"
)

var (
	hexSerialPattern      = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
	hexFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Registry is immutable after validation so one request sees one policy.
type Registry struct {
	Schema   int     `json:"schema"`
	Machines []Entry `json:"machines"`
	entries  map[string]Entry
}

// Entry pins one machine to one exact client certificate.
type Entry struct {
	MachineID         string `json:"machine_id"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

// Decode validates one complete registry without consulting the network.
func Decode(data []byte) (*Registry, error) {
	if len(data) == 0 || len(data) > MaxRegistryBytes {
		return nil, errors.New("enrollment registry size is outside the allowed range")
	}
	var registry Registry
	if err := strictjson.Decode(data, &registry); err != nil {
		return nil, fmt.Errorf("decode enrollment registry: %w", err)
	}
	if err := registry.validate(); err != nil {
		return nil, err
	}
	return &registry, nil
}

func (registry *Registry) validate() error {
	if registry.Schema != SchemaVersion {
		return errors.New("unsupported enrollment registry schema")
	}
	if len(registry.Machines) == 0 || len(registry.Machines) > 64 {
		return errors.New("enrollment registry must contain 1..64 machines")
	}
	registry.entries = make(map[string]Entry, len(registry.Machines))
	for _, entry := range registry.Machines {
		if err := validateEntry(entry); err != nil {
			return fmt.Errorf("machine %q: %w", entry.MachineID, err)
		}
		if _, duplicate := registry.entries[entry.MachineID]; duplicate {
			return fmt.Errorf("machine %q is duplicated", entry.MachineID)
		}
		registry.entries[entry.MachineID] = entry
	}
	sort.Slice(registry.Machines, func(left, right int) bool {
		return registry.Machines[left].MachineID < registry.Machines[right].MachineID
	})
	return nil
}

func validateEntry(entry Entry) error {
	if err := machineid.Validate(entry.MachineID); err != nil {
		return err
	}
	if !hexSerialPattern.MatchString(entry.CertificateSerial) {
		return errors.New("certificate_serial must be canonical lower-case hexadecimal")
	}
	if !hexFingerprintPattern.MatchString(entry.CertificateSHA256) {
		return errors.New("certificate_sha256 must be 64 lower-case hexadecimal characters")
	}
	if entry.Status != "active" && entry.Status != "revoked" {
		return errors.New("status must be active or revoked")
	}
	return nil
}

// Authorize verifies the role identity and exact certificate pin after X.509
// chain validation has completed.
func (registry *Registry) Authorize(certificate *x509.Certificate) (string, error) {
	machineID, err := certificateMachineID(certificate)
	if err != nil {
		return "", err
	}
	entry, found := registry.entries[machineID]
	if !found {
		return "", errors.New("client certificate identity is unknown")
	}
	if entry.Status == "revoked" {
		return "", errors.New("client certificate identity is revoked")
	}
	if canonicalSerial(certificate.SerialNumber) != entry.CertificateSerial {
		return "", errors.New("client certificate serial does not match enrollment")
	}
	digest := sha256.Sum256(certificate.Raw)
	expected, _ := hex.DecodeString(entry.CertificateSHA256)
	if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return "", errors.New("client certificate fingerprint does not match enrollment")
	}
	return machineID, nil
}

func certificateMachineID(certificate *x509.Certificate) (string, error) {
	if certificate.IsCA || !hasExactExtendedUsage(certificate, x509.ExtKeyUsageClientAuth) {
		return "", errors.New("client certificate has the wrong role")
	}
	if len(certificate.URIs) != 1 {
		return "", errors.New("client certificate must contain one daemon URI identity")
	}
	identity := certificate.URIs[0]
	if identity.Scheme != "urn" || identity.Opaque == "" || identity.RawQuery != "" || identity.Fragment != "" {
		return "", errors.New("client certificate daemon identity is malformed")
	}
	rendered := identity.String()
	if !strings.HasPrefix(rendered, identityPrefix) {
		return "", errors.New("client certificate has an unsupported identity namespace")
	}
	machineID := strings.TrimPrefix(rendered, identityPrefix)
	if err := machineid.Validate(machineID); err != nil {
		return "", err
	}
	if rendered != identityPrefix+machineID {
		return "", errors.New("client certificate daemon identity is not canonical")
	}
	return machineID, nil
}

func hasExactExtendedUsage(certificate *x509.Certificate, expected x509.ExtKeyUsage) bool {
	return len(certificate.ExtKeyUsage) == 1 && certificate.ExtKeyUsage[0] == expected &&
		len(certificate.UnknownExtKeyUsage) == 0
}

func canonicalSerial(serial *big.Int) string {
	if serial == nil || serial.Sign() <= 0 {
		return ""
	}
	return strings.ToLower(serial.Text(16))
}

// DaemonURI returns the exact URI SAN issued for one machine certificate.
func DaemonURI(machineID string) (*url.URL, error) {
	if err := machineid.Validate(machineID); err != nil {
		return nil, err
	}
	return url.Parse(identityPrefix + machineID)
}
