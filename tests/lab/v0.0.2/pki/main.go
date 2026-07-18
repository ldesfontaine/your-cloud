//go:build ignore

// Command pki creates only synthetic, run-local v0.0.2 proof identities.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type authority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
}

type registry struct {
	Schema   int     `json:"schema"`
	Machines []entry `json:"machines"`
}

type entry struct {
	MachineID         string `json:"machine_id"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

func main() {
	if len(os.Args) != 2 {
		fatal(errors.New("usage: pki <empty-output-directory>"))
	}
	if err := run(os.Args[1], time.Now().UTC()); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func run(directory string, now time.Time) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("output directory must be absolute and canonical")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create fresh PKI directory: %w", err)
	}
	relayCA, err := newAuthority("your-cloud-v0.0.2-relay-ca", 1, now)
	if err != nil {
		return err
	}
	daemonCA, err := newAuthority("your-cloud-v0.0.2-daemon-ca", 2, now)
	if err != nil {
		return err
	}
	wrongDaemonCA, err := newAuthority("your-cloud-v0.0.2-wrong-daemon-ca", 3, now)
	if err != nil {
		return err
	}
	wrongRelayCA, err := newAuthority("your-cloud-v0.0.2-wrong-relay-ca", 4, now)
	if err != nil {
		return err
	}
	for name, candidate := range map[string]authority{
		"relay-ca": relayCA, "daemon-ca": daemonCA,
		"wrong-daemon-ca": wrongDaemonCA, "wrong-relay-ca": wrongRelayCA,
	} {
		if err := writeCertificate(directory, name+".crt", candidate.certificate.Raw); err != nil {
			return err
		}
		if err := writeKey(directory, name+".key", candidate.key); err != nil {
			return err
		}
	}

	relay, err := issue(directory, relayCA, leafRequest{name: "relay", serial: 10, dnsName: "relay.v0-0-2.your-cloud.test", usage: x509.ExtKeyUsageServerAuth}, now)
	if err != nil {
		return err
	}
	_ = relay
	if _, err := issue(directory, relayCA, leafRequest{name: "relay-wrong-name", serial: 11, dnsName: "other.invalid", usage: x509.ExtKeyUsageServerAuth}, now); err != nil {
		return err
	}
	if _, err := issue(directory, wrongRelayCA, leafRequest{name: "relay-wrong-ca", serial: 12, dnsName: "relay.v0-0-2.your-cloud.test", usage: x509.ExtKeyUsageServerAuth}, now); err != nil {
		return err
	}

	machines := make([]entry, 0, 2)
	for index, machineID := range []string{"lab-coordinateur", "lab-machine-1"} {
		issued, err := issue(directory, daemonCA, leafRequest{name: machineID, machineID: machineID, serial: int64(20 + index), usage: x509.ExtKeyUsageClientAuth}, now)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(issued.Raw)
		machines = append(machines, entry{MachineID: machineID, CertificateSerial: issued.SerialNumber.Text(16), CertificateSHA256: hex.EncodeToString(digest[:]), Status: "active"})
	}
	for _, request := range []leafRequest{
		{name: "unknown", machineID: "lab-machine-2", serial: 30, usage: x509.ExtKeyUsageClientAuth},
		{name: "wrong-usage", machineID: "lab-machine-1", serial: 31, usage: x509.ExtKeyUsageServerAuth},
		{name: "expired", machineID: "lab-machine-1", serial: 32, usage: x509.ExtKeyUsageClientAuth, expired: true},
	} {
		if _, err := issue(directory, daemonCA, request, now); err != nil {
			return err
		}
	}
	if _, err := issue(directory, wrongDaemonCA, leafRequest{name: "wrong-ca", machineID: "lab-machine-1", serial: 33, usage: x509.ExtKeyUsageClientAuth}, now); err != nil {
		return err
	}
	encoded, err := json.Marshal(registry{Schema: 1, Machines: machines})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "enrollment.json"), append(encoded, '\n'), 0o644)
}

func newAuthority(name string, serial int64, now time.Time) (authority, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return authority{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return authority{}, err
	}
	certificate, err := x509.ParseCertificate(raw)
	return authority{certificate: certificate, key: private}, err
}

type leafRequest struct {
	name      string
	machineID string
	dnsName   string
	serial    int64
	usage     x509.ExtKeyUsage
	expired   bool
}

func issue(directory string, issuer authority, request leafRequest, now time.Time) (*x509.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := now.Add(-time.Hour), now.Add(24*time.Hour)
	if request.expired {
		notBefore, notAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(request.serial), Subject: pkix.Name{CommonName: "unused-" + request.name},
		NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{request.usage},
	}
	if request.dnsName != "" {
		template.DNSNames = []string{request.dnsName}
	}
	if request.machineID != "" {
		template.URIs = []*url.URL{{Scheme: "urn", Opaque: "your-cloud:daemon:" + request.machineID}}
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, public, issuer.key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	if err := writeCertificate(directory, request.name+".crt", raw); err != nil {
		return nil, err
	}
	if err := writeKey(directory, request.name+".key", private); err != nil {
		return nil, err
	}
	return certificate, nil
}

func writeCertificate(directory, name string, raw []byte) error {
	return os.WriteFile(filepath.Join(directory, name), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0o644)
}

func writeKey(directory, name string, key ed25519.PrivateKey) error {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0o600)
}
