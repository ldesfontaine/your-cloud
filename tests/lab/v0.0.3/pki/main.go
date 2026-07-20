//go:build ignore

// Command pki creates only synthetic, run-local v0.0.3 proof identities.
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
	"strings"
	"time"
)

type authority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
}

type enrollmentRegistry struct {
	Schema           int               `json:"schema"`
	InfrastructureID string            `json:"infrastructure_id"`
	Machines         []enrollmentEntry `json:"machines"`
}

type enrollmentEntry struct {
	MachineID         string `json:"machine_id"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

type readerManifest struct {
	SchemaVersion     int    `json:"schema_version"`
	ControllerID      string `json:"controller_id"`
	InfrastructureID  string `json:"infrastructure_id"`
	URI               string `json:"uri"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

type leafRequest struct {
	name      string
	machineID string
	dnsName   string
	uri       string
	serial    int64
	usage     x509.ExtKeyUsage
}

func main() {
	if len(os.Args) != 4 {
		fatal(errors.New("usage: pki <empty-output-directory> <controller-id> <infrastructure-id>"))
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], time.Now().UTC()); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func run(directory, controllerID, infrastructureID string, now time.Time) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("output directory must be absolute and canonical")
	}
	if !uuidV4(controllerID) || !uuidV4(infrastructureID) {
		return errors.New("controller and infrastructure identifiers must be canonical UUIDv4")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create fresh PKI directory: %w", err)
	}
	relayCA, err := newAuthority("your-cloud-v0.0.3-relay-server-ca", 1, now)
	if err != nil {
		return err
	}
	daemonCA, err := newAuthority("your-cloud-v0.0.3-daemon-client-ca", 2, now)
	if err != nil {
		return err
	}
	relayReaderCA, err := newAuthority("your-cloud-v0.0.3-relay-reader-server-ca", 3, now)
	if err != nil {
		return err
	}
	controllerReaderCA, err := newAuthority("your-cloud-v0.0.3-controller-reader-client-ca", 4, now)
	if err != nil {
		return err
	}
	for name, candidate := range map[string]authority{
		"relay-ca": relayCA, "daemon-ca": daemonCA,
		"relay-reader-ca": relayReaderCA, "controller-reader-ca": controllerReaderCA,
	} {
		if err := writeCertificate(directory, name+".crt", candidate.certificate.Raw); err != nil {
			return err
		}
		if err := writeKey(directory, name+".key", candidate.key); err != nil {
			return err
		}
	}
	if _, err := issue(directory, relayCA, leafRequest{
		name: "relay", dnsName: "relay.v0-0-2.your-cloud.test", serial: 10, usage: x509.ExtKeyUsageServerAuth,
	}, now); err != nil {
		return err
	}
	relayReaderName := "relay-reader." + infrastructureID + ".v0-0-3.your-cloud.test"
	if _, err := issue(directory, relayReaderCA, leafRequest{
		name: "relay-reader", dnsName: relayReaderName, serial: 11, usage: x509.ExtKeyUsageServerAuth,
	}, now); err != nil {
		return err
	}

	machines := make([]enrollmentEntry, 0, 2)
	for index, machineID := range []string{"lab-machine-1", "lab-machine-2"} {
		certificate, err := issue(directory, daemonCA, leafRequest{
			name: machineID, machineID: machineID, serial: int64(20 + index), usage: x509.ExtKeyUsageClientAuth,
		}, now)
		if err != nil {
			return err
		}
		machines = append(machines, enrollmentEntry{
			MachineID: machineID, CertificateSerial: strings.ToLower(certificate.SerialNumber.Text(16)),
			CertificateSHA256: fingerprint(certificate.Raw), Status: "active",
		})
	}

	readerURI := "urn:your-cloud:controller-reader:" + infrastructureID + ":" + controllerID
	reader, err := issue(directory, controllerReaderCA, leafRequest{
		name: "controller-reader", uri: readerURI, serial: 30, usage: x509.ExtKeyUsageClientAuth,
	}, now)
	if err != nil {
		return err
	}
	if _, err := issue(directory, controllerReaderCA, leafRequest{
		name:   "controller-reader-unknown",
		uri:    "urn:your-cloud:controller-reader:" + infrastructureID + ":00000000-0000-4000-8000-000000000000",
		serial: 31, usage: x509.ExtKeyUsageClientAuth,
	}, now); err != nil {
		return err
	}

	registry := enrollmentRegistry{Schema: 2, InfrastructureID: infrastructureID, Machines: machines}
	if err := writeJSON(directory, "enrollment.json", registry); err != nil {
		return err
	}
	manifest := readerManifest{
		SchemaVersion: 1, ControllerID: controllerID, InfrastructureID: infrastructureID,
		URI: readerURI, CertificateSerial: strings.ToLower(reader.SerialNumber.Text(16)),
		CertificateSHA256: fingerprint(reader.Raw), Status: "active",
	}
	if err := writeJSON(directory, "relay-reader.json", manifest); err != nil {
		return err
	}
	return os.WriteFile(
		filepath.Join(directory, "relay-candidate.json"),
		[]byte("{\"schema\":1,\"role\":\"relay-candidate\"}\n"),
		0o644,
	)
}

func newAuthority(name string, serial int64, now time.Time) (authority, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return authority{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return authority{}, err
	}
	certificate, err := x509.ParseCertificate(raw)
	return authority{certificate: certificate, key: private}, err
}

func issue(directory string, issuer authority, request leafRequest, now time.Time) (*x509.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(request.serial), Subject: pkix.Name{CommonName: request.name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{request.usage},
	}
	if request.dnsName != "" {
		template.DNSNames = []string{request.dnsName}
	}
	if request.machineID != "" {
		template.URIs = []*url.URL{{Scheme: "urn", Opaque: "your-cloud:daemon:" + request.machineID}}
	}
	if request.uri != "" {
		identity, err := url.Parse(request.uri)
		if err != nil {
			return nil, err
		}
		template.URIs = []*url.URL{identity}
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

func writeJSON(directory, name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, name), append(encoded, '\n'), 0o644)
}

func fingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func uuidV4(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '4' {
		return false
	}
	if value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
