// Command generate-runtime-pki creates one short-lived synthetic LAB PKI.
// It never persists CA private keys and never prints leaf private material.
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
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type authority struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	encoded     []byte
}

type leaf struct {
	certificate    *x509.Certificate
	certificatePEM []byte
	privateKeyPEM  []byte
}

type enrollmentEntry struct {
	MachineID         string `json:"machine_id"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

type enrollmentRegistry struct {
	Schema           int               `json:"schema"`
	InfrastructureID string            `json:"infrastructure_id"`
	Machines         []enrollmentEntry `json:"machines"`
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

func main() {
	output := flag.String("output", "", "new private output directory")
	infrastructureID := flag.String("infrastructure-id", "", "v4 infrastructure UUID")
	controllerID := flag.String("controller-id", "", "v4 Controller UUID")
	flag.Parse()
	if flag.NArg() != 0 || !uuidV4.MatchString(*infrastructureID) || !uuidV4.MatchString(*controllerID) {
		fatal(errors.New("output and canonical v4 Controller/infrastructure identifiers are required"))
	}
	if !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
		fatal(errors.New("output must be one absolute canonical path"))
	}
	if err := os.Mkdir(*output, 0o700); err != nil {
		fatal(fmt.Errorf("create output: %w", err))
	}
	for _, name := range []string{"relay", "machine-1", "machine-2", "controller"} {
		if err := os.Mkdir(filepath.Join(*output, name), 0o700); err != nil {
			fatal(fmt.Errorf("create role directory: %w", err))
		}
	}

	now := time.Now().UTC()
	relayServerCA := newAuthority("Your Cloud LAB Relay server CA", 1, now)
	daemonClientCA := newAuthority("Your Cloud LAB Daemon client CA", 2, now)
	readerServerCA := newAuthority("Your Cloud LAB Relay reader server CA", 3, now)
	controllerClientCA := newAuthority("Your Cloud LAB Controller reader client CA", 4, now)

	relayServer := newLeaf(relayServerCA, "Relay ingestion", 0x11, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{"relay.v0-0-2.your-cloud.test"}, nil)
	daemonOne := newLeaf(daemonClientCA, "Daemon lab-machine-1", 0x12, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil,
		[]string{"urn:your-cloud:daemon:lab-machine-1"})
	daemonTwo := newLeaf(daemonClientCA, "Daemon lab-machine-2", 0x13, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil,
		[]string{"urn:your-cloud:daemon:lab-machine-2"})
	readerServerName := "relay-reader." + *infrastructureID + ".v0-0-3.your-cloud.test"
	readerServer := newLeaf(readerServerCA, "Relay reader", 0x21, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{readerServerName}, nil)
	readerURI := "urn:your-cloud:controller-reader:" + *infrastructureID + ":" + *controllerID
	controllerReader := newLeaf(controllerClientCA, "Controller reader", 0x22, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, []string{readerURI})

	writeRole(*output, "relay", map[string]fileValue{
		"relay.crt":                {relayServer.certificatePEM, 0o644},
		"relay.key":                {relayServer.privateKeyPEM, 0o600},
		"daemon-ca.crt":            {daemonClientCA.encoded, 0o644},
		"relay-reader.crt":         {readerServer.certificatePEM, 0o644},
		"relay-reader.key":         {readerServer.privateKeyPEM, 0o600},
		"controller-reader-ca.crt": {controllerClientCA.encoded, 0o644},
	})
	writeRole(*output, "machine-1", map[string]fileValue{
		"daemon.crt":   {daemonOne.certificatePEM, 0o644},
		"daemon.key":   {daemonOne.privateKeyPEM, 0o600},
		"relay-ca.crt": {relayServerCA.encoded, 0o644},
	})
	writeRole(*output, "machine-2", map[string]fileValue{
		"daemon.crt":   {daemonTwo.certificatePEM, 0o644},
		"daemon.key":   {daemonTwo.privateKeyPEM, 0o600},
		"relay-ca.crt": {relayServerCA.encoded, 0o644},
	})
	writeRole(*output, "controller", map[string]fileValue{
		"controller-reader.crt": {controllerReader.certificatePEM, 0o644},
		"controller-reader.key": {controllerReader.privateKeyPEM, 0o600},
		"relay-reader-ca.crt":   {readerServerCA.encoded, 0o644},
	})

	registry := enrollmentRegistry{Schema: 2, InfrastructureID: *infrastructureID, Machines: []enrollmentEntry{
		entry("lab-machine-1", daemonOne), entry("lab-machine-2", daemonTwo),
	}}
	manifest := readerManifest{
		SchemaVersion: 1, ControllerID: *controllerID, InfrastructureID: *infrastructureID,
		URI: readerURI, CertificateSerial: serial(controllerReader),
		CertificateSHA256: fingerprint(controllerReader), Status: "active",
	}
	writeJSON(filepath.Join(*output, "relay", "enrollment.json"), registry)
	writeJSON(filepath.Join(*output, "relay", "relay-reader.json"), manifest)
	fmt.Println("runtime_pki=generated authorities=4 ca_private_keys=persisted:0")
}

type fileValue struct {
	content []byte
	mode    os.FileMode
}

func newAuthority(commonName string, serialNumber int64, now time.Time) authority {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(72 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		fatal(err)
	}
	return authority{certificate: certificate, privateKey: privateKey,
		encoded: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func newLeaf(ca authority, commonName string, serialNumber int64, now time.Time,
	usage []x509.ExtKeyUsage, dnsNames, uriNames []string) leaf {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	var uris []*url.URL
	for _, name := range uriNames {
		identity, parseErr := url.Parse(name)
		if parseErr != nil {
			fatal(parseErr)
		}
		uris = append(uris, identity)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
		DNSNames: dnsNames, URIs: uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, publicKey, ca.privateKey)
	if err != nil {
		fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fatal(err)
	}
	return leaf{certificate: certificate,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		privateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})}
}

func entry(machineID string, certificate leaf) enrollmentEntry {
	return enrollmentEntry{MachineID: machineID, CertificateSerial: serial(certificate),
		CertificateSHA256: fingerprint(certificate), Status: "active"}
}

func serial(certificate leaf) string { return certificate.certificate.SerialNumber.Text(16) }

func fingerprint(certificate leaf) string {
	digest := sha256.Sum256(certificate.certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func writeRole(root, role string, files map[string]fileValue) {
	for name, value := range files {
		writeNew(filepath.Join(root, role, name), value.content, value.mode)
	}
}

func writeJSON(path string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		fatal(err)
	}
	writeNew(path, append(encoded, '\n'), 0o644)
}

func writeNew(path string, content []byte, mode os.FileMode) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		fatal(err)
	}
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		fatal(err)
	}
	if closeErr != nil {
		fatal(closeErr)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "generate-runtime-pki:", err)
	os.Exit(1)
}
