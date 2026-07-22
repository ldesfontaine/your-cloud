package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMutualTLSAcceptsOnlyTheExpectedPeers(t *testing.T) {
	t.Parallel()
	relayCA := newTestAuthority(t, "relay authority")
	daemonCA := newTestAuthority(t, "daemon authority")
	relayIdentity := relayCA.issue(t, "relay", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"relay.observation.your-cloud.test"}, nil)
	daemonURI, err := url.Parse("urn:your-cloud:daemon:lab-machine-1")
	if err != nil {
		t.Fatal(err)
	}
	daemonIdentity := daemonCA.issue(t, "daemon", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, []*url.URL{daemonURI})

	serverTLS, err := NewRelayConfig(daemonCA.pem, relayIdentity, func(certificate *x509.Certificate) error {
		if len(certificate.URIs) != 1 || certificate.URIs[0].String() != daemonURI.String() {
			return io.ErrUnexpectedEOF
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect" {
			http.Redirect(response, request, "https://other.example/", http.StatusTemporaryRedirect)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	client, err := NewDaemonClient(relayCA.pem, daemonIdentity, "relay.observation.your-cloud.test")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("valid mutual TLS rejected: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}

	response, err = client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect was followed or rewritten: %d", response.StatusCode)
	}

	wrongName, err := NewDaemonClient(relayCA.pem, daemonIdentity, "wrong.your-cloud.test")
	if err != nil {
		t.Fatal(err)
	}
	if response, err := wrongName.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("wrong Relay identity accepted")
	}

	otherCA := newTestAuthority(t, "other daemon authority")
	unknownIdentity := otherCA.issue(t, "unknown", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, []*url.URL{daemonURI})
	unknownClient, err := NewDaemonClient(relayCA.pem, unknownIdentity, "relay.observation.your-cloud.test")
	if err != nil {
		t.Fatal(err)
	}
	if response, err := unknownClient.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("unknown client authority accepted")
	}
}

func TestTLSConfigurationRefusesMissingAuthoritiesAndAuthorization(t *testing.T) {
	t.Parallel()
	if _, err := NewDaemonClient(nil, tls.Certificate{}, "relay.observation.your-cloud.test"); err == nil {
		t.Fatal("empty Relay authority accepted")
	}
	if _, err := NewRelayConfig(nil, tls.Certificate{}, func(*x509.Certificate) error { return nil }); err == nil {
		t.Fatal("empty Daemon authority accepted")
	}
	authority := newTestAuthority(t, "daemon authority")
	if _, err := NewRelayConfig(authority.pem, tls.Certificate{}, nil); err == nil {
		t.Fatal("missing enrollment callback accepted")
	}
}

func TestControllerReaderClientPinsPrivateIPv4AndOrigin(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t, "Relay reader authority")
	identity := authority.issue(t, "Controller reader", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	host := "relay-reader.11111111-1111-4111-8111-111111111111.your-cloud.test"
	client, err := NewControllerReaderClient(authority.pem, identity, host, host+":8444", "192.0.2.10:8444")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.MaxConnsPerHost != 1 || transport.MaxResponseHeaderBytes != 8*1024 || transport.TLSClientConfig.ServerName != host {
		t.Fatal("Controller reader transport is not strictly bounded")
	}
	if _, err := NewControllerReaderClient(authority.pem, identity, host, host+":9443", "192.0.2.10:8444"); err == nil {
		t.Fatal("wrong reader origin port was accepted")
	}
	if _, err := NewControllerReaderClient(authority.pem, identity, host, host+":8444", "relay.example:8444"); err == nil {
		t.Fatal("non-IP private endpoint was accepted")
	}
}

func TestTLSConfigurationRefusesUnsafeAuthorityDocuments(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t, "expected authority")
	otherAuthority := newTestAuthority(t, "unexpected authority")
	leaf := authority.issue(t, "leaf", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"relay.observation.your-cloud.test"}, nil)
	expandedBundle := append(append([]byte{}, authority.pem...), otherAuthority.pem...)
	trailingData := append(append([]byte{}, authority.pem...), []byte("unexpected")...)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})

	for name, document := range map[string][]byte{
		"second certificate": expandedBundle,
		"trailing data":      trailingData,
		"non-CA certificate": leafPEM,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewDaemonClient(document, tls.Certificate{}, "relay.observation.your-cloud.test"); err == nil {
				t.Fatal("Daemon accepted an unsafe Relay authority document")
			}
			if _, err := NewRelayConfig(document, tls.Certificate{}, func(*x509.Certificate) error { return nil }); err == nil {
				t.Fatal("Relay accepted an unsafe Daemon authority document")
			}
		})
	}
}

type testAuthority struct {
	certificate *x509.Certificate
	private     ed25519.PrivateKey
	pem         []byte
}

func newTestAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{
		certificate: certificate,
		private:     private,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}),
	}
}

func (authority testAuthority) issue(t *testing.T, name string, usages []x509.ExtKeyUsage, dnsNames []string, uris []*url.URL) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		DNSNames:              dnsNames,
		URIs:                  uris,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, public, authority.private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{encoded},
		PrivateKey:  private,
	}
	leaf, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Leaf = leaf
	return certificate
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatal(err)
	}
	if serial.Sign() == 0 {
		return big.NewInt(1)
	}
	return serial
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
