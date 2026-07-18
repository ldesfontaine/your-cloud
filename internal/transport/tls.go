// Package transport assembles the exact TLS 1.3 policies of v0.0.2.
package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// NewDaemonClient creates a client that trusts only the Relay authority and
// refuses every HTTP redirect away from the approved endpoint.
func NewDaemonClient(relayCAPEM []byte, identity tls.Certificate, serverName string) (*http.Client, error) {
	if serverName == "" {
		return nil, errors.New("relay server name is required")
	}
	roots, err := certificatePool(relayCAPEM)
	if err != nil {
		return nil, fmt.Errorf("relay authority: %w", err)
	}
	configuration := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{identity},
		ServerName:   serverName,
		NextProtos:   []string{"http/1.1"},
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     configuration,
			DisableCompression:  true,
			MaxIdleConns:        2,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// NewRelayConfig requires a valid Daemon chain, then applies the current local
// enrollment and revocation policy to the exact leaf certificate.
func NewRelayConfig(daemonCAPEM []byte, identity tls.Certificate, authorize func(*x509.Certificate) error) (*tls.Config, error) {
	if authorize == nil {
		return nil, errors.New("client authorization callback is required")
	}
	clients, err := certificatePool(daemonCAPEM)
	if err != nil {
		return nil, fmt.Errorf("daemon authority: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
		NextProtos:   []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) != 1 {
				return errors.New("client certificate chain is not exact")
			}
			if err := authorize(state.PeerCertificates[0]); err != nil {
				return fmt.Errorf("client certificate is not enrolled: %w", err)
			}
			return nil
		},
	}, nil
}

func certificatePool(encoded []byte) (*x509.CertPool, error) {
	trimmed := bytes.TrimSpace(encoded)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errors.New("PEM must contain exactly one CA certificate")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("PEM must contain exactly one CA certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("PEM contains an invalid CA certificate")
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("PEM certificate is not a certificate authority")
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool, nil
}
