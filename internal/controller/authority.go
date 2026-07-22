package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/protocol"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	authorityFileName = "identity.json"
	maxAuthorityBytes = int64(128 * 1024)
)

type DeviceRecord struct {
	DeviceID          string `json:"device_id"`
	CertificateSerial string `json:"certificate_serial"`
	CertificateSHA256 string `json:"certificate_sha256"`
	HumanPublicKey    string `json:"human_public_key"`
	RecoverySalt      string `json:"recovery_salt"`
	RecoveryEpoch     uint64 `json:"recovery_epoch"`
	RecoveryPublicKey string `json:"recovery_public_key"`
	Status            string `json:"status"`
}

type IdempotenceReceipt struct {
	OperationID       string `json:"operation_id"`
	RequestSHA256     string `json:"request_sha256"`
	Result            string `json:"result"`
	IdentityRevision  uint64 `json:"identity_revision"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CommittedAt       string `json:"committed_at"`
}

type AuthorityState struct {
	SchemaVersion       int                  `json:"schema_version"`
	ControllerID        string               `json:"controller_id"`
	InfrastructureID    string               `json:"infrastructure_id"`
	IdentityRevision    uint64               `json:"identity_revision"`
	ServerCACertificate string               `json:"server_ca_certificate"`
	ServerCAPrivateKey  string               `json:"server_ca_private_key"`
	ServerCertificate   string               `json:"server_certificate"`
	ServerPrivateKey    string               `json:"server_private_key"`
	DeviceCACertificate string               `json:"device_ca_certificate"`
	DeviceCAPrivateKey  string               `json:"device_ca_private_key"`
	Active              *DeviceRecord        `json:"active"`
	Revoked             []DeviceRecord       `json:"revoked"`
	Receipts            []IdempotenceReceipt `json:"receipts"`
}

type AuthorityStore struct {
	mu         sync.RWMutex
	directory  string
	path       string
	state      AuthorityState
	writeState func(AuthorityState) error
}

type CandidateCertificate struct {
	Record         DeviceRecord
	CertificatePEM string
	CertificateDER []byte
	ExpiresAt      string
}

func InitializeAuthority(directory string, now time.Time) (AuthorityState, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return AuthorityState{}, err
	}
	path := filepath.Join(directory, authorityFileName)
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return AuthorityState{}, errors.New("Controller identity authority already exists or cannot be inspected")
	}
	controllerID, err := identifier.NewUUIDv4()
	if err != nil {
		return AuthorityState{}, err
	}
	infrastructureID, err := identifier.NewUUIDv4()
	if err != nil {
		return AuthorityState{}, err
	}
	serverCA, serverCAKey, serverCertificate, serverKey, err := generateServerPKI(infrastructureID, now.UTC())
	if err != nil {
		return AuthorityState{}, err
	}
	deviceCA, deviceCAKey, err := generateAuthority("Your Cloud device authority", now.UTC())
	if err != nil {
		return AuthorityState{}, err
	}
	state := AuthorityState{
		SchemaVersion:       1,
		ControllerID:        controllerID,
		InfrastructureID:    infrastructureID,
		ServerCACertificate: string(serverCA),
		ServerCAPrivateKey:  string(serverCAKey),
		ServerCertificate:   string(serverCertificate),
		ServerPrivateKey:    string(serverKey),
		DeviceCACertificate: string(deviceCA),
		DeviceCAPrivateKey:  string(deviceCAKey),
		Revoked:             make([]DeviceRecord, 0),
		Receipts:            make([]IdempotenceReceipt, 0),
	}
	if err := validateAuthorityState(state, now.UTC()); err != nil {
		return AuthorityState{}, err
	}
	if err := persistAuthority(directory, path, state); err != nil {
		return AuthorityState{}, err
	}
	return cloneAuthorityState(state), nil
}

func OpenAuthorityStore(directory string, now time.Time) (*AuthorityStore, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, authorityFileName)
	data, err := readPrivateStateFile(path, maxAuthorityBytes)
	if err != nil {
		return nil, err
	}
	var state AuthorityState
	if err := strictjson.Decode(data, &state); err != nil {
		return nil, fmt.Errorf("decode Controller identity authority: %w", err)
	}
	if err := validateAuthorityState(state, now.UTC()); err != nil {
		return nil, err
	}
	store := &AuthorityStore{directory: directory, path: path, state: state}
	store.writeState = func(candidate AuthorityState) error {
		return persistAuthority(directory, path, candidate)
	}
	return store, nil
}

func (store *AuthorityStore) Snapshot() AuthorityState {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return cloneAuthorityState(store.state)
}

func (store *AuthorityStore) ServerIdentity() (tls.Certificate, error) {
	state := store.Snapshot()
	return tls.X509KeyPair([]byte(state.ServerCertificate), []byte(state.ServerPrivateKey))
}

func (store *AuthorityStore) ServerCAPEM() []byte {
	return []byte(store.Snapshot().ServerCACertificate)
}

func (store *AuthorityStore) DeviceTLSConfig() (*tls.Config, error) {
	identity, err := store.ServerIdentity()
	if err != nil {
		return nil, err
	}
	state := store.Snapshot()
	deviceCA, err := parseOneCertificate([]byte(state.DeviceCACertificate))
	if err != nil {
		return nil, err
	}
	clients := x509.NewCertPool()
	clients.AddCert(deviceCA)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
		NextProtos:   []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) != 1 || len(state.PeerCertificates) != 1 {
				return errors.New("device certificate chain is not exact")
			}
			return nil
		},
	}, nil
}

func (store *AuthorityStore) TemporaryTLSConfig() (*tls.Config, error) {
	identity, err := store.ServerIdentity()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ClientAuth:   tls.NoClientCert,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func (store *AuthorityStore) IssueDeviceCertificate(deviceID string, public *ecdsa.PublicKey, now time.Time) (CandidateCertificate, error) {
	if err := identifier.ValidateUUIDv4(deviceID); err != nil || public == nil || public.Curve != elliptic.P256() {
		return CandidateCertificate{}, errors.New("candidate device identity or P-256 key is invalid")
	}
	state := store.Snapshot()
	deviceCA, err := parseOneCertificate([]byte(state.DeviceCACertificate))
	if err != nil {
		return CandidateCertificate{}, err
	}
	deviceCAKey, err := parseEd25519PrivateKey([]byte(state.DeviceCAPrivateKey))
	if err != nil {
		return CandidateCertificate{}, err
	}
	identity, err := url.Parse(deviceURI(state.InfrastructureID, deviceID))
	if err != nil {
		return CandidateCertificate{}, err
	}
	serial, err := randomPositiveSerial()
	if err != nil {
		return CandidateCertificate{}, err
	}
	expires := now.UTC().Add(180 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: deviceID},
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              expires,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identity},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, deviceCA, public, deviceCAKey)
	if err != nil {
		return CandidateCertificate{}, err
	}
	issuedCertificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return CandidateCertificate{}, err
	}
	digest := sha256.Sum256(encoded)
	return CandidateCertificate{
		Record: DeviceRecord{
			DeviceID:          deviceID,
			CertificateSerial: strings.ToLower(serial.Text(16)),
			CertificateSHA256: hex.EncodeToString(digest[:]),
			Status:            "active",
		},
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})),
		CertificateDER: append([]byte(nil), encoded...),
		ExpiresAt:      issuedCertificate.NotAfter.UTC().Format(time.RFC3339Nano),
	}, nil
}

// RevokeActiveDevice is a local maintenance action. It durably removes every
// right from the current device while retaining its public revocation record.
func (store *AuthorityStore) RevokeActiveDevice(now time.Time) (DeviceRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.Active == nil {
		return DeviceRecord{}, errors.New("no active Controller device exists")
	}
	if len(store.state.Revoked) >= 64 || store.state.IdentityRevision == math.MaxUint64 {
		return DeviceRecord{}, errors.New("Controller revocation capacity is exhausted")
	}
	candidate := cloneAuthorityState(store.state)
	revoked := *candidate.Active
	revoked.Status = "revoked"
	candidate.Active = nil
	candidate.Revoked = append(candidate.Revoked, revoked)
	sortRevoked(candidate.Revoked)
	candidate.IdentityRevision++
	if err := validateAuthorityState(candidate, now.UTC()); err != nil {
		return DeviceRecord{}, err
	}
	if err := store.writeState(candidate); err != nil {
		return DeviceRecord{}, err
	}
	store.state = candidate
	return revoked, nil
}

func (store *AuthorityStore) AuthorizeActive(certificate *x509.Certificate, now time.Time) (DeviceRecord, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if certificate == nil || store.state.Active == nil {
		return DeviceRecord{}, errors.New("device identity is unknown")
	}
	if err := validatePresentedDevice(certificate, store.state.InfrastructureID, store.state.Active, now.UTC()); err != nil {
		return DeviceRecord{}, err
	}
	return *store.state.Active, nil
}

func (store *AuthorityStore) ServerCASPKISHA256() (string, error) {
	state := store.Snapshot()
	certificate, err := parseOneCertificate([]byte(state.ServerCACertificate))
	if err != nil {
		return "", err
	}
	encoded, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateAuthorityState(state AuthorityState, now time.Time) error {
	if state.SchemaVersion != 1 {
		return errors.New("unsupported Controller identity schema_version")
	}
	if err := identifier.ValidateUUIDv4(state.ControllerID); err != nil {
		return fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(state.InfrastructureID); err != nil {
		return fmt.Errorf("infrastructure_id: %w", err)
	}
	serverCA, err := validateAuthorityPair([]byte(state.ServerCACertificate), []byte(state.ServerCAPrivateKey))
	if err != nil {
		return fmt.Errorf("server authority: %w", err)
	}
	serverPair, err := tls.X509KeyPair([]byte(state.ServerCertificate), []byte(state.ServerPrivateKey))
	if err != nil || len(serverPair.Certificate) != 1 {
		return errors.New("server identity pair is invalid")
	}
	serverLeaf, err := x509.ParseCertificate(serverPair.Certificate[0])
	if err != nil || serverLeaf.IsCA || serverLeaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(serverLeaf.ExtKeyUsage) != 1 || serverLeaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		len(serverLeaf.DNSNames) != 1 || serverLeaf.DNSNames[0] != controllerServerName(state.InfrastructureID) ||
		len(serverLeaf.URIs) != 0 || len(serverLeaf.IPAddresses) != 0 || serverLeaf.CheckSignatureFrom(serverCA) != nil {
		return errors.New("server leaf identity is invalid")
	}
	if now.Before(serverLeaf.NotBefore) || now.After(serverLeaf.NotAfter) {
		return errors.New("server leaf is outside its validity period")
	}
	if _, err := validateAuthorityPair([]byte(state.DeviceCACertificate), []byte(state.DeviceCAPrivateKey)); err != nil {
		return fmt.Errorf("device authority: %w", err)
	}
	if state.Revoked == nil || len(state.Revoked) > 64 || state.Receipts == nil || len(state.Receipts) > 32 {
		return errors.New("Controller identity arrays are absent or outside their bounds")
	}
	if state.Active != nil {
		if err := validateDeviceRecord(*state.Active, "active"); err != nil {
			return err
		}
	}
	previous := ""
	for _, record := range state.Revoked {
		key := record.DeviceID + "\x00" + record.CertificateSHA256
		if err := validateDeviceRecord(record, "revoked"); err != nil || key <= previous {
			return errors.New("revoked device records are invalid, duplicated or unsorted")
		}
		previous = key
	}
	seenReceipts := make(map[string]struct{}, len(state.Receipts))
	for _, receipt := range state.Receipts {
		if !canonicalRawURLBytes(receipt.OperationID, 16) || !lowerHex(receipt.RequestSHA256, 64, 64) ||
			(receipt.Result != "enrollment_activated" && receipt.Result != "recovery_activated" &&
				receipt.Result != "rotation_activated" && receipt.Result != "recovery_key_rotated") ||
			receipt.IdentityRevision == 0 || !lowerHex(receipt.CertificateSHA256, 64, 64) {
			return errors.New("identity idempotence receipt is invalid")
		}
		committed, err := parseCanonicalUTC(receipt.CommittedAt)
		if err != nil || committed.After(now) {
			return errors.New("identity idempotence receipt timestamp is invalid")
		}
		if _, duplicate := seenReceipts[receipt.OperationID]; duplicate {
			return errors.New("identity idempotence receipts are duplicated")
		}
		seenReceipts[receipt.OperationID] = struct{}{}
	}
	return nil
}

func validateDeviceRecord(record DeviceRecord, expectedStatus string) error {
	if err := identifier.ValidateUUIDv4(record.DeviceID); err != nil || record.Status != expectedStatus ||
		!lowerHex(record.CertificateSerial, 1, 64) || !lowerHex(record.CertificateSHA256, 64, 64) ||
		!canonicalRawURLBytes(record.HumanPublicKey, ed25519.PublicKeySize) ||
		!canonicalRawURLBytes(record.RecoverySalt, 32) || record.RecoveryEpoch == 0 ||
		!canonicalRawURLBytes(record.RecoveryPublicKey, ed25519.PublicKeySize) {
		return errors.New("device authority record is invalid")
	}
	return nil
}

func generateServerPKI(infrastructureID string, now time.Time) ([]byte, []byte, []byte, []byte, error) {
	caCertificate, caKey, err := generateAuthority("Your Cloud server authority", now)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ca, err := parseOneCertificate(caCertificate)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	private, err := parseEd25519PrivateKey(caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	public, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serial, err := randomPositiveSerial()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: controllerServerName(infrastructureID)},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{controllerServerName(infrastructureID)},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, ca, public, private)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leafKey, err := marshalPrivateKey(leafPrivate)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return caCertificate, caKey,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), leafKey, nil
}

func generateAuthority(commonName string, now time.Time) ([]byte, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomPositiveSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, nil, err
	}
	privatePEM, err := marshalPrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), privatePEM, nil
}

func validateAuthorityPair(certificatePEM, privateKeyPEM []byte) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, errors.New("authority key pair is invalid")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || certificate.CheckSignatureFrom(certificate) != nil {
		return nil, errors.New("authority certificate role is invalid")
	}
	return certificate, nil
}

func parseOneCertificate(encoded []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(bytes.TrimSpace(encoded))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one certificate PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseEd25519PrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(bytes.TrimSpace(encoded))
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one PKCS#8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return private, nil
}

func marshalPrivateKey(private any) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

func randomPositiveSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

func persistAuthority(directory, path string, state AuthorityState) error {
	encoded, err := json.Marshal(state)
	if err != nil || int64(len(encoded)) > maxAuthorityBytes {
		return errors.New("Controller identity cannot be encoded within its bound")
	}
	temporary, err := os.CreateTemp(directory, ".identity-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func cloneAuthorityState(state AuthorityState) AuthorityState {
	result := state
	if state.Active != nil {
		active := *state.Active
		result.Active = &active
	}
	result.Revoked = append([]DeviceRecord(nil), state.Revoked...)
	if state.Revoked != nil && result.Revoked == nil {
		result.Revoked = make([]DeviceRecord, 0)
	}
	result.Receipts = append([]IdempotenceReceipt(nil), state.Receipts...)
	if state.Receipts != nil && result.Receipts == nil {
		result.Receipts = make([]IdempotenceReceipt, 0)
	}
	return result
}

func controllerServerName(infrastructureID string) string {
	return protocol.ControllerServerName(infrastructureID)
}

func deviceURI(infrastructureID, deviceID string) string {
	return protocol.DeviceURI(infrastructureID, deviceID)
}

func validatePresentedDevice(certificate *x509.Certificate, infrastructureID string, expected *DeviceRecord, now time.Time) error {
	if certificate == nil || expected == nil || certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(certificate.UnknownExtKeyUsage) != 0 ||
		now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) || len(certificate.URIs) != 1 ||
		certificate.URIs[0].String() != deviceURI(infrastructureID, expected.DeviceID) ||
		len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 {
		return errors.New("device certificate role, period or identity is invalid")
	}
	if strings.ToLower(certificate.SerialNumber.Text(16)) != expected.CertificateSerial {
		return errors.New("device certificate serial is unknown")
	}
	digest := sha256.Sum256(certificate.Raw)
	expectedDigest, err := hex.DecodeString(expected.CertificateSHA256)
	if err != nil || subtle.ConstantTimeCompare(digest[:], expectedDigest) != 1 {
		return errors.New("device certificate fingerprint is unknown")
	}
	return nil
}

func lowerHex(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			if value[index] < 'a' || value[index] > 'f' {
				return false
			}
		}
	}
	return true
}

func canonicalRawURLBytes(value string, expected int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == expected && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func sortRevoked(records []DeviceRecord) {
	sort.Slice(records, func(left, right int) bool {
		leftKey := records[left].DeviceID + "\x00" + records[left].CertificateSHA256
		rightKey := records[right].DeviceID + "\x00" + records[right].CertificateSHA256
		return leftKey < rightKey
	})
}
