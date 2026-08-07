// Synthetic LAB client of the real Controller. It stands in for the one
// authority this proof does not exercise — the Console — and holds none of the
// others: the Controller, the Relay and the Daemon of this run are the product's
// own binaries, running for real on real machines.
//
// It exists because `#108` closed with a named debt: the Console has no
// declaration form. It reads the declared inventory and withdraws a declaration,
// and that is all. Declaring goes through `POST /v0/external-elements`, so a
// proof of this palier needs something that can speak that route — a device the
// Controller issued, a human key it enrolled, and a session it opened.
//
// Two halves, two different sources on purpose, exactly as
// tests/lab/v0.1.0/{oci-plan,public-profile,private-service}/_fixture do:
//
//   - the requests and the answers are the product's own wire format, spoken
//     against the product's own Controller over its own mTLS;
//   - the two transcripts a human signs — the identity transcript of the pairing
//     and the session transcript — are rebuilt by hand below, so the signature
//     this program produces is not verified by the same lines that produced it.
//
// What it deliberately is not: a Console. It derives no key from a passphrase,
// holds no native vault, renders nothing and decides nothing about what a human
// should be shown. The key material is synthetic, lives only as long as the run's
// state directory, and interoperability with the real Console is held by that
// suite and by the pinned cross-language vectors, never by this program.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The two domains a human proof is bound to. They are restated here rather than
// imported, because a transcript that is built by the same constant the verifier
// reads proves the constant and not the transcript.
const (
	identityTranscriptDomain = "your-cloud/identity-transcript.v1\x00"
	humanSessionDomain       = "your-cloud/human-session.v1\x00"
)

const maxAnswerBytes = 256 * 1024

// windowSheet is the one-time sheet root wrote beside the Controller when it
// opened its enrolment window. Everything this program needs to trust the
// Controller comes from it, and nothing comes from a first answer on the wire.
type windowSheet struct {
	SchemaVersion    int    `json:"schema_version"`
	Mode             string `json:"mode"`
	Origin           string `json:"origin"`
	TemporaryOrigin  string `json:"temporary_origin"`
	ControllerID     string `json:"controller_id"`
	InfrastructureID string `json:"infrastructure_id"`
	ServerCAPEM      string `json:"server_ca_pem"`
	ServerSPKISHA256 string `json:"server_spki_sha256"`
	WindowID         string `json:"window_id"`
	WindowCode       string `json:"window_code"`
	ExpiresAt        string `json:"expires_at"`
}

// clientState is what this program keeps between invocations. It is written into
// the run's own directory on lab-console, mode 0600, and removed with it.
type clientState struct {
	ControllerID     string `json:"controller_id"`
	InfrastructureID string `json:"infrastructure_id"`
	DeviceID         string `json:"device_id"`
	Endpoint         string `json:"endpoint"`
	ServerCAPEM      string `json:"server_ca_pem"`
	DeviceCertPEM    string `json:"device_certificate_pem"`
	DeviceKeyPEM     string `json:"device_key_pem"`
	HumanKey         string `json:"human_private_key"`
	IdentityRevision uint64 `json:"identity_revision"`
	SessionToken     string `json:"session_token"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lab-external-console:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: lab-external-console <state-dir> " +
		"pair <sheet> <endpoint:9443> <temporary-endpoint:9444> | session | " +
		"call <METHOD> <PATH> [body]")
}

func run(arguments []string) error {
	if len(arguments) < 2 {
		return usage()
	}
	directory, verb := arguments[0], arguments[1]
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("the state directory must be absolute and canonical")
	}
	switch verb {
	case "pair":
		if len(arguments) != 5 {
			return usage()
		}
		return pair(directory, arguments[2], arguments[3], arguments[4])
	case "session":
		if len(arguments) != 2 {
			return usage()
		}
		return session(directory)
	case "call":
		if len(arguments) != 4 && len(arguments) != 5 {
			return usage()
		}
		body := ""
		if len(arguments) == 5 {
			body = arguments[4]
		}
		return call(directory, arguments[2], arguments[3], body)
	default:
		return usage()
	}
}

// ---------------------------------------------------------------------------
// The pairing: one window, one challenge, one human proof, one activation.

func pair(directory, sheetPath, endpoint, temporaryEndpoint string) error {
	raw, err := os.ReadFile(sheetPath)
	if err != nil {
		return fmt.Errorf("read the window sheet: %w", err)
	}
	var sheet windowSheet
	if err := json.Unmarshal(raw, &sheet); err != nil {
		return fmt.Errorf("decode the window sheet: %w", err)
	}
	if sheet.Mode != "enrollment" || sheet.ServerCAPEM == "" {
		return errors.New("this proof pairs through an enrolment window and nothing else")
	}
	serverName := "controller." + sheet.InfrastructureID + ".your-cloud.test"
	if sheet.TemporaryOrigin != "https://"+serverName+":9444" {
		return errors.New("the sheet names a temporary origin this program does not recognise")
	}

	requestID, err := randomRawURL(16)
	if err != nil {
		return err
	}
	temporary, err := newClient(sheet.ServerCAPEM, serverName, temporaryEndpoint, nil)
	if err != nil {
		return err
	}
	challengeBody := mustJSON(map[string]any{
		"schema_version": 1,
		"window_id":      sheet.WindowID,
		"window_code":    sheet.WindowCode,
		"request_id":     requestID,
	})
	status, answer, err := speak(temporary, http.MethodPost,
		sheet.TemporaryOrigin+"/v0/enrollment/challenge", serverName+":9444", challengeBody, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the Controller refused the challenge: %d %s", status, answer)
	}
	var challenge struct {
		TransactionID     string `json:"transaction_id"`
		DeviceID          string `json:"device_id"`
		Challenge         string `json:"challenge"`
		CreatedAt         string `json:"created_at"`
		ExpiresAt         string `json:"expires_at"`
		NextRecoverySalt  string `json:"next_recovery_salt"`
		NextRecoveryEpoch uint64 `json:"next_recovery_epoch"`
	}
	if err := json.Unmarshal(answer, &challenge); err != nil {
		return fmt.Errorf("decode the challenge: %w", err)
	}

	// The device key never leaves this machine, and the Controller receives a
	// certification request rather than a key: the private half of a device
	// identity is not something a Controller may ever hold.
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	identity, err := url.Parse("urn:your-cloud:device:v1:" + sheet.InfrastructureID + ":" + challenge.DeviceID)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject:            pkix.Name{},
		URIs:               []*url.URL{identity},
	}, deviceKey)
	if err != nil {
		return err
	}

	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	recoveryPublic, recoveryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	challengeBytes, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return errors.New("the challenge is not canonical base64url")
	}
	saltBytes, err := base64.RawURLEncoding.DecodeString(challenge.NextRecoverySalt)
	if err != nil {
		return errors.New("the recovery salt is not canonical base64url")
	}
	csrDigest := sha256.Sum256(csrDER)

	// The transcript, rebuilt field by field from what the sheet said and what
	// the Controller answered. An enrolment names no current recovery epoch, no
	// current salt and no current key, and those three fields are present and
	// empty rather than absent: a transcript whose shape changed with its content
	// would let two different meanings hash to the same bytes.
	var transcript bytes.Buffer
	transcript.WriteString(identityTranscriptDomain)
	appendField(&transcript, []byte("enrollment"))
	appendField(&transcript, []byte(sheet.TemporaryOrigin))
	appendField(&transcript, []byte("PUT /v0/enrollment"))
	appendField(&transcript, []byte(sheet.WindowID))
	appendField(&transcript, []byte(requestID))
	appendField(&transcript, []byte(challenge.TransactionID))
	appendField(&transcript, []byte(sheet.ControllerID))
	appendField(&transcript, []byte(sheet.InfrastructureID))
	appendField(&transcript, []byte(challenge.DeviceID))
	appendField(&transcript, challengeBytes)
	appendField(&transcript, []byte(challenge.CreatedAt))
	appendField(&transcript, []byte(challenge.ExpiresAt))
	appendField(&transcript, nil)
	appendUint64(&transcript, 0)
	appendField(&transcript, saltBytes)
	appendUint64(&transcript, challenge.NextRecoveryEpoch)
	appendField(&transcript, csrDigest[:])
	appendField(&transcript, humanPublic)
	appendField(&transcript, nil)
	appendField(&transcript, recoveryPublic)

	completion := mustJSON(map[string]any{
		"schema_version":           1,
		"transaction_id":           challenge.TransactionID,
		"device_csr":               base64.RawURLEncoding.EncodeToString(csrDER),
		"human_public_key":         base64.RawURLEncoding.EncodeToString(humanPublic),
		"next_recovery_public_key": base64.RawURLEncoding.EncodeToString(recoveryPublic),
		"human_signature":          base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanPrivate, transcript.Bytes())),
		"next_recovery_signature":  base64.RawURLEncoding.EncodeToString(ed25519.Sign(recoveryPrivate, transcript.Bytes())),
	})
	status, answer, err = speak(temporary, http.MethodPut,
		sheet.TemporaryOrigin+"/v0/enrollment", serverName+":9444", completion, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the Controller refused the human proof: %d %s", status, answer)
	}
	var issued struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(answer, &issued); err != nil {
		return fmt.Errorf("decode the issued certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	if err != nil {
		return err
	}
	state := clientState{
		ControllerID:     sheet.ControllerID,
		InfrastructureID: sheet.InfrastructureID,
		DeviceID:         issued.DeviceID,
		Endpoint:         endpoint,
		ServerCAPEM:      sheet.ServerCAPEM,
		DeviceCertPEM:    issued.CertificatePEM,
		DeviceKeyPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		HumanKey:         base64.RawURLEncoding.EncodeToString(humanPrivate),
	}

	// The activation is the first request this device makes on the main surface,
	// and it is made with the certificate it was just issued: a candidate becomes
	// the active device by presenting itself, and never by being told to.
	main, err := clientFor(state)
	if err != nil {
		return err
	}
	status, answer, err = speak(main, http.MethodPut,
		"https://"+serverName+":9443/v0/enrollment/"+challenge.TransactionID+"/activation",
		serverName+":9443", []byte(`{"schema_version":1}`), "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the Controller refused the activation: %d %s", status, answer)
	}
	var activated struct {
		DeviceStatus     string `json:"device_status"`
		IdentityRevision uint64 `json:"identity_revision"`
	}
	if err := json.Unmarshal(answer, &activated); err != nil {
		return fmt.Errorf("decode the activation: %w", err)
	}
	state.IdentityRevision = activated.IdentityRevision
	if err := writeState(directory, state); err != nil {
		return err
	}
	fmt.Printf("device_id=%s\ndevice_status=%s\nidentity_revision=%d\ncontroller_id=%s\ninfrastructure_id=%s\n",
		state.DeviceID, activated.DeviceStatus, state.IdentityRevision, state.ControllerID, state.InfrastructureID)
	return nil
}

// ---------------------------------------------------------------------------
// The session: one challenge bound to one purpose, one human signature.

func session(directory string) error {
	state, err := readState(directory)
	if err != nil {
		return err
	}
	client, err := clientFor(state)
	if err != nil {
		return err
	}
	serverName := "controller." + state.InfrastructureID + ".your-cloud.test"
	origin := "https://" + serverName + ":9443"

	// The body digest of the target request. It is a real digest of the bytes
	// this program is about to be able to send, and it is bound into the
	// transcript so that a proof taken for one act cannot be spent on another.
	empty := sha256.Sum256(nil)
	bodyDigest := base64.RawURLEncoding.EncodeToString(empty[:])
	challengeRequest := mustJSON(map[string]any{
		"schema_version": 1,
		"purpose":        "open_session",
		"target_method":  "POST",
		"target_route":   "/v0/session",
		"body_sha256":    bodyDigest,
	})
	status, answer, err := speak(client, http.MethodPost,
		origin+"/v0/session/challenge", serverName+":9443", challengeRequest, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the Controller refused the session challenge: %d %s", status, answer)
	}
	var challenge struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		CreatedAt   string `json:"created_at"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(answer, &challenge); err != nil {
		return fmt.Errorf("decode the session challenge: %w", err)
	}
	challengeBytes, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return errors.New("the session challenge is not canonical base64url")
	}
	certificate, err := leafOf(state.DeviceCertPEM)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	humanPrivate, err := base64.RawURLEncoding.DecodeString(state.HumanKey)
	if err != nil || len(humanPrivate) != ed25519.PrivateKeySize {
		return errors.New("the human key of this run is unreadable")
	}
	humanPublic := ed25519.PrivateKey(humanPrivate).Public().(ed25519.PublicKey)

	var transcript bytes.Buffer
	transcript.WriteString(humanSessionDomain)
	appendField(&transcript, []byte("open_session"))
	appendField(&transcript, []byte("POST"))
	appendField(&transcript, []byte("/v0/session"))
	appendField(&transcript, empty[:])
	appendField(&transcript, []byte(state.ControllerID))
	appendField(&transcript, []byte(state.InfrastructureID))
	appendField(&transcript, []byte(state.DeviceID))
	appendField(&transcript, []byte(hex.EncodeToString(fingerprint[:])))
	appendField(&transcript, []byte(base64.RawURLEncoding.EncodeToString(humanPublic)))
	appendField(&transcript, []byte(challenge.ChallengeID))
	appendField(&transcript, challengeBytes)
	appendField(&transcript, []byte(challenge.CreatedAt))
	appendField(&transcript, []byte(challenge.ExpiresAt))
	appendUint64(&transcript, state.IdentityRevision)

	open := mustJSON(map[string]any{
		"schema_version": 1,
		"challenge_id":   challenge.ChallengeID,
		"signature": base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(ed25519.PrivateKey(humanPrivate), transcript.Bytes())),
	})
	status, answer, err = speak(client, http.MethodPost, origin+"/v0/session", serverName+":9443", open, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the Controller refused the human proof: %d %s", status, answer)
	}
	var opened struct {
		SessionToken      string `json:"session_token"`
		AbsoluteExpiresAt string `json:"absolute_expires_at"`
	}
	if err := json.Unmarshal(answer, &opened); err != nil {
		return fmt.Errorf("decode the session: %w", err)
	}
	state.SessionToken = opened.SessionToken
	if err := writeState(directory, state); err != nil {
		return err
	}
	fmt.Printf("session=open\nabsolute_expires_at=%s\n", opened.AbsoluteExpiresAt)
	return nil
}

// ---------------------------------------------------------------------------
// One authenticated request, printed exactly as the Controller answered it.
//
// The status is printed on its own line and the body follows whole, so that a
// harness reads a refusal as a fact and never has to infer one from an exit
// code. A refused call is not an error of this program: the refusals are half of
// what this palier has to prove.

func call(directory, method, path, body string) error {
	state, err := readState(directory)
	if err != nil {
		return err
	}
	if state.SessionToken == "" {
		return errors.New("this call needs a session; open one first")
	}
	client, err := clientFor(state)
	if err != nil {
		return err
	}
	serverName := "controller." + state.InfrastructureID + ".your-cloud.test"
	if !strings.HasPrefix(path, "/") {
		return errors.New("the path must be absolute")
	}
	var payload []byte
	if body != "" {
		payload = []byte(body)
	}
	status, answer, err := speak(client, method,
		"https://"+serverName+":9443"+path, serverName+":9443", payload, "Bearer "+state.SessionToken)
	if err != nil {
		return err
	}
	fmt.Printf("status=%d\n", status)
	if len(answer) != 0 {
		os.Stdout.Write(answer)
		if answer[len(answer)-1] != '\n' {
			fmt.Println()
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The transport. One pinned authority, one exact server name, one exact address.

func newClient(caPEM, serverName, endpoint string, identity *tls.Certificate) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("the pinned Controller authority does not decode")
	}
	configuration := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: serverName,
	}
	if identity != nil {
		configuration.Certificates = []tls.Certificate{*identity}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: configuration,
			// Every request of this program goes to the one address the harness
			// named. Nothing here resolves a name, and nothing follows a redirect.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, endpoint)
			},
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: 1,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("this client follows no redirect")
		},
	}, nil
}

func clientFor(state clientState) (*http.Client, error) {
	identity, err := tls.X509KeyPair([]byte(state.DeviceCertPEM), []byte(state.DeviceKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("the device identity of this run does not load: %w", err)
	}
	return newClient(state.ServerCAPEM, "controller."+state.InfrastructureID+".your-cloud.test",
		state.Endpoint, &identity)
}

func speak(client *http.Client, method, target, host string, body []byte, authorization string) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		return 0, nil, err
	}
	request.Host = host
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxAnswerBytes))
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, answer, nil
}

// ---------------------------------------------------------------------------

func appendField(buffer *bytes.Buffer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer.Write(length[:])
	buffer.Write(value)
}

func appendUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}

func randomRawURL(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func leafOf(certificatePEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the device certificate of this run does not decode")
	}
	return x509.ParseCertificate(block.Bytes)
}

func statePath(directory string) string { return filepath.Join(directory, "client.json") }

func writeState(directory string, state clientState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(directory), append(encoded, '\n'), 0o600)
}

func readState(directory string) (clientState, error) {
	raw, err := os.ReadFile(statePath(directory))
	if err != nil {
		return clientState{}, fmt.Errorf("this run holds no paired device: %w", err)
	}
	var state clientState
	if err := json.Unmarshal(raw, &state); err != nil {
		return clientState{}, err
	}
	return state, nil
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
