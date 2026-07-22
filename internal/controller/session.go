package controller

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/protocol"
)

const (
	sessionIdleLifetime     = 30 * time.Minute
	sessionAbsoluteLifetime = 8 * time.Hour
	sessionChallengeLimit   = 5
)

type SessionChallengeRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Purpose       string `json:"purpose"`
	TargetMethod  string `json:"target_method"`
	TargetRoute   string `json:"target_route"`
	BodySHA256    string `json:"body_sha256"`
}

type SessionChallengeResponse struct {
	SchemaVersion int    `json:"schema_version"`
	ChallengeID   string `json:"challenge_id"`
	Challenge     string `json:"challenge"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
}

type SessionOpenRequest struct {
	SchemaVersion int    `json:"schema_version"`
	ChallengeID   string `json:"challenge_id"`
	Signature     string `json:"signature"`
}

type SessionOpenResponse struct {
	SchemaVersion     int    `json:"schema_version"`
	SessionToken      string `json:"session_token"`
	IdleExpiresAt     string `json:"idle_expires_at"`
	AbsoluteExpiresAt string `json:"absolute_expires_at"`
}

type SessionContext struct {
	DeviceID          string
	CertificateSHA256 string
	IdentityRevision  uint64
	tokenDigest       [32]byte
}

type sessionChallenge struct {
	request          SessionChallengeRequest
	digest           [32]byte
	id               string
	value            [32]byte
	created          time.Time
	expires          time.Time
	device           DeviceRecord
	fingerprint      string
	serial           string
	identityRevision uint64
}

type activeSession struct {
	tokenDigest       [32]byte
	deviceID          string
	certificateSHA256 string
	certificateSerial string
	humanPublicKey    string
	controllerID      string
	infrastructureID  string
	identityRevision  uint64
	created           time.Time
	lastUsed          time.Time
	absoluteExpires   time.Time
}

type loggedOutSession struct {
	tokenDigest       [32]byte
	deviceID          string
	certificateSHA256 string
	expires           time.Time
}

type signatureFailures struct {
	starts       []time.Time
	blockedUntil time.Time
}

type AuthenticationDelayError struct {
	Delay time.Duration
}

func (failure AuthenticationDelayError) Error() string { return "human authentication failed" }

type SessionManager struct {
	mu              sync.Mutex
	authority       *AuthorityStore
	now             func() time.Time
	challenges      map[string]*sessionChallenge
	challengeStarts map[string][]time.Time
	sessions        map[string]*activeSession
	loggedOut       []loggedOutSession
	failures        map[string]*signatureFailures
}

func NewSessionManager(authority *AuthorityStore) (*SessionManager, error) {
	if authority == nil {
		return nil, errors.New("Controller authority is required")
	}
	return &SessionManager{
		authority: authority, now: time.Now,
		challenges: make(map[string]*sessionChallenge), challengeStarts: make(map[string][]time.Time),
		sessions: make(map[string]*activeSession), failures: make(map[string]*signatureFailures),
	}, nil
}

func (manager *SessionManager) Challenge(certificate *x509.Certificate, request SessionChallengeRequest, existing *SessionContext) (SessionChallengeResponse, error) {
	now := manager.now()
	device, err := manager.authority.AuthorizeActive(certificate, now)
	if err != nil {
		return SessionChallengeResponse{}, err
	}
	if err := validateSessionChallengeRequest(request); err != nil {
		return SessionChallengeResponse{}, err
	}
	if request.Purpose != "open_session" && existing == nil {
		return SessionChallengeResponse{}, errors.New("sensitive purpose requires an active session")
	}
	state := manager.authority.Snapshot()
	digest := sha256.Sum256(mustJSON(request))
	fingerprint := certificateFingerprint(certificate)
	key := device.DeviceID + "\x00" + request.Purpose
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if request.Purpose != "open_session" && !manager.contextValidLocked(*existing, state, now) {
		return SessionChallengeResponse{}, errors.New("sensitive purpose requires the matching active session")
	}
	if current := manager.challenges[key]; current != nil && !now.After(current.expires) {
		if subtle.ConstantTimeCompare(current.digest[:], digest[:]) != 1 {
			return SessionChallengeResponse{}, errors.New("a different challenge is already active for this purpose")
		}
		if request.Purpose != "open_session" {
			manager.sessions[device.DeviceID].lastUsed = now
		}
		return renderSessionChallenge(current), nil
	}
	starts := retainAfter(manager.challengeStarts[device.DeviceID], now.Add(-time.Minute))
	if len(starts) >= sessionChallengeLimit {
		manager.challengeStarts[device.DeviceID] = starts
		return SessionChallengeResponse{}, errors.New("session challenge rate is exceeded")
	}
	starts = append(starts, now)
	manager.challengeStarts[device.DeviceID] = starts
	id, err := randomRawURL(16)
	if err != nil {
		return SessionChallengeResponse{}, err
	}
	challenge := &sessionChallenge{
		request: request, digest: digest, id: id, created: now, expires: now.Add(challengeLifetime),
		device: device, fingerprint: fingerprint, serial: strings.ToLower(certificate.SerialNumber.Text(16)),
		identityRevision: state.IdentityRevision,
	}
	if _, err := rand.Read(challenge.value[:]); err != nil {
		return SessionChallengeResponse{}, err
	}
	manager.challenges[key] = challenge
	if request.Purpose != "open_session" {
		manager.sessions[device.DeviceID].lastUsed = now
	}
	return renderSessionChallenge(challenge), nil
}

func (manager *SessionManager) Open(certificate *x509.Certificate, request SessionOpenRequest) (SessionOpenResponse, error) {
	now := manager.now()
	device, err := manager.authority.AuthorizeActive(certificate, now)
	if err != nil {
		return SessionOpenResponse{}, err
	}
	if request.SchemaVersion != 1 || !canonicalRawURLBytes(request.ChallengeID, 16) {
		return SessionOpenResponse{}, errors.New("session proof request is invalid")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if delay := manager.blockDelayLocked(device.DeviceID, now); delay > 0 {
		return SessionOpenResponse{}, AuthenticationDelayError{Delay: delay}
	}
	signature, err := decodeFixed(request.Signature, ed25519.SignatureSize)
	if err != nil {
		return SessionOpenResponse{}, manager.invalidSignatureLocked(device.DeviceID, now)
	}
	var key string
	var challenge *sessionChallenge
	for candidateKey, candidate := range manager.challenges {
		if candidate.device.DeviceID == device.DeviceID && candidate.id == request.ChallengeID {
			key, challenge = candidateKey, candidate
			break
		}
	}
	if challenge == nil || now.After(challenge.expires) || challenge.request.Purpose != "open_session" ||
		challenge.fingerprint != certificateFingerprint(certificate) || challenge.serial != strings.ToLower(certificate.SerialNumber.Text(16)) {
		return SessionOpenResponse{}, errors.New("session challenge is invalid or expired")
	}
	delete(manager.challenges, key)
	transcript := sessionTranscript(manager.authority.Snapshot(), challenge)
	public, _ := base64.RawURLEncoding.DecodeString(device.HumanPublicKey)
	if !ed25519.Verify(ed25519.PublicKey(public), transcript, signature) {
		return SessionOpenResponse{}, manager.invalidSignatureLocked(device.DeviceID, now)
	}
	delete(manager.failures, device.DeviceID)
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return SessionOpenResponse{}, err
	}
	tokenText := base64.RawURLEncoding.EncodeToString(token)
	tokenDigest := sha256.Sum256(token)
	for index := range token {
		token[index] = 0
	}
	state := manager.authority.Snapshot()
	manager.sessions[device.DeviceID] = &activeSession{
		tokenDigest: tokenDigest, deviceID: device.DeviceID,
		certificateSHA256: device.CertificateSHA256, certificateSerial: device.CertificateSerial,
		humanPublicKey: device.HumanPublicKey, controllerID: state.ControllerID, infrastructureID: state.InfrastructureID,
		identityRevision: state.IdentityRevision, created: now, lastUsed: now, absoluteExpires: now.Add(sessionAbsoluteLifetime),
	}
	return SessionOpenResponse{
		SchemaVersion: 1, SessionToken: tokenText,
		IdleExpiresAt:     now.Add(sessionIdleLifetime).UTC().Format(time.RFC3339Nano),
		AbsoluteExpiresAt: now.Add(sessionAbsoluteLifetime).UTC().Format(time.RFC3339Nano),
	}, nil
}

func (manager *SessionManager) Authenticate(certificate *x509.Certificate, authorization string) (SessionContext, error) {
	now := manager.now()
	device, err := manager.authority.AuthorizeActive(certificate, now)
	if err != nil {
		return SessionContext{}, err
	}
	if !strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 {
		return SessionContext{}, errors.New("session authorization is absent or malformed")
	}
	token, err := decodeFixed(strings.TrimPrefix(authorization, "Bearer "), 32)
	if err != nil {
		return SessionContext{}, errors.New("session authorization is invalid")
	}
	digest := sha256.Sum256(token)
	for index := range token {
		token[index] = 0
	}
	state := manager.authority.Snapshot()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	context := SessionContext{
		DeviceID: device.DeviceID, CertificateSHA256: device.CertificateSHA256,
		IdentityRevision: state.IdentityRevision, tokenDigest: digest,
	}
	if !manager.contextValidLocked(context, state, now) {
		delete(manager.sessions, device.DeviceID)
		return SessionContext{}, errors.New("session authorization is invalid or expired")
	}
	return context, nil
}

// VerifySensitive consumes one human challenge bound to an already
// authenticated session and to the digest of one sensitive operation.
func (manager *SessionManager) VerifySensitive(
	certificate *x509.Certificate,
	context SessionContext,
	purpose string,
	bodyDigest [32]byte,
	challengeID string,
	signatureText string,
) error {
	now := manager.now()
	device, err := manager.authority.AuthorizeActive(certificate, now)
	if err != nil || purpose != "rotate_device" && purpose != "rotate_recovery_key" ||
		!canonicalRawURLBytes(challengeID, 16) {
		return errors.New("sensitive human proof is invalid")
	}
	signature, decodeErr := decodeFixed(signatureText, ed25519.SignatureSize)
	state := manager.authority.Snapshot()
	key := device.DeviceID + "\x00" + purpose
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if delay := manager.blockDelayLocked(device.DeviceID, now); delay > 0 {
		return AuthenticationDelayError{Delay: delay}
	}
	challenge := manager.challenges[key]
	if challenge == nil || challenge.id != challengeID || now.After(challenge.expires) ||
		challenge.request.Purpose != purpose || challenge.fingerprint != certificateFingerprint(certificate) ||
		challenge.serial != strings.ToLower(certificate.SerialNumber.Text(16)) ||
		challenge.identityRevision != state.IdentityRevision ||
		!manager.contextValidLocked(context, state, now) {
		return errors.New("sensitive human challenge is invalid or expired")
	}
	expectedDigest, digestErr := decodeFixed(challenge.request.BodySHA256, sha256.Size)
	if digestErr != nil || subtle.ConstantTimeCompare(expectedDigest, bodyDigest[:]) != 1 {
		return errors.New("sensitive human challenge targets another operation")
	}
	delete(manager.challenges, key)
	public, publicErr := decodeFixed(device.HumanPublicKey, ed25519.PublicKeySize)
	if decodeErr != nil || publicErr != nil || !ed25519.Verify(ed25519.PublicKey(public), sessionTranscript(state, challenge), signature) {
		return manager.invalidSignatureLocked(device.DeviceID, now)
	}
	delete(manager.failures, device.DeviceID)
	return nil
}

func (manager *SessionManager) Touch(context SessionContext) error {
	return manager.Accept(context, nil)
}

// Accept serializes a successfully authenticated operation with logout and a
// replacement session. It extends inactivity only after the operation succeeds.
func (manager *SessionManager) Accept(context SessionContext, operation func() error) error {
	now := manager.now()
	state := manager.authority.Snapshot()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.contextValidLocked(context, state, now) {
		return errors.New("session cannot be extended")
	}
	if operation != nil {
		if err := operation(); err != nil {
			return err
		}
	}
	manager.sessions[context.DeviceID].lastUsed = now
	return nil
}

func (manager *SessionManager) contextValidLocked(context SessionContext, state AuthorityState, now time.Time) bool {
	session := manager.sessions[context.DeviceID]
	return session != nil && now.Sub(session.lastUsed) <= sessionIdleLifetime && !now.After(session.absoluteExpires) &&
		context.DeviceID == session.deviceID && context.CertificateSHA256 == session.certificateSHA256 &&
		context.IdentityRevision == session.identityRevision && context.IdentityRevision == state.IdentityRevision &&
		session.controllerID == state.ControllerID && session.infrastructureID == state.InfrastructureID &&
		state.Active != nil && state.Active.DeviceID == session.deviceID &&
		state.Active.CertificateSHA256 == session.certificateSHA256 && state.Active.CertificateSerial == session.certificateSerial &&
		state.Active.HumanPublicKey == session.humanPublicKey &&
		subtle.ConstantTimeCompare(session.tokenDigest[:], context.tokenDigest[:]) == 1
}

func (manager *SessionManager) Logout(certificate *x509.Certificate, authorization string) error {
	context, err := manager.Authenticate(certificate, authorization)
	if err != nil {
		return manager.replayLogout(certificate, authorization)
	}
	now := manager.now()
	manager.mu.Lock()
	session := manager.sessions[context.DeviceID]
	if session == nil || subtle.ConstantTimeCompare(session.tokenDigest[:], context.tokenDigest[:]) != 1 {
		manager.mu.Unlock()
		return manager.replayLogout(certificate, authorization)
	}
	delete(manager.sessions, context.DeviceID)
	manager.loggedOut = append(manager.loggedOut, loggedOutSession{
		tokenDigest: context.tokenDigest, deviceID: context.DeviceID,
		certificateSHA256: context.CertificateSHA256, expires: session.absoluteExpires,
	})
	manager.pruneLoggedOutLocked(now)
	manager.mu.Unlock()
	return nil
}

func (manager *SessionManager) InvalidateAll() {
	manager.mu.Lock()
	manager.challenges = make(map[string]*sessionChallenge)
	manager.sessions = make(map[string]*activeSession)
	manager.loggedOut = nil
	manager.failures = make(map[string]*signatureFailures)
	manager.mu.Unlock()
}

func (manager *SessionManager) replayLogout(certificate *x509.Certificate, authorization string) error {
	if certificate == nil || !strings.HasPrefix(authorization, "Bearer ") {
		return errors.New("session logout authentication failed")
	}
	token, err := decodeFixed(strings.TrimPrefix(authorization, "Bearer "), 32)
	if err != nil {
		return errors.New("session logout authentication failed")
	}
	digest := sha256.Sum256(token)
	for index := range token {
		token[index] = 0
	}
	now := manager.now()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.pruneLoggedOutLocked(now)
	fingerprint := certificateFingerprint(certificate)
	for _, tombstone := range manager.loggedOut {
		if tombstone.certificateSHA256 == fingerprint && subtle.ConstantTimeCompare(tombstone.tokenDigest[:], digest[:]) == 1 {
			return nil
		}
	}
	return errors.New("session logout authentication failed")
}

func (manager *SessionManager) invalidSignature(deviceID string, now time.Time) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.invalidSignatureLocked(deviceID, now)
}

func (manager *SessionManager) invalidSignatureLocked(deviceID string, now time.Time) error {
	state := manager.failures[deviceID]
	if state == nil {
		state = &signatureFailures{}
		manager.failures[deviceID] = state
	}
	state.starts = retainAfter(state.starts, now.Add(-10*time.Minute))
	state.starts = append(state.starts, now)
	index := len(state.starts) - 1
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	if index >= len(delays) {
		index = len(delays) - 1
	}
	if len(state.starts) >= 5 {
		state.blockedUntil = now.Add(5 * time.Minute)
	}
	return AuthenticationDelayError{Delay: delays[index]}
}

func (manager *SessionManager) blockDelayLocked(deviceID string, now time.Time) time.Duration {
	state := manager.failures[deviceID]
	if state == nil || !now.Before(state.blockedUntil) {
		return 0
	}
	return state.blockedUntil.Sub(now)
}

func (manager *SessionManager) pruneLoggedOutLocked(now time.Time) {
	kept := manager.loggedOut[:0]
	for _, tombstone := range manager.loggedOut {
		if now.Before(tombstone.expires) {
			kept = append(kept, tombstone)
		}
	}
	manager.loggedOut = kept
}

func validateSessionChallengeRequest(request SessionChallengeRequest) error {
	if request.SchemaVersion != 1 ||
		request.Purpose != "open_session" && request.Purpose != "rotate_device" && request.Purpose != "rotate_recovery_key" ||
		request.TargetMethod == "" || request.TargetRoute == "" || !canonicalRawURLBytes(request.BodySHA256, 32) {
		return errors.New("session challenge request is invalid")
	}
	expected := map[string][2]string{
		"open_session":        {httpMethodPost, "/v0/session"},
		"rotate_device":       {httpMethodPut, "/v0/device-rotations"},
		"rotate_recovery_key": {httpMethodPut, "/v0/recovery-key"},
	}[request.Purpose]
	if request.TargetMethod != expected[0] || request.TargetRoute != expected[1] {
		return errors.New("session challenge target does not match its purpose")
	}
	return nil
}

const (
	httpMethodPost = "POST"
	httpMethodPut  = "PUT"
)

func sessionTranscript(state AuthorityState, challenge *sessionChallenge) []byte {
	buffer := bytes.NewBuffer(nil)
	buffer.WriteString(protocol.HumanSessionDomain)
	appendTranscriptField(buffer, []byte(challenge.request.Purpose))
	appendTranscriptField(buffer, []byte(challenge.request.TargetMethod))
	appendTranscriptField(buffer, []byte(challenge.request.TargetRoute))
	bodyDigest, _ := base64.RawURLEncoding.DecodeString(challenge.request.BodySHA256)
	appendTranscriptField(buffer, bodyDigest)
	appendTranscriptField(buffer, []byte(state.ControllerID))
	appendTranscriptField(buffer, []byte(state.InfrastructureID))
	appendTranscriptField(buffer, []byte(challenge.device.DeviceID))
	appendTranscriptField(buffer, []byte(challenge.fingerprint))
	appendTranscriptField(buffer, []byte(challenge.device.HumanPublicKey))
	appendTranscriptField(buffer, []byte(challenge.id))
	appendTranscriptField(buffer, challenge.value[:])
	appendTranscriptField(buffer, []byte(challenge.created.UTC().Format(time.RFC3339Nano)))
	appendTranscriptField(buffer, []byte(challenge.expires.UTC().Format(time.RFC3339Nano)))
	_ = binary.Write(buffer, binary.BigEndian, challenge.identityRevision)
	return buffer.Bytes()
}

func renderSessionChallenge(challenge *sessionChallenge) SessionChallengeResponse {
	return SessionChallengeResponse{
		SchemaVersion: 1, ChallengeID: challenge.id,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge.value[:]),
		CreatedAt: challenge.created.UTC().Format(time.RFC3339Nano), ExpiresAt: challenge.expires.UTC().Format(time.RFC3339Nano),
	}
}

func retainAfter(values []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(values) && values[first].Before(cutoff) {
		first++
	}
	return append(values[:0], values[first:]...)
}

func certificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	digest := sha256.Sum256(certificate.Raw)
	return fmt.Sprintf("%x", digest[:])
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
