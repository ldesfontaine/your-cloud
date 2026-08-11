package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRelayReader struct {
	mu         sync.Mutex
	snapshot   *RelaySnapshot
	status     RelayStatus
	err        error
	calls      int
	freshAfter time.Time
}

func (reader *fakeRelayReader) Read(_ context.Context, freshAfter time.Time) (*RelaySnapshot, RelayStatus, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.calls++
	reader.freshAfter = freshAfter
	if reader.snapshot == nil {
		return nil, reader.status, reader.err
	}
	copy := cloneRelaySnapshot(*reader.snapshot)
	return &copy, reader.status, reader.err
}

type controllerHTTPFixture struct {
	handler     *ControllerHandler
	authority   *AuthorityStore
	certificate *x509.Certificate
	identity    testConsoleIdentity
	sessions    *SessionManager
	inventory   *InventoryStore
	external    *ExternalStore
	definitions *ServiceDefinitionStore
	dispatches  *DispatchRegistryStore
	directory   string
	relay       *fakeRelayReader
	host        string
	token       string
	current     *time.Time
}

func newControllerHTTPFixture(t *testing.T) controllerHTTPFixture {
	t.Helper()
	authority, certificate, identity, initial := activeSessionFixture(t)
	state := authority.Snapshot()
	directory := privateTestDirectory(t)
	if err := CreateInventory(directory, state.ControllerID, state.InfrastructureID); err != nil {
		t.Fatal(err)
	}
	inventory, err := OpenInventoryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	external, err := OpenExternalStore(directory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := OpenServiceDefinitionStore(directory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	dispatches, err := OpenDispatchRegistryStore(directory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	sessions, _ := NewSessionManager(authority)
	current := initial
	sessions.now = func() time.Time { return current }
	tokenBytes := bytes.Repeat([]byte{0x42}, 32)
	tokenDigest := sha256.Sum256(tokenBytes)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	sessions.sessions[state.Active.DeviceID] = &activeSession{
		tokenDigest: tokenDigest, deviceID: state.Active.DeviceID,
		certificateSHA256: state.Active.CertificateSHA256, certificateSerial: state.Active.CertificateSerial,
		humanPublicKey: state.Active.HumanPublicKey, controllerID: state.ControllerID,
		infrastructureID: state.InfrastructureID, identityRevision: state.IdentityRevision,
		created: initial, lastUsed: initial, absoluteExpires: initial.Add(sessionAbsoluteLifetime),
	}
	pairing, _ := NewPairingManager(authority)
	relay := &fakeRelayReader{status: RelayUnavailable, err: errors.New("offline")}
	host := controllerServerName(state.InfrastructureID) + ":9443"
	handler, err := NewControllerHandler(authority, pairing, sessions, inventory, external, definitions, dispatches, relay, host)
	if err != nil {
		t.Fatal(err)
	}
	// The two routes of the command trajectory exist only beside an engine.
	// The tests attach the halted one, which is a test double and lives in a
	// test file for that reason: no production wiring can name it, and the
	// launch itself is #126's.
	if err := handler.AttachAuxiliaryDispatcher(haltedDispatcher{}); err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return current }
	return controllerHTTPFixture{
		handler: handler, authority: authority, certificate: certificate, identity: identity, sessions: sessions,
		inventory: inventory, external: external, definitions: definitions, dispatches: dispatches,
		directory: directory, relay: relay, host: host, token: token, current: &current,
	}
}

func (fixture controllerHTTPFixture) request(method, path, body, accept, authorization string, certificate *x509.Certificate) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://"+fixture.host+path, strings.NewReader(body))
	request.Host = fixture.host
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if certificate != nil {
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func TestControllerHTTPRequiresExactDeviceHumanOriginAndSurface(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	bearer := "Bearer " + fixture.token
	if response := fixture.request(http.MethodGet, "/v0/infrastructure", "", "application/json", bearer, nil); response.Code != http.StatusForbidden {
		t.Fatalf("missing device certificate status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodGet, "/v0/infrastructure", "", "application/json", "", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing human session status=%d body=%s", response.Code, response.Body.String())
	}
	wrongHost := httptest.NewRequest(http.MethodGet, "https://wrong.example/v0/infrastructure", nil)
	wrongHost.Host = "wrong.example"
	wrongHost.Header.Set("Accept", "application/json")
	wrongHost.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{fixture.certificate}}
	wrongHost.Header.Set("Authorization", bearer)
	wrongHostResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(wrongHostResponse, wrongHost)
	if wrongHostResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong origin was not refused: %d", wrongHostResponse.Code)
	}
	checks := []struct {
		method string
		path   string
		accept string
		status int
		code   string
	}{
		{http.MethodPost, "/v0/infrastructure", "application/json", 405, "method_not_allowed"},
		{http.MethodGet, "/v0/unknown", "application/json", 404, "route_not_found"},
		{http.MethodGet, "/v0/infrastructure?", "application/json", 400, "invalid_request"},
		{http.MethodGet, "/v0/infrastructure", "*/*", 406, "not_acceptable"},
	}
	for _, check := range checks {
		response := fixture.request(check.method, check.path, "", check.accept, bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s %s status=%d body=%s", check.method, check.path, response.Code, response.Body.String())
		}
	}
}

func TestControllerHTTPBoundsMutationsAndRequiresFreshRelayAuthority(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	state := fixture.authority.Snapshot()
	bearer := "Bearer " + fixture.token
	*fixture.current = fixture.current.Add(time.Minute)
	badLabel := `{"schema_version":1,"infrastructure_id":"` + state.InfrastructureID + `","label":"bad/slash"}`
	response := fixture.request(http.MethodPut, "/v0/infrastructure", badLabel, "application/json", bearer, fixture.certificate)
	if response.Code != http.StatusUnprocessableEntity || fixture.inventory.Snapshot().InventoryRevision != 0 {
		t.Fatalf("hostile label changed inventory: status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.sessions.mu.Lock()
	lastUsed := fixture.sessions.sessions[state.Active.DeviceID].lastUsed
	fixture.sessions.mu.Unlock()
	if !lastUsed.Equal(fixture.current.Add(-time.Minute)) {
		t.Fatal("refused request extended session inactivity")
	}

	duplicate := `{"schema_version":1,"schema_version":1,"infrastructure_id":"` + state.InfrastructureID + `","label":"Principale"}`
	if response := fixture.request(http.MethodPut, "/v0/infrastructure", duplicate, "application/json", bearer, fixture.certificate); response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate field status=%d body=%s", response.Code, response.Body.String())
	}
	oversized := `{"schema_version":1,"infrastructure_id":"` + state.InfrastructureID + `","label":"` + strings.Repeat("a", 4096) + `"}`
	if response := fixture.request(http.MethodPut, "/v0/infrastructure", oversized, "application/json", bearer, fixture.certificate); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d body=%s", response.Code, response.Body.String())
	}
	valid := `{"schema_version":1,"infrastructure_id":"` + state.InfrastructureID + `","label":"Principale"}`
	if response := fixture.request(http.MethodPut, "/v0/infrastructure", valid, "application/json", bearer, fixture.certificate); response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("valid initialization status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPut, "/v0/infrastructure", valid, "application/json", bearer, fixture.certificate); response.Code != http.StatusOK {
		t.Fatalf("initialization replay status=%d body=%s", response.Code, response.Body.String())
	}

	machineBody := `{"schema_version":1,"label":"Serveur principal"}`
	if response := fixture.request(http.MethodPut, "/v0/machines/lab-machine-1", machineBody, "application/json", bearer, fixture.certificate); response.Code != http.StatusServiceUnavailable || len(fixture.inventory.Snapshot().Machines) != 0 {
		t.Fatalf("Relay failure allowed attachment: status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.relay.mu.Lock()
	fixture.relay.status = RelayAvailable
	fixture.relay.err = nil
	fixture.relay.snapshot = &RelaySnapshot{
		SchemaVersion: 1, ControllerID: state.ControllerID, InfrastructureID: state.InfrastructureID,
		SnapshotAt: fixture.current.UTC().Format(time.RFC3339Nano),
		Machines:   []RelaySnapshotMachine{{MachineID: "lab-machine-1", EnrollmentStatus: "active"}},
	}
	fixture.relay.mu.Unlock()
	response = fixture.request(http.MethodPut, "/v0/machines/lab-machine-1", machineBody, "application/json", bearer, fixture.certificate)
	if response.Code != http.StatusCreated || len(fixture.inventory.Snapshot().Machines) != 1 {
		t.Fatalf("fresh active machine was not attached: status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.relay.mu.Lock()
	freshAfter := fixture.relay.freshAfter
	fixture.relay.mu.Unlock()
	if freshAfter.IsZero() {
		t.Fatal("machine attachment did not require a post-authentication Relay read")
	}
	if response := fixture.request(http.MethodGet, "/v0/machines", "", "application/json", bearer, fixture.certificate); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"machine_id":"lab-machine-1"`) {
		t.Fatalf("machine projection failed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestControllerHTTPErrorRandomnessAndDeviceConcurrencyAreBounded(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	deviceID := fixture.authority.Snapshot().Active.DeviceID
	for index := 0; index < maxDeviceRequests; index++ {
		if !fixture.handler.enterDevice(deviceID) {
			t.Fatalf("request %d inside concurrency bound was refused", index+1)
		}
	}
	if fixture.handler.enterDevice(deviceID) {
		t.Fatal("fifth concurrent device request was accepted")
	}
	for index := 0; index < maxDeviceRequests; index++ {
		fixture.handler.leaveDevice(deviceID)
	}
	fixture.handler.random = bytes.NewReader(nil)
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("request-id randomness failure did not abort: %#v", recovered)
		}
	}()
	_ = fixture.request(http.MethodGet, "/v0/infrastructure", "", "application/json", "", nil)
}

func TestControllerProblemDocumentStaysInClosedSchema(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	response := fixture.request(http.MethodGet, "/v0/infrastructure", "", "application/json", "", fixture.certificate)
	var problem controllerProblem
	if response.Code != http.StatusUnauthorized || json.Unmarshal(response.Body.Bytes(), &problem) != nil ||
		problem.SchemaVersion != 1 || problem.ErrorCode != "authentication_failed" || !canonicalRawURLBytes(problem.RequestID, 16) {
		t.Fatalf("invalid problem document: status=%d body=%s", response.Code, response.Body.String())
	}
}
