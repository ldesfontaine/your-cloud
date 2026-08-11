package controller

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// haltedDispatcher is a test double, and it exists only in this file. It stands
// where #126's bounded OpenSSH launch will stand and concludes the way that
// launch concludes when the connection failed before the first byte of the
// wrapper: `not_launched`, with this Controller's own observation and no
// sentence from a machine that was never reached.
//
// It is a seam of the tests rather than an engine of the product: a build whose
// Controller held this would spend human approvals and reach nothing, which is
// exactly what AttachAuxiliaryDispatcher makes unreachable — no production file
// can name this type, and an unattached Controller serves no such route.
type haltedDispatcher struct{}

func (haltedDispatcher) Dispatch(DispatchRecord, []byte) (string, string, string) {
	return DispatchNotLaunched, "",
		"the connection failed before the first byte of the wrapper; the machine is unchanged"
}

// signedApprovalFor signs one envelope with the fixture's human key — the key
// the Console's native core signs with — and returns the exact bytes a
// submission carries.
func signedApprovalFor(t *testing.T, fixture controllerHTTPFixture, envelope approval.Envelope) []byte {
	t.Helper()
	envelope.ApprovalPublicKey = base64.RawURLEncoding.EncodeToString(fixture.identity.humanPublic)
	transcript, err := envelope.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(fixture.identity.humanPrivate, transcript)
	signed := approval.SignedApproval{
		Envelope:  envelope,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// frozenProbePair asks the route the Console would ask and returns the exact
// pair a human would then approve: documents and digests together.
func frozenProbePair(t *testing.T, fixture controllerHTTPFixture, machineID string) ProbePlanView {
	t.Helper()
	response := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody(machineID, plan.OperationDeployOCIProbe, 8080),
		"application/json", "Bearer "+fixture.token, fixture.certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("probe pair: status=%d body=%s", response.Code, response.Body.String())
	}
	var view ProbePlanView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// probeEnvelope names the frozen pair for one machine at one sequence, with
// the exact privileges the operation declares and a whole valid window.
func probeEnvelope(fixture controllerHTTPFixture, pair ProbePlanView, machineID string, sequence uint64) approval.Envelope {
	issued := uint64(fixture.current.Unix())
	return approval.Envelope{
		SchemaVersion:    approval.SchemaVersion,
		InfrastructureID: fixture.inventory.Snapshot().InfrastructureID,
		MachineID:        machineID,
		ApprovalEpoch:    1,
		Sequence:         sequence,
		Operation:        approval.OperationDeployOCIProbe,
		PlanSHA256:       pair.PlanSHA256,
		RollbackSHA256:   pair.RollbackSHA256,
		Privileges:       []string{approval.PrivilegeMutateLocalState, approval.PrivilegeReadLocalState},
		IssuedAtUnix:     issued,
		ExpiresAtUnix:    issued + approval.MaxLifetimeSeconds,
	}
}

func submissionBody(t *testing.T, signed []byte, pair ProbePlanView, definition string) string {
	t.Helper()
	body, err := json.Marshal(planApprovalRequest{
		SchemaVersion:      planApprovalSchema,
		SignedApproval:     json.RawMessage(signed),
		PlanDocument:       pair.PlanDocument,
		RollbackDocument:   pair.RollbackDocument,
		DefinitionDocument: definition,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func submit(fixture controllerHTTPFixture, body string) *httptest.ResponseRecorder {
	return fixture.request(http.MethodPost, "/v0/plan-approvals", body,
		"application/json", "Bearer "+fixture.token, fixture.certificate)
}

func refusalCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var problem struct {
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("refusal is not the closed problem envelope: %s", response.Body.String())
	}
	return problem.ErrorCode
}

// registryBytes reads the durable registry exactly as the next life would.
func registryBytes(t *testing.T, fixture controllerHTTPFixture) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.directory, dispatchRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestPlanApprovalSubmissionSpendsTheDispatchDurably is the nominal proof of
// this palier: a fully verified submission writes its record before any
// launch, the launch of this build is honestly `not_launched`, and the very
// same signed bytes are refused ever after — including by a Controller that
// restarted in between and reads the registry back from disk.
func TestPlanApprovalSubmissionSpendsTheDispatchDurably(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	pair := frozenProbePair(t, fixture, "lab-machine-1")
	signed := signedApprovalFor(t, fixture, probeEnvelope(fixture, pair, "lab-machine-1", 1))
	body := submissionBody(t, signed, pair, "")

	response := submit(fixture, body)
	if response.Code != http.StatusOK {
		t.Fatalf("nominal submission: status=%d body=%s", response.Code, response.Body.String())
	}
	var accepted PlanDispatchAcceptedView
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signed)
	if accepted.Dispatch.ApprovalSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("the record does not name the exact signed bytes: %+v", accepted.Dispatch)
	}
	if accepted.Dispatch.State != DispatchNotLaunched || accepted.Dispatch.MachineSentence != "" ||
		accepted.Dispatch.ControllerObservation == "" {
		t.Fatalf("this build holds no engine; the honest conclusion is not_launched with the Controller's own observation: %+v", accepted.Dispatch)
	}

	// The rule this test exists to pin, and the one an earlier reading of the
	// contract got backwards: a dispatch that reached nothing spends the
	// signed bytes all the same. "La séquence est dépensée, aucun effet n'a
	// eu lieu, et la reprise appartient à l'humain — jamais à une
	// réparation." What a human may do afterwards is approve the same
	// position again, which is a new envelope and new bytes — never these.
	//
	// The same bytes again, same life: refused by the durable state.
	replay := submit(fixture, body)
	if replay.Code != http.StatusConflict || refusalCode(t, replay) != refusalAlreadyDispatched {
		t.Fatalf("replay in the same life: status=%d code=%s", replay.Code, refusalCode(t, replay))
	}

	// The same bytes after a restart: the registry is reopened from disk, the
	// handler rebuilt, and the refusal still names the spent dispatch.
	reopened, err := OpenDispatchRegistryStore(fixture.directory,
		fixture.inventory.Snapshot().ControllerID, fixture.inventory.Snapshot().InfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.dispatches = reopened
	restarted := submit(fixture, body)
	if restarted.Code != http.StatusConflict || refusalCode(t, restarted) != refusalAlreadyDispatched {
		t.Fatalf("replay across a restart: status=%d code=%s", restarted.Code, refusalCode(t, restarted))
	}

	// The history reads back the one record, whole.
	history := fixture.request(http.MethodGet, "/v0/plan-dispatches", "",
		"application/json", "Bearer "+fixture.token, fixture.certificate)
	if history.Code != http.StatusOK {
		t.Fatalf("history: status=%d body=%s", history.Code, history.Body.String())
	}
	var view PlanDispatchesView
	if err := json.Unmarshal(history.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Dispatches) != 1 || view.Dispatches[0].ApprovalSHA256 != accepted.Dispatch.ApprovalSHA256 {
		t.Fatalf("the history does not carry the one dispatch: %+v", view)
	}
}

// TestPlanApprovalRefusalsAreNamedAndSpendNothing walks the closed list: every
// hostile submission receives its own name, and none of them leaves a byte in
// the registry — the durable file is identical before and after each refusal.
func TestPlanApprovalRefusalsAreNamedAndSpendNothing(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	pair := frozenProbePair(t, fixture, "lab-machine-1")

	otherHuman := func() ed25519.PrivateKey {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return private
	}()

	cases := []struct {
		name   string
		body   func() string
		status int
		code   string
	}{
		{"a document that is not the closed form", func() string {
			return `{"schema_version":1,"unknown":true}`
		}, http.StatusBadRequest, "invalid_request"},
		{"a signed approval that is not an approval", func() string {
			return submissionBody(t, []byte(`{"envelope":1}`), pair, "")
		}, http.StatusBadRequest, "invalid_request"},
		{"a machine this Controller does not manage", func() string {
			envelope := probeEnvelope(fixture, pair, "lab-machine-1", 1)
			envelope.MachineID = "lab-machine-9"
			return submissionBody(t, signedApprovalFor(t, fixture, envelope), pair, "")
		}, http.StatusUnprocessableEntity, "machine_not_active"},
		{"an approval signed by another key", func() string {
			envelope := probeEnvelope(fixture, pair, "lab-machine-1", 1)
			envelope.ApprovalPublicKey = base64.RawURLEncoding.EncodeToString(fixture.identity.humanPublic)
			transcript, err := envelope.SigningTranscript()
			if err != nil {
				t.Fatal(err)
			}
			signed, err := json.Marshal(approval.SignedApproval{
				Envelope:  envelope,
				Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherHuman, transcript)),
			})
			if err != nil {
				t.Fatal(err)
			}
			return submissionBody(t, signed, pair, "")
		}, http.StatusUnprocessableEntity, refusalApprovalSignature},
		{"an approval past its own window", func() string {
			envelope := probeEnvelope(fixture, pair, "lab-machine-1", 1)
			envelope.IssuedAtUnix -= 2 * approval.MaxLifetimeSeconds
			envelope.ExpiresAtUnix = envelope.IssuedAtUnix + approval.MaxLifetimeSeconds
			return submissionBody(t, signedApprovalFor(t, fixture, envelope), pair, "")
		}, http.StatusUnprocessableEntity, refusalApprovalExpired},
		{"a pair whose plan is not the one the envelope signs", func() string {
			envelope := probeEnvelope(fixture, pair, "lab-machine-1", 1)
			altered := pair
			altered.PlanDocument = strings.Replace(pair.PlanDocument, `"local_port":8080`, `"local_port":8081`, 1)
			return submissionBody(t, signedApprovalFor(t, fixture, envelope), altered, "")
		}, http.StatusUnprocessableEntity, refusalPairMismatch},
		{"a definition beside an operation that pins none", func() string {
			envelope := probeEnvelope(fixture, pair, "lab-machine-1", 1)
			return submissionBody(t, signedApprovalFor(t, fixture, envelope), pair, `{"schema_version":1}`)
		}, http.StatusUnprocessableEntity, refusalDefinitionMismatch},
		{"a sequence this Controller can attest as spent", func() string {
			// A synthetic reported record stands for a machine whose own
			// report already named sequence 5 as consumed.
			seeded := DispatchRecord{
				ApprovalSHA256: strings.Repeat("ab", 32), MachineID: "lab-machine-1",
				Operation: approval.OperationDeployOCIProbe, ApprovalEpoch: 1, Sequence: 5,
				PlanSHA256: pair.PlanSHA256, RollbackSHA256: pair.RollbackSHA256,
				State: DispatchInFlight, AcceptedAtUnix: 1,
			}
			if err := fixture.dispatches.Accept(seeded); err != nil {
				t.Fatal(err)
			}
			if err := fixture.dispatches.Conclude(seeded.ApprovalSHA256, DispatchReported, "", "", 2); err != nil {
				t.Fatal(err)
			}
			envelope := probeEnvelope(fixture, pair, "lab-machine-1", 5)
			return submissionBody(t, signedApprovalFor(t, fixture, envelope), pair, "")
		}, http.StatusUnprocessableEntity, refusalSequenceInvalid},
	}

	for _, hostile := range cases {
		body := hostile.body()
		snapshot := registryBytes(t, fixture)
		response := submit(fixture, body)
		if response.Code != hostile.status || refusalCode(t, response) != hostile.code {
			t.Fatalf("%s: status=%d code=%s body=%s",
				hostile.name, response.Code, refusalCode(t, response), response.Body.String())
		}
		after := registryBytes(t, fixture)
		if string(after) != string(snapshot) {
			t.Fatalf("%s: the refusal left a trace in the durable registry", hostile.name)
		}
	}
}

// TestPlanApprovalRoutesKeepTheirClosedMethods holds the two doors to their
// single verbs: the launcher accepts POST alone, the history GET alone.
func TestPlanApprovalRoutesKeepTheirClosedMethods(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	bearer := "Bearer " + fixture.token
	got := fixture.request(http.MethodGet, "/v0/plan-approvals", "", "application/json", bearer, fixture.certificate)
	if got.Code != http.StatusMethodNotAllowed || got.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET on the launcher: status=%d allow=%q", got.Code, got.Header().Get("Allow"))
	}
	posted := fixture.request(http.MethodPost, "/v0/plan-dispatches", "{}",
		"application/json", bearer, fixture.certificate)
	if posted.Code != http.StatusMethodNotAllowed || posted.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST on the history: status=%d allow=%q", posted.Code, posted.Header().Get("Allow"))
	}
}

// TestCommandRoutesDoNotExistWithoutAnEngine pins the structural guard: a
// Controller that holds no dispatch engine serves neither door, so it cannot
// durably spend a human approval and reach nothing. The engine is attached
// once and only once, and nil is refused rather than accepted as a degraded
// mode.
func TestCommandRoutesDoNotExistWithoutAnEngine(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	pair := frozenProbePair(t, fixture, "lab-machine-1")
	signed := signedApprovalFor(t, fixture, probeEnvelope(fixture, pair, "lab-machine-1", 1))
	body := submissionBody(t, signed, pair, "")

	// A second handler over the same stores, left without an engine: this is
	// the shape of every Controller until #126 wires the launch.
	pairing, err := NewPairingManager(fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := NewControllerHandler(fixture.authority, pairing, fixture.sessions, fixture.inventory,
		fixture.external, fixture.definitions, fixture.dispatches, fixture.relay, fixture.host)
	if err != nil {
		t.Fatal(err)
	}
	closed.now = fixture.handler.now

	before := registryBytes(t, fixture)
	for _, closedCase := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/v0/plan-approvals", body},
		{http.MethodGet, "/v0/plan-dispatches", ""},
		// The methods table reads the same field as the routing: an absent
		// route never answers 405, which would announce a door that does not
		// open.
		{http.MethodGet, "/v0/plan-approvals", ""},
	} {
		request := httptest.NewRequest(closedCase.method, "https://"+fixture.host+closedCase.path,
			strings.NewReader(closedCase.body))
		request.Host = fixture.host
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Authorization", "Bearer "+fixture.token)
		if closedCase.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{fixture.certificate}}
		recorder := httptest.NewRecorder()
		closed.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound || refusalCode(t, recorder) != "route_not_found" {
			t.Fatalf("%s %s on an engineless Controller: status=%d body=%s",
				closedCase.method, closedCase.path, recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get("Allow") != "" {
			t.Fatalf("%s %s announced %q on an engineless Controller",
				closedCase.method, closedCase.path, recorder.Header().Get("Allow"))
		}
	}
	if string(registryBytes(t, fixture)) != string(before) {
		t.Fatal("an engineless Controller wrote to the dispatch registry")
	}

	// One engine, once, and never nil.
	if closed.AttachAuxiliaryDispatcher(nil) == nil {
		t.Fatal("a nil dispatcher was accepted as an engine")
	}
	if err := closed.AttachAuxiliaryDispatcher(haltedDispatcher{}); err != nil {
		t.Fatal(err)
	}
	if closed.AttachAuxiliaryDispatcher(haltedDispatcher{}) == nil {
		t.Fatal("a second engine was attached to the same Controller")
	}
}

// TestOnlyTheSubmissionRouteReachesTheApprovalSurface is the door count made
// executable: across every production file of this package, the approval and
// auxiliary packages are importable from the submission route's file and from
// nowhere else. The freeze and external guards keep their own, stricter
// lists; this one holds the whole package.
func TestOnlyTheSubmissionRouteReachesTheApprovalSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range source.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			reaches := strings.HasSuffix(path, "/internal/approval") ||
				strings.HasSuffix(path, "/internal/auxiliary")
			if reaches && name != "plan_approvals_http.go" {
				t.Fatalf("%s imports %s: the submission route is the only door to the approval surface", name, path)
			}
		}
	}
}
