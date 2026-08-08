package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

func externalDeclarationBody(machineID, label, kind string, port int) string {
	encodedLabel, err := json.Marshal(label)
	if err != nil {
		panic(err)
	}
	return `{"schema_version":1,"machine_id":"` + machineID + `","label":` + string(encodedLabel) +
		`,"kind":"` + kind + `","probe_port":` + strconv.Itoa(port) + `}`
}

func externalWithdrawalBody(elementID string) string {
	return `{"schema_version":1,"element_id":"` + elementID + `"}`
}

func declareExternalElement(t *testing.T, fixture controllerHTTPFixture, body string) ExternalDeclarationView {
	t.Helper()
	response := fixture.request(http.MethodPost, "/v0/external-elements", body,
		"application/json", "Bearer "+fixture.token, fixture.certificate)
	if response.Code != http.StatusCreated {
		t.Fatalf("declaration status=%d body=%s", response.Code, response.Body.String())
	}
	var view ExternalDeclarationView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// TestControllerExternalElementsDeclareListAndWithdraw is the nominal proof of
// the three routes: a thing nobody installed enters the inventory, is read back
// as the human wrote it, and leaves it again — and at no point does a plan, a
// digest or an envelope appear anywhere in what the Console receives.
func TestControllerExternalElementsDeclareListAndWithdraw(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	declared := declareExternalElement(t, fixture,
		externalDeclarationBody("lab-machine-1", "NAS du salon", ExternalKindService, 5000))
	if declared.SchemaVersion != 1 || declared.ExternalRevision != 1 ||
		!canonicalRawURLBytes(declared.Element.ElementID, 16) ||
		declared.Element.State != ExternalStateDeclared || declared.Element.ObservationStatus != "absent" ||
		declared.Element.ObservedAt != nil || declared.Element.Reason != nil {
		t.Fatalf("the declaration was not projected as declared and unread: %+v", declared)
	}

	response := fixture.request(http.MethodGet, "/v0/external-elements", "", "application/json", bearer, fixture.certificate)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("listing status=%d body=%s", response.Code, response.Body.String())
	}
	var listed ExternalElementsView
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Elements) != 1 || listed.ExternalRevision != 1 ||
		listed.InfrastructureID != fixture.inventory.Snapshot().InfrastructureID ||
		listed.Elements[0].ElementID != declared.Element.ElementID ||
		listed.Elements[0].Label != declared.Element.Label ||
		listed.Elements[0].Kind != declared.Element.Kind ||
		listed.Elements[0].ProbePort != declared.Element.ProbePort ||
		listed.Elements[0].DeclaredAt != declared.Element.DeclaredAt ||
		listed.Elements[0].State != declared.Element.State ||
		listed.Elements[0].ObservationStatus != declared.Element.ObservationStatus {
		t.Fatalf("the listing is not the declaration that was made: %+v", listed)
	}
	// No plan surface travels on this route, in either direction.
	for _, forbidden := range []string{"plan_document", "plan_sha256", "rollback_document", "rollback_sha256", "operation"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("the external listing carried %q: %s", forbidden, response.Body.String())
		}
	}

	// A reading recorded through the seam of the next palier becomes visible with
	// its date, and the state the adapter concluded is the state that is shown.
	if _, err := fixture.external.RecordObservation(declared.Element.ElementID, ExternalObservation{
		State: ExternalStateUnverifiable, Reason: ExternalReasonNothingListening,
		ObservedAt: fixture.current.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(http.MethodGet, "/v0/external-elements", "", "application/json", bearer, fixture.certificate)
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Elements[0].State != ExternalStateUnverifiable ||
		listed.Elements[0].Reason == nil || *listed.Elements[0].Reason != ExternalReasonNothingListening ||
		listed.Elements[0].ObservationStatus != "recent" {
		t.Fatalf("the recorded reading was not projected: %+v", listed.Elements[0])
	}

	withdrawal := fixture.request(http.MethodPost, "/v0/external-element-withdrawals",
		externalWithdrawalBody(declared.Element.ElementID), "application/json", bearer, fixture.certificate)
	if withdrawal.Code != http.StatusOK {
		t.Fatalf("withdrawal status=%d body=%s", withdrawal.Code, withdrawal.Body.String())
	}
	var withdrawn ExternalWithdrawalView
	if err := json.Unmarshal(withdrawal.Body.Bytes(), &withdrawn); err != nil {
		t.Fatal(err)
	}
	if withdrawn.ElementID != declared.Element.ElementID || withdrawn.ExternalRevision != 3 {
		t.Fatalf("the withdrawal does not name what it removed: %+v", withdrawn)
	}
	if len(fixture.external.Snapshot().Elements) != 0 {
		t.Fatal("the declaration survived its withdrawal")
	}
	// A withdrawal is not a deletion the product can repeat as a success: the
	// second one finds nothing, and says so.
	repeat := fixture.request(http.MethodPost, "/v0/external-element-withdrawals",
		externalWithdrawalBody(declared.Element.ElementID), "application/json", bearer, fixture.certificate)
	if repeat.Code != http.StatusNotFound || !strings.Contains(repeat.Body.String(), `"error_code":"resource_not_found"`) {
		t.Fatalf("repeated withdrawal status=%d body=%s", repeat.Code, repeat.Body.String())
	}
	// The managed inventory was never touched by any of it.
	if fixture.inventory.Snapshot().InventoryRevision != 1 || len(fixture.inventory.Snapshot().Machines) != 1 {
		t.Fatalf("the declared inventory disturbed the managed one: %+v", fixture.inventory.Snapshot())
	}
}

// TestControllerExternalElementsRequireTheSameAuthorityAsEveryOtherRoute holds
// the three routes to the authority the business surface already has: no new
// path, no new exemption, and no method the closed surface does not name.
func TestControllerExternalElementsRequireTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	declaration := externalDeclarationBody("lab-machine-1", "NAS du salon", ExternalKindService, 5000)
	withdrawal := externalWithdrawalBody("AAAAAAAAAAAAAAAAAAAAAA")

	for route, body := range map[string]string{
		"/v0/external-elements":            declaration,
		"/v0/external-element-withdrawals": withdrawal,
	} {
		if response := fixture.request(http.MethodPost, route, body, "application/json", bearer, nil); response.Code != http.StatusForbidden {
			t.Fatalf("%s: missing device certificate status=%d body=%s", route, response.Code, response.Body.String())
		}
		if response := fixture.request(http.MethodPost, route, body, "application/json", "", fixture.certificate); response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: missing human session status=%d body=%s", route, response.Code, response.Body.String())
		}
		if response := fixture.request(http.MethodPost, route, body, "application/json", "Bearer wrong", fixture.certificate); response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: foreign session token status=%d body=%s", route, response.Code, response.Body.String())
		}
		if response := fixture.request(http.MethodPost, route, body, "*/*", bearer, fixture.certificate); response.Code != http.StatusNotAcceptable {
			t.Fatalf("%s: unacceptable media status=%d body=%s", route, response.Code, response.Body.String())
		}
		if response := fixture.request(http.MethodPut, route, body, "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: replacement method status=%d body=%s", route, response.Code, response.Body.String())
		}
	}
	if response := fixture.request(http.MethodGet, "/v0/external-element-withdrawals", "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("reading the withdrawal route status=%d body=%s", response.Code, response.Body.String())
	}
	if len(fixture.external.Snapshot().Elements) != 0 {
		t.Fatal("a refused request reached the declared inventory")
	}
}

// TestControllerExternalElementsExposeNoBusinessDelete is the proof of the
// decision this palier had to take: the contract exposes no business DELETE, and
// an element the product does not own is the last thing to invent one for. A
// declaration retreats through its own route, and the element path a DELETE
// would need does not exist at all.
func TestControllerExternalElementsExposeNoBusinessDelete(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	declared := declareExternalElement(t, fixture,
		externalDeclarationBody("lab-machine-1", "NAS du salon", ExternalKindService, 5000))

	if response := fixture.request(http.MethodDelete, "/v0/external-elements", "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE on the collection status=%d body=%s", response.Code, response.Body.String())
	}
	for _, path := range []string{
		"/v0/external-elements/" + declared.Element.ElementID,
		"/v0/external-elements/" + declared.Element.ElementID + "/withdrawal",
	} {
		for _, method := range []string{http.MethodDelete, http.MethodGet, http.MethodPost} {
			response := fixture.request(method, path, "", "application/json", bearer, fixture.certificate)
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"error_code":"route_not_found"`) {
				t.Fatalf("%s %s status=%d body=%s", method, path, response.Code, response.Body.String())
			}
		}
	}
	if len(fixture.external.Snapshot().Elements) != 1 {
		t.Fatal("a route that does not exist removed a declaration")
	}
}

// TestControllerExternalElementsRefuseEveryRequestOutsideTheContract is the
// hostile surface of the two writing routes. None of these may enter an
// inventory a human is expected to read as the truth about their own network.
func TestControllerExternalElementsRefuseEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	declared := declareExternalElement(t, fixture,
		externalDeclarationBody("lab-machine-1", "NAS du salon", ExternalKindService, 5000))

	for name, check := range map[string]struct {
		route  string
		body   string
		status int
		code   string
	}{
		"a declaration of schema 2": {"/v0/external-elements",
			`{"schema_version":2,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration choosing its identifier": {"/v0/external-elements",
			`{"schema_version":1,"element_id":"AAAAAAAAAAAAAAAAAAAAAA","machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration choosing its infrastructure": {"/v0/external-elements",
			`{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration naming an image": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001,"image_reference":"ghcr.io/attacker/nas"}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration naming a version": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001,"version":"1.2.3"}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration naming a digest": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001,"image_digest":"sha256:` + strings.Repeat("a", 64) + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration carrying an operation": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001,"operation":"deploy_web_service"}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration naming an address instead of a port": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_host":"192.168.1.4","probe_port":5001}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration announcing its own state": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001,"state":"verified"}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration announcing its own date": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001,"observed_at":"2026-08-07T10:00:00Z"}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration repeating a field": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","machine_id":"lab-machine-2","label":"NAS","kind":"external_service","probe_port":5001}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration missing its kind": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","probe_port":5001}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration of a kind outside the closed list": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS", "external_database", 5001),
			http.StatusBadRequest, "invalid_request"},
		"a declaration of a managed kind": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS", "web_service", 5001),
			http.StatusBadRequest, "invalid_request"},
		"a declaration on port zero": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS", ExternalKindService, 0),
			http.StatusBadRequest, "invalid_request"},
		"a declaration on a negative port": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS", ExternalKindService, -1),
			http.StatusBadRequest, "invalid_request"},
		"a declaration beyond the port range": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS", ExternalKindService, 65536),
			http.StatusBadRequest, "invalid_request"},
		"a declaration on a fractional port": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"NAS","kind":"external_service","probe_port":5001.5}`,
			http.StatusBadRequest, "invalid_request"},
		"a declaration on a malformed machine": {"/v0/external-elements",
			externalDeclarationBody("Lab-Machine-1", "NAS", ExternalKindService, 5001),
			http.StatusBadRequest, "invalid_request"},
		"a declaration on a machine this Controller does not know": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-2", "NAS", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "machine_not_active"},
		"a declaration without a label": {"/v0/external-elements",
			`{"schema_version":1,"machine_id":"lab-machine-1","label":"","kind":"external_service","probe_port":5001}`,
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label carries a control byte": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\x01", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label carries a newline": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\ndu salon", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label carries NUL": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\x00", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label carries a tab": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\tdu salon", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label carries DEL": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\x7f", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label carries an escape sequence": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\x1b[31m", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label leaves ASCII": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS du salon \u00e9", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label is a right-to-left override": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "NAS\u202egnp.exe", ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label is 65 characters": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", strings.Repeat("a", 65), ExternalKindService, 5001),
			http.StatusUnprocessableEntity, "label_invalid"},
		"a declaration whose label exceeds the request bound": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", strings.Repeat("a", 4096), ExternalKindService, 5001),
			http.StatusRequestEntityTooLarge, "request_too_large"},
		"a declaration repeating a machine and a port": {"/v0/external-elements",
			externalDeclarationBody("lab-machine-1", "Un autre nom", ExternalKindPassage, 5000),
			http.StatusConflict, "state_conflict"},

		"a withdrawal of schema 2": {"/v0/external-element-withdrawals",
			`{"schema_version":2,"element_id":"` + declared.Element.ElementID + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a withdrawal naming a machine instead": {"/v0/external-element-withdrawals",
			`{"schema_version":1,"machine_id":"lab-machine-1"}`,
			http.StatusBadRequest, "invalid_request"},
		"a withdrawal carrying an operation": {"/v0/external-element-withdrawals",
			`{"schema_version":1,"element_id":"` + declared.Element.ElementID + `","operation":"remove_web_service"}`,
			http.StatusBadRequest, "invalid_request"},
		"a withdrawal repeating a field": {"/v0/external-element-withdrawals",
			`{"schema_version":1,"element_id":"` + declared.Element.ElementID + `","element_id":"AAAAAAAAAAAAAAAAAAAAAA"}`,
			http.StatusBadRequest, "invalid_request"},
		"a withdrawal on a malformed identifier": {"/v0/external-element-withdrawals",
			`{"schema_version":1,"element_id":"../../etc/shadow"}`,
			http.StatusBadRequest, "invalid_request"},
		"a withdrawal on a short identifier": {"/v0/external-element-withdrawals",
			`{"schema_version":1,"element_id":"AAAA"}`,
			http.StatusBadRequest, "invalid_request"},
		"a withdrawal on an identifier nobody declared": {"/v0/external-element-withdrawals",
			`{"schema_version":1,"element_id":"AAAAAAAAAAAAAAAAAAAAAA"}`,
			http.StatusNotFound, "resource_not_found"},
	} {
		response := fixture.request(http.MethodPost, check.route, check.body, "application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	state := fixture.external.Snapshot()
	if state.ExternalRevision != 1 || len(state.Elements) != 1 || state.Elements[0].ElementID != declared.Element.ElementID {
		t.Fatalf("a refused request changed the declared inventory: %+v", state)
	}
}

// TestControllerExternalLabelStaysInertData is proof requirement five: a hostile
// label is the human's own words, so it is stored and returned exactly as
// written, escaped by the encoder and never interpreted, never trimmed and never
// repeated inside an error document.
func TestControllerExternalLabelStaysInertData(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	hostile := `<script>alert("x")</script> \ ' & {} `
	declared := declareExternalElement(t, fixture,
		externalDeclarationBody("lab-machine-1", hostile, ExternalKindService, 5000))
	if declared.Element.Label != hostile {
		t.Fatalf("the label was altered on its way in: %q", declared.Element.Label)
	}
	response := fixture.request(http.MethodGet, "/v0/external-elements", "", "application/json", bearer, fixture.certificate)
	var listed ExternalElementsView
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Elements[0].Label != hostile {
		t.Fatalf("the label was altered on its way out: %q", listed.Elements[0].Label)
	}
	// The bytes on the wire are escaped rather than raw, so nothing downstream
	// receives an unbalanced document.
	if strings.Contains(response.Body.String(), `"`+hostile+`"`) {
		t.Fatalf("the label travelled unescaped: %s", response.Body.String())
	}

	// A refused label never comes back inside the error document.
	refused := fixture.request(http.MethodPost, "/v0/external-elements",
		externalDeclarationBody("lab-machine-1", "NAS\x01", ExternalKindService, 5001),
		"application/json", bearer, fixture.certificate)
	var problem controllerProblem
	if err := json.Unmarshal(refused.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.SchemaVersion != 1 || problem.ErrorCode != "label_invalid" ||
		!canonicalRawURLBytes(problem.RequestID, 16) || strings.Contains(refused.Body.String(), "NAS") {
		t.Fatalf("the refusal left the closed problem schema: %s", refused.Body.String())
	}
}

// TestControllerExternalElementsProduceNoPlanInEitherDirection is the proof of
// the palier that adds no plan.
//
// In one direction, no plan route can name a declaration: `element_id` is not a
// field of any plan schema, so a request carrying it is refused by the strict
// decoding before its value is read. In the other, declaring an element changes
// nothing about the plans a machine can receive: the two inventories are
// separate, and the declared one holds no authority over the managed one.
func TestControllerExternalElementsProduceNoPlanInEitherDirection(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	declared := declareExternalElement(t, fixture,
		externalDeclarationBody("lab-machine-1", "NAS du salon", ExternalKindService, 8080))

	for _, route := range []string{
		"/v0/probe-plans", "/v0/service-plans", "/v0/entrypoint-plans", "/v0/route-plans",
		"/v0/link-plans", "/v0/listener-peer-plans", "/v0/initiator-peer-plans",
		"/v0/private-service-plans", "/v0/link-route-plans", "/v0/snapshot-plans", "/v0/restore-plans",
		"/v0/user-service-plans",
	} {
		body := `{"schema_version":2,"machine_id":"lab-machine-1","element_id":"` + declared.Element.ElementID + `"}`
		response := fixture.request(http.MethodPost, route, body, "application/json", bearer, fixture.certificate)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error_code":"invalid_request"`) {
			t.Fatalf("%s accepted an element_id: status=%d body=%s", route, response.Code, response.Body.String())
		}
	}

	// The declared port of the declared machine still builds the plan it always
	// built: this Controller holds no map of the ports a managed service occupies
	// on a machine, so it does not pretend to arbitrate between the two
	// inventories on a fact it does not have.
	response := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 8080), "application/json", bearer, fixture.certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("a declaration blocked an unrelated plan: status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), declared.Element.ElementID) {
		t.Fatalf("a plan named a declaration: %s", response.Body.String())
	}
}

// TestControllerExternalListingAbsorbsWhatTheMachinesRead is the transport of
// `#107` end to end, through the Console's own route.
//
// The machine reads its declared loopback port, the reading rides the
// observation chain, the Relay carries it and the Controller joins it onto the
// declaration by the one pair a declaration is unique on: the machine and the
// port. Nothing came down to the machine to make it look, and nothing but a
// reading came back up.
//
// The listing also shows the two dimensions staying apart. A verified reading
// inside the announced limit is `recent`; the same reading once the limit has
// passed still says `verified` and stops saying `recent`, which is exactly "the
// state is no longer presented as current" without a fourth state to say it.
func TestControllerExternalListingAbsorbsWhatTheMachinesRead(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	declared := declareExternalElement(t, fixture,
		externalDeclarationBody("lab-machine-1", "NAS du salon", ExternalKindService, 5000))

	base := *fixture.current
	at := func(offset time.Duration) string {
		return base.Add(offset).UTC().Format(time.RFC3339Nano)
	}
	*fixture.current = base.Add(time.Minute)
	fixture.relay.status = RelayAvailable
	fixture.relay.err = nil
	fixture.relay.snapshot = readingsSnapshot(at(55*time.Second), at(50*time.Second),
		observation.ExternalReading{ProbePort: 5000, Outcome: observation.ExternalAnswered})

	view := listExternalElements(t, fixture, bearer)
	if len(view.Elements) != 1 {
		t.Fatalf("the listing carried %d elements", len(view.Elements))
	}
	element := view.Elements[0]
	if element.ElementID != declared.Element.ElementID || element.State != ExternalStateVerified ||
		element.Reason != nil || element.ObservedAt == nil || *element.ObservedAt != at(50*time.Second) ||
		element.ObservationStatus != "recent" {
		t.Fatalf("a verified reading was projected as %+v", element)
	}
	if view.ExternalRevision != declared.ExternalRevision+1 {
		t.Fatalf("absorbing one reading moved the revision to %d", view.ExternalRevision)
	}

	// Reading the same listing again changes nothing at all: a Console that
	// refreshes must not make the inventory look like it moved.
	if again := listExternalElements(t, fixture, bearer); again.ExternalRevision != view.ExternalRevision {
		t.Fatalf("a second listing moved the revision to %d", again.ExternalRevision)
	}

	*fixture.current = base.Add(3 * time.Minute)
	aged := listExternalElements(t, fixture, bearer)
	if aged.Elements[0].State != ExternalStateVerified || aged.Elements[0].ObservationStatus != "old" {
		t.Fatalf("an aged constat was projected as %+v", aged.Elements[0])
	}

	// A Relay this Controller cannot read is its own failure and never a fact
	// about a machine: the last constat stays exactly where it was.
	fixture.relay.status = RelayUnavailable
	fixture.relay.snapshot = nil
	blind := listExternalElements(t, fixture, bearer)
	if blind.Elements[0].State != ExternalStateVerified || blind.ExternalRevision != view.ExternalRevision {
		t.Fatalf("an unreadable Relay rewrote the declared inventory: %+v", blind)
	}
}

func listExternalElements(t *testing.T, fixture controllerHTTPFixture, bearer string) ExternalElementsView {
	t.Helper()
	response := fixture.request(http.MethodGet, "/v0/external-elements", "",
		"application/json", bearer, fixture.certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("listing status=%d body=%s", response.Code, response.Body.String())
	}
	var view ExternalElementsView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}
