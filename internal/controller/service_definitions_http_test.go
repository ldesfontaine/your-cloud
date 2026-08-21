package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

// definitionPlaceholderSHA256 is a well-formed digest that names nothing. It is
// what a submission carries when the document itself is the thing under test:
// bytes that are not a definition are refused before any digest could match them,
// and no digest exists for a document the contract does not admit.
const definitionPlaceholderSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

func serviceDefinitionBody(document, digest string) string {
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return `{"schema_version":1,"definition_document":` + string(encoded) +
		`,"definition_sha256":"` + digest + `"}`
}

func definitionDigest(t *testing.T, document string) string {
	t.Helper()
	parsed, err := servicedefinition.Decode([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func freezeServiceDefinition(t *testing.T, fixture controllerHTTPFixture, document, digest string, expected int) ServiceDefinitionView {
	t.Helper()
	response := fixture.request(http.MethodPost, "/v0/service-definitions",
		serviceDefinitionBody(document, digest), "application/json", "Bearer "+fixture.token, fixture.certificate)
	if response.Code != expected {
		t.Fatalf("freeze status=%d body=%s", response.Code, response.Body.String())
	}
	var view ServiceDefinitionView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func listServiceDefinitions(t *testing.T, fixture controllerHTTPFixture) ServiceDefinitionsView {
	t.Helper()
	response := fixture.request(http.MethodGet, "/v0/service-definitions", "",
		"application/json", "Bearer "+fixture.token, fixture.certificate)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("listing status=%d body=%s", response.Code, response.Body.String())
	}
	var view ServiceDefinitionsView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// TestControllerServiceDefinitionsFreezeAndList is the nominal proof of the two
// routes: a definition a human wrote is frozen, comes back as the exact canonical
// bytes it was frozen as beside the digest they hash to, and a revision joins it
// without displacing it.
//
// No machine is attached to this fixture, and that is the point. A definition is
// an inventory of infrastructure: it names no machine, so this route never reads
// the managed inventory and never asks the Relay anything, and freezing works
// perfectly on a Controller that has never enrolled anything.
func TestControllerServiceDefinitionsFreezeAndList(t *testing.T) {
	fixture := newControllerHTTPFixture(t)

	frozen := freezeServiceDefinition(t, fixture,
		definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)
	if frozen.SchemaVersion != 1 || frozen.DefinitionRevision != 1 ||
		frozen.Definition.Slug != "lab-notes" ||
		frozen.Definition.DefinitionDocument != definitionVectorDocument ||
		frozen.Definition.DefinitionSHA256 != definitionVectorSHA256 {
		t.Fatalf("the freeze is not the definition that was submitted: %+v", frozen)
	}

	// The same bytes again are the same revision, answered as a reading of what is
	// already held rather than as a second freeze.
	repeated := freezeServiceDefinition(t, fixture,
		definitionVectorDocument, definitionVectorSHA256, http.StatusOK)
	if repeated.DefinitionRevision != 1 || repeated.Definition != frozen.Definition {
		t.Fatalf("the same bytes were frozen twice: %+v", repeated)
	}

	revised, revisedDigest := alterOneByte(t, definitionVectorDocument,
		`"container_port":8080`, `"container_port":8081`)
	second := freezeServiceDefinition(t, fixture, revised, revisedDigest, http.StatusCreated)
	if second.DefinitionRevision != 2 || second.Definition.DefinitionSHA256 == definitionVectorSHA256 {
		t.Fatalf("the revision did not coexist with the definition it came from: %+v", second)
	}

	listed := listServiceDefinitions(t, fixture)
	if listed.SchemaVersion != 1 || listed.DefinitionRevision != 2 || len(listed.Definitions) != 2 ||
		listed.InfrastructureID != fixture.inventory.Snapshot().InfrastructureID {
		t.Fatalf("the listing is not the inventory that was frozen: %+v", listed)
	}
	read := map[string]ServiceDefinitionEntry{}
	for _, entry := range listed.Definitions {
		read[entry.DefinitionSHA256] = entry
	}
	if read[definitionVectorSHA256] != frozen.Definition || read[revisedDigest] != second.Definition {
		t.Fatalf("a reading altered or omitted a frozen definition: %+v", listed.Definitions)
	}

	// No plan surface travels on this route, in either direction.
	response := fixture.request(http.MethodGet, "/v0/service-definitions", "",
		"application/json", "Bearer "+fixture.token, fixture.certificate)
	for _, forbidden := range []string{
		"plan_document", "plan_sha256", "rollback_document", "rollback_sha256", "operation",
		"machine_id", "image_digest", "local_port",
	} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("the listing carried %q: %s", forbidden, response.Body.String())
		}
	}

	// Freezing created nothing and contacted nobody: no machine entered the managed
	// inventory, and the Relay was never read.
	if inventory := fixture.inventory.Snapshot(); inventory.InventoryRevision != 0 || len(inventory.Machines) != 0 {
		t.Fatalf("freezing a definition touched the managed inventory: %+v", inventory)
	}
	fixture.relay.mu.Lock()
	calls := fixture.relay.calls
	fixture.relay.mu.Unlock()
	if calls != 0 {
		t.Fatalf("freezing a definition read the Relay %d times", calls)
	}

	// What it did create is one private file, written the one way every durable
	// document of this Controller reaches the disk.
	info, err := os.Stat(filepath.Join(fixture.directory, serviceDefinitionFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the frozen definitions are held at %v", info.Mode().Perm())
	}
}

// TestControllerServiceDefinitionsListNothingBeforeAnythingIsFrozen keeps the
// reading honest on an empty inventory: an installation that froze nothing says
// so with an empty list, never with a missing field an App would have to guess
// the meaning of.
func TestControllerServiceDefinitionsListNothingBeforeAnythingIsFrozen(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	response := fixture.request(http.MethodGet, "/v0/service-definitions", "",
		"application/json", "Bearer "+fixture.token, fixture.certificate)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"definitions":[]`) ||
		!strings.Contains(response.Body.String(), `"definition_revision":0`) {
		t.Fatalf("empty listing status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestControllerServiceDefinitionsRequireTheSameAuthorityAsEveryOtherRoute holds
// the two routes to the authority the business surface already has: no new path,
// no new exemption, and no method the closed surface does not name.
func TestControllerServiceDefinitionsRequireTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	bearer := "Bearer " + fixture.token
	body := serviceDefinitionBody(definitionVectorDocument, definitionVectorSHA256)

	if response := fixture.request(http.MethodPost, "/v0/service-definitions", body, "application/json", bearer, nil); response.Code != http.StatusForbidden {
		t.Fatalf("missing device certificate status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/service-definitions", body, "application/json", "", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing human session status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/service-definitions", body, "application/json", "Bearer wrong", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("foreign session token status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodGet, "/v0/service-definitions", "", "application/json", "", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("reading without a session status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/service-definitions", body, "*/*", bearer, fixture.certificate); response.Code != http.StatusNotAcceptable {
		t.Fatalf("unacceptable media status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/service-definitions", `{"schema_version":1}`, "application/json", bearer, fixture.certificate); response.Code != http.StatusBadRequest {
		t.Fatalf("a submission without a document status=%d body=%s", response.Code, response.Body.String())
	}

	// A revision is a new freeze that coexists with the previous ones, so no method
	// of replacement or removal exists — on the collection or on a definition.
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if response := fixture.request(method, "/v0/service-definitions", body, "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s on the collection status=%d body=%s", method, response.Code, response.Body.String())
		}
	}
	for _, path := range []string{
		"/v0/service-definitions/" + definitionVectorSHA256,
		"/v0/service-definitions/lab-notes",
		"/v0/service-definitions/" + definitionVectorSHA256 + "/withdrawal",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			response := fixture.request(method, path, "", "application/json", bearer, fixture.certificate)
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"error_code":"route_not_found"`) {
				t.Fatalf("%s %s status=%d body=%s", method, path, response.Code, response.Body.String())
			}
		}
	}
	if len(fixture.definitions.Snapshot().Definitions) != 0 {
		t.Fatal("a refused request froze a definition")
	}
}

// TestControllerServiceDefinitionsRefuseEveryRequestOutsideTheContract is the
// hostile surface of the freezing route, one refusal at a time.
//
// None of these may enter an inventory whose entries plans pin by digest. The
// codes are the ones the closed list already holds: a document or a digest
// outside the contract is `400 invalid_request`, and a body beyond the bound this
// route announces is `413 request_too_large`. There is no `422 machine_not_active`
// among them and there is nothing for one to mean — a definition names no
// machine.
func TestControllerServiceDefinitionsRefuseEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	bearer := "Bearer " + fixture.token
	frozen := freezeServiceDefinition(t, fixture,
		definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)

	altered, alteredDigest := alterOneByte(t, definitionVectorDocument,
		`"container_port":8080`, `"container_port":8081`)
	encodedDocument, err := json.Marshal(definitionVectorDocument)
	if err != nil {
		t.Fatal(err)
	}
	// A definition that validates field by field and does not fit the bound the
	// contract puts on the whole document: the value is printable ASCII and the key
	// is a key, and there are simply too many bytes of them.
	oversizedDefinition := strings.Replace(definitionMinimalDocument,
		`"environment":[]`, `"environment":["LAB_NOTES_TITLE=`+strings.Repeat("a", 500)+`"`+
			strings.Repeat(`,"LAB_NOTES_TITLE_`+strings.Repeat("A", 8)+`=`+strings.Repeat("a", 500)+`"`, 16)+`]`, 1)
	if len(oversizedDefinition) <= servicedefinition.MaxDefinitionBytes {
		t.Fatalf("the oversized definition is %d bytes", len(oversizedDefinition))
	}

	for name, check := range map[string]struct {
		body   string
		status int
		code   string
	}{
		"a submission of schema 2": {
			`{"schema_version":2,"definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission naming a machine": {
			`{"schema_version":1,"machine_id":"lab-machine-1","definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission carrying an operation": {
			`{"schema_version":1,"operation":"deploy_user_service","definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission naming its own freeze date": {
			`{"schema_version":1,"frozen_at":"2026-08-08T10:00:00Z","definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission naming its own revision": {
			`{"schema_version":1,"definition_revision":9,"definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission naming a slug beside its document": {
			`{"schema_version":1,"slug":"other","definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission repeating a field": {
			`{"schema_version":1,"definition_document":` + string(encodedDocument) +
				`,"definition_document":` + string(encodedDocument) +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission carrying the document as an object": {
			`{"schema_version":1,"definition_document":` + definitionVectorDocument +
				`,"definition_sha256":"` + definitionVectorSHA256 + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission without a digest": {
			`{"schema_version":1,"definition_document":` + string(encodedDocument) + `}`,
			http.StatusBadRequest, "invalid_request"},
		"a submission whose digest is upper case": {
			serviceDefinitionBody(definitionVectorDocument, strings.ToUpper(definitionVectorSHA256)),
			http.StatusBadRequest, "invalid_request"},
		"a submission whose digest is truncated": {
			serviceDefinitionBody(definitionVectorDocument, definitionVectorSHA256[:63]),
			http.StatusBadRequest, "invalid_request"},
		"a submission whose digest carries the algorithm": {
			serviceDefinitionBody(definitionVectorDocument, "sha256:"+definitionVectorSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a submission whose digest names another definition": {
			serviceDefinitionBody(definitionVectorDocument, definitionMinimalSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition altered by one byte under the digest it came from": {
			serviceDefinitionBody(altered, definitionVectorSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition of a reserved slug": {
			serviceDefinitionBody(strings.Replace(definitionMinimalDocument,
				`"slug":"minimal"`, `"slug":"vaultwarden"`, 1), definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition naming a tag in its repository": {
			serviceDefinitionBody(strings.Replace(definitionMinimalDocument,
				`/minimal"`, `/minimal:latest"`, 1), definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition whose mounts overlap": {
			serviceDefinitionBody(strings.Replace(definitionMinimalDocument,
				`"volumes":[],"tmpfs":[]`, `"volumes":["/srv/data"],"tmpfs":["/srv/data/tmp"]`, 1),
				definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition climbing out of its container path": {
			serviceDefinitionBody(strings.Replace(definitionMinimalDocument,
				`"volumes":[]`, `"volumes":["/srv/../etc"]`, 1), definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition carrying an unknown field": {
			serviceDefinitionBody(strings.Replace(definitionMinimalDocument,
				`"schema_version":1`, `"schema_version":1,"account":"root"`, 1), definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a definition beyond its own bound": {
			serviceDefinitionBody(oversizedDefinition, definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"an empty document": {
			serviceDefinitionBody("", definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a document that is not JSON at all": {
			serviceDefinitionBody("lab-notes", definitionPlaceholderSHA256),
			http.StatusBadRequest, "invalid_request"},
		"a submission beyond the bound this route announces": {
			serviceDefinitionBody(strings.Repeat("a", int(maxServiceDefinitionRequestBytes)), definitionPlaceholderSHA256),
			http.StatusRequestEntityTooLarge, "request_too_large"},
	} {
		response := fixture.request(http.MethodPost, "/v0/service-definitions", check.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	// The one definition that was frozen is exactly as it was, and nothing joined
	// it. The refused revision is the proof the store never half-applied one: the
	// bytes of the alteration are nowhere, under any digest.
	state := fixture.definitions.Snapshot()
	if state.DefinitionRevision != 1 || len(state.Definitions) != 1 ||
		state.Definitions[0].Document != definitionVectorDocument ||
		state.Definitions[0].Digest != frozen.Definition.DefinitionSHA256 {
		t.Fatalf("a refused request changed the frozen definitions: %+v", state)
	}
	if strings.Contains(listServiceDefinitions(t, fixture).Definitions[0].DefinitionDocument, "8081") ||
		alteredDigest == definitionVectorSHA256 {
		t.Fatal("the altered definition reached the inventory")
	}
}

// TestControllerServiceDefinitionsRefuseAFreezeTheListingCouldNotCarry is the
// decision the two bounds of this palier meet at.
//
// The reading must omit no definition, so the one thing this route may never do
// is accept a freeze and then serve a listing that leaves something out. The
// refusal therefore happens at the freeze, out loud, with the existing
// `409 state_conflict` — and everything frozen before it stays readable, whole and
// unchanged, which is what a human whose next freeze was refused needs to be true.
func TestControllerServiceDefinitionsRefuseAFreezeTheListingCouldNotCarry(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	bearer := "Bearer " + fixture.token

	// A definition close to its own bound, so that the listing bound is the one
	// reached first and few enough requests are needed to reach it.
	padding := make([]string, 0, 14)
	for index := 0; index < 14; index++ {
		padding = append(padding, `"PAD_`+string(rune('A'+index))+`=`+strings.Repeat("a", 500)+`"`)
	}
	frozen := 0
	refused := false
	for index := 0; index < maxFrozenServiceDefinitions && !refused; index++ {
		document := `{"schema_version":1,"slug":"pad-` + strconv.Itoa(index) +
			`","image_repository":"registry.lab.your-cloud.test/pad","container_port":8080,` +
			`"volumes":[],"tmpfs":[],"environment":[` + strings.Join(padding, ",") + `],"secret_keys":[]}`
		if len(document) > servicedefinition.MaxDefinitionBytes {
			t.Fatalf("the padded definition is %d bytes", len(document))
		}
		response := fixture.request(http.MethodPost, "/v0/service-definitions",
			serviceDefinitionBody(document, definitionDigest(t, document)),
			"application/json", bearer, fixture.certificate)
		switch response.Code {
		case http.StatusCreated:
			frozen++
		case http.StatusConflict:
			if !strings.Contains(response.Body.String(), `"error_code":"state_conflict"`) {
				t.Fatalf("the refusal left the closed list: %s", response.Body.String())
			}
			refused = true
		default:
			t.Fatalf("freeze %d status=%d body=%s", index, response.Code, response.Body.String())
		}
	}
	if !refused || frozen == 0 {
		t.Fatalf("the listing bound was never reached: %d definitions frozen", frozen)
	}
	listed := listServiceDefinitions(t, fixture)
	if len(listed.Definitions) != frozen || listed.DefinitionRevision != uint64(frozen) {
		t.Fatalf("the listing carries %d of the %d definitions frozen", len(listed.Definitions), frozen)
	}
}

// TestControllerServiceDefinitionsProduceNoPlanInEitherDirection is the proof of
// the property the whole palier rests on: a definition has no effect.
//
// In one direction, no plan route of the delivered doors can name a definition:
// neither `definition_document` nor `definition_sha256` is a field of any of their
// schemas, so a request carrying one is refused by the strict decoding before its
// value is read. In the other, freezing changes nothing about the plans of those
// doors — the plan a machine could build before the freeze is the plan it builds
// after it, byte for byte.
//
// `/v0/user-service-plans` is deliberately absent from the list below, and it is
// the one route for which the second sentence does not hold: a definition exists
// to be pinned, and that route is where the pinning happens. It still produces
// nothing here, because a plan of the third door is born of a human asking for
// one — freezing a definition builds no plan on any route, which is what the
// reference plan at the end of this test says.
func TestControllerServiceDefinitionsProduceNoPlanInEitherDirection(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	before := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 8080),
		"application/json", bearer, fixture.certificate)
	if before.Code != http.StatusOK {
		t.Fatalf("the reference plan status=%d body=%s", before.Code, before.Body.String())
	}

	freezeServiceDefinition(t, fixture, definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)

	for _, route := range []string{
		"/v0/probe-plans", "/v0/service-plans", "/v0/entrypoint-plans", "/v0/route-plans",
		"/v0/link-plans", "/v0/listener-peer-plans", "/v0/initiator-peer-plans",
		"/v0/private-service-plans", "/v0/link-route-plans", "/v0/snapshot-plans", "/v0/restore-plans",
	} {
		body := `{"schema_version":1,"machine_id":"lab-machine-1","definition_sha256":"` + definitionVectorSHA256 + `"}`
		response := fixture.request(http.MethodPost, route, body, "application/json", bearer, fixture.certificate)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error_code":"invalid_request"`) {
			t.Fatalf("%s accepted a definition digest: status=%d body=%s", route, response.Code, response.Body.String())
		}
	}

	after := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 8080),
		"application/json", bearer, fixture.certificate)
	if after.Code != http.StatusOK || after.Body.String() != before.Body.String() {
		t.Fatalf("freezing a definition changed a plan: status=%d body=%s", after.Code, after.Body.String())
	}
	if strings.Contains(after.Body.String(), definitionVectorSHA256) {
		t.Fatalf("a plan of a delivered door named a definition: %s", after.Body.String())
	}
	// The machine is exactly where it was: freezing places nothing, attributes
	// nothing and mutates nothing about it.
	if inventory := fixture.inventory.Snapshot(); len(inventory.Machines) != 1 ||
		inventory.Machines[0].MachineID != "lab-machine-1" || inventory.InventoryRevision != 1 {
		t.Fatalf("freezing a definition disturbed the managed inventory: %+v", inventory)
	}
}
