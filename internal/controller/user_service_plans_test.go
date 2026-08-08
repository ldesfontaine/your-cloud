package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	// The instance the third door's tests deploy. The image digest is synthetic
	// and looks it: this door pins no image, so there is no identity of the
	// product to name here, and the plan package pins the same two bytes counting
	// from one so a drift between the two fails on both sides rather than neither.
	userServiceSlug        = "lab-notes"
	userServiceImageDigest = "sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	userServiceLocalPort   = 8080
	userServiceOriginHost  = "notes.lab.your-cloud.test"

	userMinimalSlug        = "minimal"
	userMinimalImageDigest = "sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	userMinimalLocalPort   = 8081
)

func userServicePlanBody(machineID, operation, slug, digest, imageDigest string, port int, origin string) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation +
		`","definition_slug":"` + slug + `","definition_digest":"` + digest +
		`","image_digest":"` + imageDigest + `","local_port":` + strconv.Itoa(port) +
		`,"origin_host":"` + origin + `"}`
}

// TestControllerUserServicePlansFreezeThePairTheyBuilt is the nominal proof of
// the third door's route: the Console receives two complete documents and the two
// digests an envelope will name, every field the definition decides was read out
// of the definition rather than out of the request, and both documents survive a
// decode by the same rules the Auxiliary will apply.
func TestControllerUserServicePlansFreezeThePairTheyBuilt(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	freezeServiceDefinition(t, fixture, definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)
	state := fixture.inventory.Snapshot()

	forward := userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
		userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
		userServiceLocalPort, userServiceOriginHost)
	response := fixture.request(http.MethodPost, "/v0/user-service-plans", forward,
		"application/json", bearer, fixture.certificate)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("nominal status=%d body=%s", response.Code, response.Body.String())
	}
	var view PlanPairView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.SchemaVersion != plan.SchemaVersionV2 {
		t.Fatalf("unexpected view schema: %d", view.SchemaVersion)
	}

	document, err := plan.DecodeV2([]byte(view.PlanDocument))
	if err != nil {
		t.Fatalf("the Controller emitted a plan its own rules refuse: %v", err)
	}
	rollback, err := plan.DecodeV2([]byte(view.RollbackDocument))
	if err != nil {
		t.Fatalf("the Controller emitted a rollback its own rules refuse: %v", err)
	}
	service, ok := document.(plan.UserServiceDocument)
	if !ok {
		t.Fatalf("the user service route emitted %T", document)
	}
	if document.Target() != (plan.Target{InfrastructureID: state.InfrastructureID, MachineID: "lab-machine-1"}) {
		t.Fatalf("the plan aims elsewhere: %+v", document.Target())
	}
	if service.DefinitionSlug != userServiceSlug || service.DefinitionDigest != definitionVectorSHA256 ||
		service.ImageDigest != userServiceImageDigest || service.LocalPort != userServiceLocalPort ||
		service.OriginHost != userServiceOriginHost {
		t.Fatalf("the plan does not describe what was asked for: %+v", service)
	}
	// The repository is the pinned definition's and never the request's: no field
	// of the request could have named it.
	if service.ImageReference != "registry.lab.your-cloud.test/your-cloud/lab-notes" {
		t.Fatalf("the plan names a repository the definition does not: %+v", service)
	}
	if !rollback.IsExactInverseOf(document) {
		t.Fatal("the rollback does not undo the exact instance")
	}
	if rollback.OperationName() != plan.OperationRemoveUserService {
		t.Fatalf("the rollback of a deployment is %q", rollback.OperationName())
	}

	planDigest, err := document.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	rollbackDigest, err := rollback.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if view.PlanSHA256 != planDigest || view.RollbackSHA256 != rollbackDigest {
		t.Fatalf("the announced digests do not cover the transported documents: %+v", view)
	}

	// The same request twice is the same frozen pair: nothing here is a
	// transaction and nothing here consumes anything.
	replay := fixture.request(http.MethodPost, "/v0/user-service-plans", forward,
		"application/json", bearer, fixture.certificate)
	if replay.Code != http.StatusOK || replay.Body.String() != response.Body.String() {
		t.Fatalf("a repeated request produced another pair: status=%d body=%s",
			replay.Code, replay.Body.String())
	}

	// The reverse direction names the same two documents in the other order.
	reverse := fixture.request(http.MethodPost, "/v0/user-service-plans",
		userServicePlanBody("lab-machine-1", plan.OperationRemoveUserService,
			userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
			userServiceLocalPort, userServiceOriginHost),
		"application/json", bearer, fixture.certificate)
	if reverse.Code != http.StatusOK {
		t.Fatalf("reverse status=%d body=%s", reverse.Code, reverse.Body.String())
	}
	var inverse PlanPairView
	if err := json.Unmarshal(reverse.Body.Bytes(), &inverse); err != nil {
		t.Fatal(err)
	}
	if inverse.PlanSHA256 != view.RollbackSHA256 || inverse.RollbackSHA256 != view.PlanSHA256 {
		t.Fatal("the two directions of the pair do not name the same documents")
	}
}

// TestControllerUserServicePlansCarryNoOriginWhenTheDefinitionConsumesNone is the
// other half of the conditional field, at the one place the rule can be held:
// with the frozen definition in hand.
//
// A definition that interpolates nothing makes the origin refused rather than
// optional, and a definition that interpolates makes it required. The route holds
// both directions before any bytes a human could approve exist.
func TestControllerUserServicePlansCarryNoOriginWhenTheDefinitionConsumesNone(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	freezeServiceDefinition(t, fixture, definitionMinimalDocument, definitionMinimalSHA256, http.StatusCreated)

	response := fixture.request(http.MethodPost, "/v0/user-service-plans",
		userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
			userMinimalSlug, definitionMinimalSHA256, userMinimalImageDigest,
			userMinimalLocalPort, ""),
		"application/json", bearer, fixture.certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("nominal status=%d body=%s", response.Code, response.Body.String())
	}
	var view PlanPairView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	document, err := plan.DecodeV2([]byte(view.PlanDocument))
	if err != nil {
		t.Fatalf("the Controller emitted a plan its own rules refuse: %v", err)
	}
	service, ok := document.(plan.UserServiceDocument)
	if !ok || service.OriginHost != "" {
		t.Fatalf("the plan carries an origin no line consumes: %T %+v", document, document)
	}
	// The canonical bytes render the field even when it is empty, so the document
	// a human reads and the document the Auxiliary receives are one spelling.
	if !strings.Contains(view.PlanDocument, `"origin_host":""`) {
		t.Fatalf("the canonical plan omits the empty origin: %s", view.PlanDocument)
	}
}

// TestControllerUserServicePlansRequireTheSameAuthorityAsEveryOtherRoute keeps
// the third door's endpoint on the one authenticated path rather than beside it.
func TestControllerUserServicePlansRequireTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	freezeServiceDefinition(t, fixture, definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)

	const route = "/v0/user-service-plans"
	body := userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
		userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
		userServiceLocalPort, userServiceOriginHost)

	if response := fixture.request(http.MethodPost, route, body, "application/json", bearer, nil); response.Code != http.StatusForbidden {
		t.Fatalf("missing device certificate status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, route, body, "application/json", "", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing human session status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, route, body, "application/json", "Bearer wrong", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("foreign session token status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodGet, route, "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("read method status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodDelete, route, "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("delete method status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, route, body, "*/*", bearer, fixture.certificate); response.Code != http.StatusNotAcceptable {
		t.Fatalf("unacceptable media status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestControllerUserServicePlansRefuseEveryRequestOutsideTheContract is the
// hostile surface of the third door's endpoint. None of these may produce bytes a
// human could be asked to approve.
//
// Three families of refusal live here and nowhere else. A revision this
// Controller never froze is not a plan it can build — there would be no document
// behind the digest a human approves. A digest frozen under another slug is a
// revision of another service, and the lookup is on the pair rather than on the
// digest alone precisely so that it fails. And the two cross-checks against the
// pinned definition — the repository and the presence of the origin — are held
// with the definition in hand, which is the only place they can be held.
func TestControllerUserServicePlansRefuseEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	freezeServiceDefinition(t, fixture, definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)
	freezeServiceDefinition(t, fixture, definitionMinimalDocument, definitionMinimalSHA256, http.StatusCreated)

	const unfrozenDigest = "0000000000000000000000000000000000000000000000000000000000000000"

	for name, check := range map[string]struct {
		body   string
		status int
		code   string
	}{
		"a plan of schema 3": {
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan choosing its infrastructure": {
			`{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		// The repository is the definition's. A request that could name one could
		// aim an approval at an image from somewhere the human never approved, so
		// there is no field for it and naming one is refused before its value is
		// read.
		"a plan choosing its repository": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_reference":"ghcr.io/attacker/lab-notes","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan choosing a volume": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `","volumes":["/etc"]}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan choosing an environment line": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `","environment":["LAB_NOTES_READ_ONLY=0"]}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan choosing a secret value": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `","secrets":{"LAB_NOTES_ADMIN_TOKEN":"hunter2"}}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan choosing an account": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `","account":"root"}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan carrying the definition itself": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","definition_document":"{}","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a plan repeating a field": {
			`{"schema_version":2,"machine_id":"lab-machine-1","machine_id":"lab-machine-2","operation":"deploy_user_service","definition_slug":"lab-notes","definition_digest":"` + definitionVectorSHA256 + `","image_digest":"` + userServiceImageDigest + `","local_port":8080,"origin_host":"` + userServiceOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},

		// A revision nobody froze, and a revision frozen under another name.
		"a plan pinning a digest this Controller never froze": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, unfrozenDigest, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan pinning a digest frozen under another slug": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionMinimalSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan naming a slug frozen under another digest": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userMinimalSlug, definitionVectorSHA256, userMinimalImageDigest,
				userMinimalLocalPort, ""),
			http.StatusBadRequest, "invalid_request"},
		"a plan naming no slug at all": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				"", definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},

		// The two directions of the conditional field, each against the definition
		// that decides it.
		"a plan without the origin its definition interpolates": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, ""),
			http.StatusBadRequest, "invalid_request"},
		"a plan carrying an origin its definition consumes nowhere": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userMinimalSlug, definitionMinimalSHA256, userMinimalImageDigest,
				userMinimalLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan on a wildcard origin": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, "*.lab.your-cloud.test"),
			http.StatusBadRequest, "invalid_request"},
		"a plan on an origin carrying a scheme": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, "https://notes.lab.your-cloud.test"),
			http.StatusBadRequest, "invalid_request"},

		// The doors refuse one another, and here the refusal is the lookup that
		// fails: a definition may not be written under the four reserved names, so
		// no revision was ever frozen under them.
		"a plan naming the stateless profile": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				plan.ServiceProfileBentoPDF, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan naming the private profile": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				plan.ServiceProfileVaultwarden, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},

		"a plan on a stateless operation": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployWebService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan on a private operation": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan on an unknown operation": {
			userServicePlanBody("lab-machine-1", "start_user_service",
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan on a malformed image digest": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, "sha256:not-a-digest",
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan without an image digest": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, "",
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan on a privileged port": {
			userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				443, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a plan on a traversal machine": {
			userServicePlanBody("../../etc/shadow", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusBadRequest, "invalid_request"},
		// A machine outside the inventory receives the existing code of the closed
		// list, and this palier adds none.
		"a plan on a machine this Controller does not know": {
			userServicePlanBody("lab-machine-2", plan.OperationDeployUserService,
				userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
				userServiceLocalPort, userServiceOriginHost),
			http.StatusUnprocessableEntity, "machine_not_active"},
	} {
		response := fixture.request(http.MethodPost, "/v0/user-service-plans", check.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	oversized := userServicePlanBody("lab-machine-1", plan.OperationDeployUserService,
		userServiceSlug, definitionVectorSHA256, userServiceImageDigest,
		userServiceLocalPort, strings.Repeat("a", 5000))
	if response := fixture.request(http.MethodPost, "/v0/user-service-plans", oversized,
		"application/json", bearer, fixture.certificate); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestTheDeliveredProfilesRefuseADefinitionAtEveryPlanRoute is the other
// direction of the mutual refusal the contract names.
//
// A definition passes through no route of the delivered profiles: the two lists
// of profiles are closed against every name a definition may take, so the refusal
// is a lookup that fails rather than a comparison this Controller had to write.
// The archive routes are the exception the contract states rather than an
// oversight — they share their field with the third door and admit a slug — so
// they are exercised here as accepting, and what a slug means on a machine is
// read there.
func TestTheDeliveredProfilesRefuseADefinitionAtEveryPlanRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	freezeServiceDefinition(t, fixture, definitionVectorDocument, definitionVectorSHA256, http.StatusCreated)

	for name, body := range map[string]struct {
		route string
		body  string
	}{
		"the stateless door": {"/v0/service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_web_service","service_profile":"` + userServiceSlug + `","local_port":8080}`},
		"the private door": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				userServiceSlug, privateLocalPort, privateOriginHost)},
	} {
		response := fixture.request(http.MethodPost, body.route, body.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s built a plan for a definition: status=%d body=%s",
				name, response.Code, response.Body.String())
		}
	}

	// The archives are the one field the two vocabularies share, and the contract
	// opens them to the third door without changing their form.
	for name, body := range map[string]struct {
		route string
		body  string
	}{
		"a snapshot": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				userServiceSlug, privateSnapshotSlot)},
		"a discard": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationDiscardSnapshot,
				userServiceSlug, privateSnapshotSlot)},
		"a restore": {"/v0/restore-plans",
			restorePlanBody("lab-machine-1", userServiceSlug, privateSnapshotSlot)},
	} {
		response := fixture.request(http.MethodPost, body.route, body.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != http.StatusOK {
			t.Fatalf("%s of a user service was refused: status=%d body=%s",
				name, response.Code, response.Body.String())
		}
		var view PlanPairView
		if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		document, err := plan.DecodeV2([]byte(view.PlanDocument))
		if err != nil {
			t.Fatalf("%s: the Controller emitted a plan its own rules refuse: %v", name, err)
		}
		if !strings.Contains(view.PlanDocument, `"service_profile":"`+userServiceSlug+`"`) {
			t.Fatalf("%s does not name the service it archives: %s", name, view.PlanDocument)
		}
		if document.Target().MachineID != "lab-machine-1" {
			t.Fatalf("%s aims elsewhere: %+v", name, document.Target())
		}
	}
}
