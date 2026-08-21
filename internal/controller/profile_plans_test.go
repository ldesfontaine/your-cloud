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
	profileRouteHost   = "bentopdf.lab.your-cloud.test"
	profileBackendPort = 8080
)

func webServicePlanBody(machineID, operation, profile string, port int) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation +
		`","service_profile":"` + profile + `","local_port":` + strconv.Itoa(port) + `}`
}

func entrypointPlanBody(machineID, operation string) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation + `"}`
}

func routePlanBody(machineID, operation, host string, port int) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation +
		`","route_host":"` + host + `","backend_port":` + strconv.Itoa(port) + `}`
}

// TestControllerProfilePlansFreezeThePairsTheyBuilt is the nominal proof of the
// three routes: the App receives two complete documents and the two digests
// an envelope will name, and every one of them survives a decode by the same
// rules the Auxiliary will apply.
func TestControllerProfilePlansFreezeThePairsTheyBuilt(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	state := fixture.inventory.Snapshot()

	for name, subject := range map[string]struct {
		route    string
		forward  string
		reverse  string
		expected func(t *testing.T, document plan.V2Document)
	}{
		"service": {
			route:   "/v0/service-plans",
			forward: webServicePlanBody("lab-machine-1", plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, 8080),
			reverse: webServicePlanBody("lab-machine-1", plan.OperationRemoveWebService, plan.ServiceProfileBentoPDF, 8080),
			expected: func(t *testing.T, document plan.V2Document) {
				service, ok := document.(plan.WebServiceDocument)
				if !ok {
					t.Fatalf("the service route emitted %T", document)
				}
				if service.ServiceProfile != plan.ServiceProfileBentoPDF ||
					service.ImageReference != plan.BentoPDFImageReference ||
					service.ImageDigest != plan.BentoPDFImageDigest || service.LocalPort != 8080 {
					t.Fatalf("the plan does not describe what was asked for: %+v", service)
				}
			},
		},
		"entrypoint": {
			route:   "/v0/entrypoint-plans",
			forward: entrypointPlanBody("lab-machine-1", plan.OperationDeployEntrypoint),
			reverse: entrypointPlanBody("lab-machine-1", plan.OperationRemoveEntrypoint),
			expected: func(t *testing.T, document plan.V2Document) {
				entrypoint, ok := document.(plan.EntrypointDocument)
				if !ok {
					t.Fatalf("the entrypoint route emitted %T", document)
				}
				if entrypoint.ImageReference != plan.EntrypointImageReference ||
					entrypoint.ImageDigest != plan.EntrypointImageDigest {
					t.Fatalf("the plan does not describe what was asked for: %+v", entrypoint)
				}
			},
		},
		"route": {
			route:   "/v0/route-plans",
			forward: routePlanBody("lab-machine-1", plan.OperationPublishRoute, profileRouteHost, profileBackendPort),
			reverse: routePlanBody("lab-machine-1", plan.OperationRetireRoute, profileRouteHost, profileBackendPort),
			expected: func(t *testing.T, document plan.V2Document) {
				published, ok := document.(plan.RouteDocument)
				if !ok {
					t.Fatalf("the route route emitted %T", document)
				}
				if published.RouteHost != profileRouteHost || published.BackendPort != profileBackendPort {
					t.Fatalf("the plan does not describe what was asked for: %+v", published)
				}
			},
		},
	} {
		response := fixture.request(http.MethodPost, subject.route, subject.forward,
			"application/json", bearer, fixture.certificate)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: nominal status=%d body=%s", name, response.Code, response.Body.String())
		}
		var view PlanPairView
		if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if view.SchemaVersion != plan.SchemaVersionV2 {
			t.Fatalf("%s: unexpected view schema: %d", name, view.SchemaVersion)
		}

		document, err := plan.DecodeV2([]byte(view.PlanDocument))
		if err != nil {
			t.Fatalf("%s: the Controller emitted a plan its own rules refuse: %v", name, err)
		}
		rollback, err := plan.DecodeV2([]byte(view.RollbackDocument))
		if err != nil {
			t.Fatalf("%s: the Controller emitted a rollback its own rules refuse: %v", name, err)
		}
		if document.Target() != (plan.Target{InfrastructureID: state.InfrastructureID, MachineID: "lab-machine-1"}) {
			t.Fatalf("%s: the plan aims elsewhere: %+v", name, document.Target())
		}
		subject.expected(t, document)
		if !rollback.IsExactInverseOf(document) {
			t.Fatalf("%s: the rollback does not undo the exact instance", name)
		}

		// The digests are the App's to recompute; they must be the ones the
		// transported documents produce and not a claim beside them.
		planDigest, err := document.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rollbackDigest, err := rollback.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if view.PlanSHA256 != planDigest || view.RollbackSHA256 != rollbackDigest {
			t.Fatalf("%s: the announced digests do not cover the transported documents: %+v", name, view)
		}

		// The same request twice is the same frozen pair: nothing here is a
		// transaction and nothing here consumes anything.
		replay := fixture.request(http.MethodPost, subject.route, subject.forward,
			"application/json", bearer, fixture.certificate)
		if replay.Code != http.StatusOK || replay.Body.String() != response.Body.String() {
			t.Fatalf("%s: a repeated request produced another pair: status=%d body=%s",
				name, replay.Code, replay.Body.String())
		}

		// The reverse direction names the same two documents in the other order.
		inverse := fixture.request(http.MethodPost, subject.route, subject.reverse,
			"application/json", bearer, fixture.certificate)
		if inverse.Code != http.StatusOK {
			t.Fatalf("%s: reverse status=%d body=%s", name, inverse.Code, inverse.Body.String())
		}
		var reverse PlanPairView
		if err := json.Unmarshal(inverse.Body.Bytes(), &reverse); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reverse.PlanSHA256 != view.RollbackSHA256 || reverse.RollbackSHA256 != view.PlanSHA256 {
			t.Fatalf("%s: the two directions of the pair do not name the same documents", name)
		}
	}
}

// TestControllerProfilePlansRequireTheSameAuthorityAsEveryOtherRoute keeps the
// three endpoints on the one authenticated path rather than beside it.
func TestControllerProfilePlansRequireTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for route, body := range map[string]string{
		"/v0/service-plans":    webServicePlanBody("lab-machine-1", plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, 8080),
		"/v0/entrypoint-plans": entrypointPlanBody("lab-machine-1", plan.OperationDeployEntrypoint),
		"/v0/route-plans":      routePlanBody("lab-machine-1", plan.OperationPublishRoute, profileRouteHost, profileBackendPort),
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
		if response := fixture.request(http.MethodGet, route, "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: read method status=%d body=%s", route, response.Code, response.Body.String())
		}
		if response := fixture.request(http.MethodDelete, route, "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: delete method status=%d body=%s", route, response.Code, response.Body.String())
		}
		if response := fixture.request(http.MethodPost, route, body, "*/*", bearer, fixture.certificate); response.Code != http.StatusNotAcceptable {
			t.Fatalf("%s: unacceptable media status=%d body=%s", route, response.Code, response.Body.String())
		}
	}
}

// TestControllerProfilePlansRefuseEveryRequestOutsideTheContract is the hostile
// surface of the three endpoints. None of these may produce bytes a human could
// be asked to approve.
//
// The requests that carry a field of another operation group are the point of
// the three sibling routes: they are refused as unknown fields of the schema the
// route declares, before any of their values is read.
func TestControllerProfilePlansRefuseEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for name, check := range map[string]struct {
		route  string
		body   string
		status int
		code   string
	}{
		"a service plan of schema 1": {"/v0/service-plans",
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"deploy_web_service","service_profile":"bentopdf","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan choosing its image": {"/v0/service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_web_service","service_profile":"bentopdf","local_port":8080,"image_reference":"ghcr.io/attacker/bentopdf"}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan choosing its digest": {"/v0/service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_web_service","service_profile":"bentopdf","local_port":8080,"image_digest":"sha256:` + strings.Repeat("0", 64) + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan choosing its infrastructure": {"/v0/service-plans",
			`{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","machine_id":"lab-machine-1","operation":"deploy_web_service","service_profile":"bentopdf","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan repeating a field": {"/v0/service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","machine_id":"lab-machine-2","operation":"deploy_web_service","service_profile":"bentopdf","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan carrying a route host": {"/v0/service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_web_service","service_profile":"bentopdf","local_port":8080,"route_host":"evil.test"}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan on an unknown profile": {"/v0/service-plans",
			webServicePlanBody("lab-machine-1", plan.OperationDeployWebService, "bentopdf-simple", 8080),
			http.StatusBadRequest, "invalid_request"},
		"a service plan without a profile": {"/v0/service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_web_service","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a service plan on the probe operation": {"/v0/service-plans",
			webServicePlanBody("lab-machine-1", "deploy_oci_probe", plan.ServiceProfileBentoPDF, 8080),
			http.StatusBadRequest, "invalid_request"},
		"a service plan on a route operation": {"/v0/service-plans",
			webServicePlanBody("lab-machine-1", plan.OperationPublishRoute, plan.ServiceProfileBentoPDF, 8080),
			http.StatusBadRequest, "invalid_request"},
		"a service plan on a privileged port": {"/v0/service-plans",
			webServicePlanBody("lab-machine-1", plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, 443),
			http.StatusBadRequest, "invalid_request"},
		"a service plan beyond the port range": {"/v0/service-plans",
			webServicePlanBody("lab-machine-1", plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, 65536),
			http.StatusBadRequest, "invalid_request"},
		"a service plan on a traversal machine": {"/v0/service-plans",
			webServicePlanBody("../../etc/shadow", plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, 8080),
			http.StatusBadRequest, "invalid_request"},
		"a service plan on a machine this Controller does not know": {"/v0/service-plans",
			webServicePlanBody("lab-machine-2", plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, 8080),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"an entrypoint plan of schema 1": {"/v0/entrypoint-plans",
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"deploy_entrypoint"}`,
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan choosing a port": {"/v0/entrypoint-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_entrypoint","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan choosing a public port": {"/v0/entrypoint-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_entrypoint","public_port":443}`,
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan choosing a host": {"/v0/entrypoint-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_entrypoint","route_host":"evil.test"}`,
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan choosing its image": {"/v0/entrypoint-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_entrypoint","image_reference":"ghcr.io/attacker/traefik"}`,
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan on a service operation": {"/v0/entrypoint-plans",
			entrypointPlanBody("lab-machine-1", plan.OperationDeployWebService),
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan on an unknown operation": {"/v0/entrypoint-plans",
			entrypointPlanBody("lab-machine-1", "install_ingress"),
			http.StatusBadRequest, "invalid_request"},
		"an entrypoint plan on a machine this Controller does not know": {"/v0/entrypoint-plans",
			entrypointPlanBody("lab-machine-2", plan.OperationDeployEntrypoint),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"a route plan of schema 1": {"/v0/route-plans",
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"publish_route","route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a route plan carrying an image": {"/v0/route-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"publish_route","route_host":"bentopdf.lab.your-cloud.test","backend_port":8080,"image_digest":"sha256:` + strings.Repeat("0", 64) + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a route plan carrying a profile": {"/v0/route-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"publish_route","route_host":"bentopdf.lab.your-cloud.test","backend_port":8080,"service_profile":"bentopdf"}`,
			http.StatusBadRequest, "invalid_request"},
		"a route plan on a wildcard host": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationPublishRoute, "*.lab.your-cloud.test", profileBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a route plan on an upper-case host": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationPublishRoute, "BentoPDF.lab.your-cloud.test", profileBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a route plan on a host opening on a dot": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationPublishRoute, ".lab.your-cloud.test", profileBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a route plan on a host with an empty label": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationPublishRoute, "bentopdf..lab.your-cloud.test", profileBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a route plan without a host": {"/v0/route-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"publish_route","backend_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a route plan on a privileged backend": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationPublishRoute, profileRouteHost, 443),
			http.StatusBadRequest, "invalid_request"},
		"a route plan beyond the backend range": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationPublishRoute, profileRouteHost, 65536),
			http.StatusBadRequest, "invalid_request"},
		"a route plan on an entrypoint operation": {"/v0/route-plans",
			routePlanBody("lab-machine-1", plan.OperationRemoveEntrypoint, profileRouteHost, profileBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a route plan on a machine this Controller does not know": {"/v0/route-plans",
			routePlanBody("lab-machine-2", plan.OperationPublishRoute, profileRouteHost, profileBackendPort),
			http.StatusUnprocessableEntity, "machine_not_active"},
	} {
		response := fixture.request(http.MethodPost, check.route, check.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	oversized := routePlanBody("lab-machine-1", plan.OperationPublishRoute,
		strings.Repeat("a", 5000), profileBackendPort)
	if response := fixture.request(http.MethodPost, "/v0/route-plans", oversized,
		"application/json", bearer, fixture.certificate); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d body=%s", response.Code, response.Body.String())
	}
}
