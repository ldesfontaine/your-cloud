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
	// The origin and the published name are the same string, which is what the
	// contract describes: the service answers under the exact name the route
	// serves. They are the values the plan package pins as its own vectors, so a
	// drift between the two packages fails on both sides rather than on neither.
	privateOriginHost   = "vault.lab.your-cloud.test"
	privateRouteHost    = "vault.lab.your-cloud.test"
	privateBackendPort  = 8080
	privateLocalPort    = 8080
	privateSnapshotSlot = "nightly"
)

func privateServicePlanBody(machineID, operation, profile string, port int, origin string) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation +
		`","service_profile":"` + profile + `","local_port":` + strconv.Itoa(port) +
		`,"origin_host":"` + origin + `"}`
}

func linkRoutePlanBody(machineID, operation, host string, port int) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation +
		`","route_host":"` + host + `","backend_port":` + strconv.Itoa(port) + `}`
}

func snapshotPlanBody(machineID, operation, profile, slot string) string {
	return `{"schema_version":2,"machine_id":"` + machineID + `","operation":"` + operation +
		`","service_profile":"` + profile + `","snapshot_slot":"` + slot + `"}`
}

func restorePlanBody(machineID, profile, slot string) string {
	return `{"schema_version":2,"machine_id":"` + machineID +
		`","service_profile":"` + profile + `","snapshot_slot":"` + slot + `"}`
}

// TestControllerPrivatePlansFreezeThePairsTheyBuilt is the nominal proof of the
// four routes of the private profile: the Console receives two complete documents
// and the two digests an envelope will name, and every one of them survives a
// decode by the same rules the Auxiliary will apply.
func TestControllerPrivatePlansFreezeThePairsTheyBuilt(t *testing.T) {
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
		"private service": {
			route: "/v0/private-service-plans",
			forward: privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				plan.ServiceProfileVaultwarden, privateLocalPort, privateOriginHost),
			reverse: privateServicePlanBody("lab-machine-1", plan.OperationRemovePrivateService,
				plan.ServiceProfileVaultwarden, privateLocalPort, privateOriginHost),
			expected: func(t *testing.T, document plan.V2Document) {
				service, ok := document.(plan.PrivateServiceDocument)
				if !ok {
					t.Fatalf("the private service route emitted %T", document)
				}
				if service.ServiceProfile != plan.ServiceProfileVaultwarden ||
					service.LocalPort != privateLocalPort ||
					service.OriginHost != privateOriginHost {
					t.Fatalf("the plan does not describe what was asked for: %+v", service)
				}
				// The image is the profile's and never the request's: no field of
				// the request could have named it.
				if service.ImageReference != plan.VaultwardenImageReference ||
					service.ImageDigest != plan.VaultwardenImageDigest {
					t.Fatalf("the plan names an image the profile does not pin: %+v", service)
				}
			},
		},
		"link route": {
			route: "/v0/link-route-plans",
			forward: linkRoutePlanBody("lab-machine-1", plan.OperationPublishLinkRoute,
				privateRouteHost, privateBackendPort),
			reverse: linkRoutePlanBody("lab-machine-1", plan.OperationRetireLinkRoute,
				privateRouteHost, privateBackendPort),
			expected: func(t *testing.T, document plan.V2Document) {
				route, ok := document.(plan.LinkRouteDocument)
				if !ok {
					t.Fatalf("the link route route emitted %T", document)
				}
				if route.RouteHost != privateRouteHost || route.BackendPort != privateBackendPort {
					t.Fatalf("the plan does not describe what was asked for: %+v", route)
				}
			},
		},
		"snapshot": {
			route: "/v0/snapshot-plans",
			forward: snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, privateSnapshotSlot),
			reverse: snapshotPlanBody("lab-machine-1", plan.OperationDiscardSnapshot,
				plan.ServiceProfileVaultwarden, privateSnapshotSlot),
			expected: func(t *testing.T, document plan.V2Document) {
				snapshot, ok := document.(plan.SnapshotDocument)
				if !ok {
					t.Fatalf("the snapshot route emitted %T", document)
				}
				if snapshot.ServiceProfile != plan.ServiceProfileVaultwarden ||
					snapshot.SnapshotSlot != privateSnapshotSlot {
					t.Fatalf("the plan does not describe what was asked for: %+v", snapshot)
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

// TestControllerRestorePlansCarryTheReturnAsTheirRollback is the one route whose
// rollback a request never describes.
//
// A restore has one direction, so the request has no operation field; and the
// document that undoes it is a restore of the reserved slot, built by the plan
// package from the profile and the machine the request named. The Console
// displays that document like any other — it is what the human approves beside
// the restore itself.
func TestControllerRestorePlansCarryTheReturnAsTheirRollback(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	response := fixture.request(http.MethodPost, "/v0/restore-plans",
		restorePlanBody("lab-machine-1", plan.ServiceProfileVaultwarden, privateSnapshotSlot),
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
	rollback, err := plan.DecodeV2([]byte(view.RollbackDocument))
	if err != nil {
		t.Fatalf("the Controller emitted a rollback its own rules refuse: %v", err)
	}
	subject, ok := document.(plan.RestoreDocument)
	if !ok || subject.SnapshotSlot != privateSnapshotSlot {
		t.Fatalf("the restore route emitted %T: %+v", document, document)
	}
	returning, ok := rollback.(plan.RestoreDocument)
	if !ok {
		t.Fatalf("the rollback of a restore is a %T", rollback)
	}
	if returning.Operation != plan.OperationRestoreService ||
		returning.SnapshotSlot != plan.ReservedSnapshotSlot {
		t.Fatalf("the rollback of a restore is not the return itself: %+v", returning)
	}
	if !rollback.IsExactInverseOf(document) {
		t.Fatalf("the rollback does not undo the restore it travels with")
	}
	if view.PlanSHA256 == view.RollbackSHA256 {
		t.Fatal("a restore and its return name one digest")
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
}

// TestControllerPrivatePlansRequireTheSameAuthorityAsEveryOtherRoute keeps the
// four endpoints on the one authenticated path rather than beside it.
func TestControllerPrivatePlansRequireTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for route, body := range map[string]string{
		"/v0/private-service-plans": privateServicePlanBody("lab-machine-1",
			plan.OperationDeployPrivateService, plan.ServiceProfileVaultwarden,
			privateLocalPort, privateOriginHost),
		"/v0/link-route-plans": linkRoutePlanBody("lab-machine-1",
			plan.OperationPublishLinkRoute, privateRouteHost, privateBackendPort),
		"/v0/snapshot-plans": snapshotPlanBody("lab-machine-1",
			plan.OperationSnapshotService, plan.ServiceProfileVaultwarden, privateSnapshotSlot),
		"/v0/restore-plans": restorePlanBody("lab-machine-1",
			plan.ServiceProfileVaultwarden, privateSnapshotSlot),
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

// TestControllerPrivatePlansRefuseEveryRequestOutsideTheContract is the hostile
// surface of the four endpoints. None of these may produce bytes a human could be
// asked to approve.
//
// The requests that carry a field of another operation group are the point of the
// four sibling routes: they are refused as unknown fields of the schema the route
// declares, before any of their values is read. The requests that name a constant
// of the profile — a volume, an environment line, the tunnel's peer — are the
// point of the contract: an approvable value that could move a path or widen the
// passage does not exist.
func TestControllerPrivatePlansRefuseEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for name, check := range map[string]struct {
		route  string
		body   string
		status int
		code   string
	}{
		"a private plan of schema 3": {"/v0/private-service-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan choosing its infrastructure": {"/v0/private-service-plans",
			`{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan choosing its image": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `","image_reference":"ghcr.io/attacker/vaultwarden"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan choosing its digest": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `","image_digest":"` + plan.BentoPDFImageDigest + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan choosing a volume": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `","volume":"/etc"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan choosing an environment line": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `","environment":["SIGNUPS_ALLOWED=true"]}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan choosing an egress rule": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `","egress":"accept"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan carrying a slot": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `","snapshot_slot":"nightly"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan repeating a field": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","machine_id":"lab-machine-2","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080,"origin_host":"` + privateOriginHost + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan on the stateless profile": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				plan.ServiceProfileBentoPDF, privateLocalPort, privateOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a private plan on a stateless operation": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-1", plan.OperationDeployWebService,
				plan.ServiceProfileVaultwarden, privateLocalPort, privateOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a private plan without an origin": {"/v0/private-service-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_private_service","service_profile":"vaultwarden","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a private plan on a wildcard origin": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				plan.ServiceProfileVaultwarden, privateLocalPort, "*.lab.your-cloud.test"),
			http.StatusBadRequest, "invalid_request"},
		"a private plan on an origin carrying a scheme": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				plan.ServiceProfileVaultwarden, privateLocalPort, "https://vault.lab.your-cloud.test"),
			http.StatusBadRequest, "invalid_request"},
		"a private plan on a privileged port": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
				plan.ServiceProfileVaultwarden, 443, privateOriginHost),
			http.StatusBadRequest, "invalid_request"},
		"a private plan on a machine this Controller does not know": {"/v0/private-service-plans",
			privateServicePlanBody("lab-machine-2", plan.OperationDeployPrivateService,
				plan.ServiceProfileVaultwarden, privateLocalPort, privateOriginHost),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"a link route plan of schema 3": {"/v0/link-route-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"publish_link_route","route_host":"` + privateRouteHost + `","backend_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a link route plan choosing a backend address": {"/v0/link-route-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"publish_link_route","route_host":"` + privateRouteHost + `","backend_port":8080,"backend_address":"10.66.66.2"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link route plan choosing headers": {"/v0/link-route-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"publish_link_route","route_host":"` + privateRouteHost + `","backend_port":8080,"headers":{"X-Real-IP":"1.2.3.4"}}`,
			http.StatusBadRequest, "invalid_request"},
		"a link route plan carrying a profile": {"/v0/link-route-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"publish_link_route","route_host":"` + privateRouteHost + `","backend_port":8080,"service_profile":"vaultwarden"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link route plan on a wildcard host": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-1", plan.OperationPublishLinkRoute,
				"*.lab.your-cloud.test", privateBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a link route plan on an upper-case host": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-1", plan.OperationPublishLinkRoute,
				"Vault.lab.your-cloud.test", privateBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a link route plan on a host carrying a rule": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-1", plan.OperationPublishLinkRoute,
				"vault.lab.test`)||Host(`evil.test", privateBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a link route plan on a privileged backend": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-1", plan.OperationPublishLinkRoute, privateRouteHost, 443),
			http.StatusBadRequest, "invalid_request"},
		"a link route plan beyond the backend range": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-1", plan.OperationPublishLinkRoute, privateRouteHost, 65536),
			http.StatusBadRequest, "invalid_request"},
		"a link route plan on a passage operation": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-1", plan.OperationAttachLinkPeer, privateRouteHost, privateBackendPort),
			http.StatusBadRequest, "invalid_request"},
		"a link route plan on a machine this Controller does not know": {"/v0/link-route-plans",
			linkRoutePlanBody("lab-machine-2", plan.OperationPublishLinkRoute, privateRouteHost, privateBackendPort),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"a snapshot plan of schema 1": {"/v0/snapshot-plans",
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"snapshot_service","service_profile":"vaultwarden","snapshot_slot":"nightly"}`,
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan choosing an archive path": {"/v0/snapshot-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"snapshot_service","service_profile":"vaultwarden","snapshot_slot":"nightly","archive_path":"/tmp/out.tar.gz"}`,
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan announcing a digest": {"/v0/snapshot-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"snapshot_service","service_profile":"vaultwarden","snapshot_slot":"nightly","archive_sha256":"` + strings.Repeat("a", 64) + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on the stateless profile": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileBentoPDF, privateSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan naming the reserved slot": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, plan.ReservedSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a discard of the reserved slot": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationDiscardSnapshot,
				plan.ServiceProfileVaultwarden, plan.ReservedSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on a traversal slot": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, "../../etc/shadow"),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on an upper-case slot": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, "Nightly"),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on a dotted slot": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, "nightly.tar.gz"),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on a slot opening on a hyphen": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, "-nightly"),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan without a slot": {"/v0/snapshot-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"snapshot_service","service_profile":"vaultwarden"}`,
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on a restore operation": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-1", plan.OperationRestoreService,
				plan.ServiceProfileVaultwarden, privateSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a snapshot plan on a machine this Controller does not know": {"/v0/snapshot-plans",
			snapshotPlanBody("lab-machine-2", plan.OperationSnapshotService,
				plan.ServiceProfileVaultwarden, privateSnapshotSlot),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"a restore plan of schema 3": {"/v0/restore-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","service_profile":"vaultwarden","snapshot_slot":"nightly"}`,
			http.StatusBadRequest, "invalid_request"},
		// A restore has one direction, so the request has no operation field.
		// Naming one is an unknown field, refused before its value is read —
		// which is what keeps a direction from ever being a value someone reads.
		"a restore plan naming an operation": {"/v0/restore-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"restore_service","service_profile":"vaultwarden","snapshot_slot":"nightly"}`,
			http.StatusBadRequest, "invalid_request"},
		"a restore plan naming the reserved slot": {"/v0/restore-plans",
			restorePlanBody("lab-machine-1", plan.ServiceProfileVaultwarden, plan.ReservedSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a restore plan on the stateless profile": {"/v0/restore-plans",
			restorePlanBody("lab-machine-1", plan.ServiceProfileBentoPDF, privateSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a restore plan on a traversal slot": {"/v0/restore-plans",
			restorePlanBody("lab-machine-1", plan.ServiceProfileVaultwarden, "../../etc/shadow"),
			http.StatusBadRequest, "invalid_request"},
		"a restore plan without a slot": {"/v0/restore-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","service_profile":"vaultwarden"}`,
			http.StatusBadRequest, "invalid_request"},
		"a restore plan carrying a local port": {"/v0/restore-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","service_profile":"vaultwarden","snapshot_slot":"nightly","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a restore plan on a traversal machine": {"/v0/restore-plans",
			restorePlanBody("../../etc/shadow", plan.ServiceProfileVaultwarden, privateSnapshotSlot),
			http.StatusBadRequest, "invalid_request"},
		"a restore plan on a machine this Controller does not know": {"/v0/restore-plans",
			restorePlanBody("lab-machine-2", plan.ServiceProfileVaultwarden, privateSnapshotSlot),
			http.StatusUnprocessableEntity, "machine_not_active"},
	} {
		response := fixture.request(http.MethodPost, check.route, check.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	oversized := privateServicePlanBody("lab-machine-1", plan.OperationDeployPrivateService,
		plan.ServiceProfileVaultwarden, privateLocalPort, strings.Repeat("a", 5000))
	if response := fixture.request(http.MethodPost, "/v0/private-service-plans", oversized,
		"application/json", bearer, fixture.certificate); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d body=%s", response.Code, response.Body.String())
	}
}
