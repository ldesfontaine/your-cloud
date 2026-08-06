package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

func attachProbeMachine(t *testing.T, fixture controllerHTTPFixture, machineID string) {
	t.Helper()
	if _, _, err := fixture.inventory.PutMachine(machineID, "Serveur principal", true); err != nil {
		t.Fatal(err)
	}
}

func probePlanBody(machineID, operation string, port int) string {
	return `{"schema_version":1,"machine_id":"` + machineID + `","operation":"` + operation +
		`","local_port":` + strconv.Itoa(port) + `}`
}

// TestControllerProbePlanFreezesThePairItBuilt is the nominal proof: the
// Console receives two complete documents and the two digests an envelope will
// name, and every one of them survives a decode by the same rules the Auxiliary
// will apply.
func TestControllerProbePlanFreezesThePairItBuilt(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	response := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 8080),
		"application/json", bearer, fixture.certificate)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("nominal probe plan status=%d body=%s", response.Code, response.Body.String())
	}
	var view ProbePlanView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.SchemaVersion != 1 {
		t.Fatalf("unexpected view schema: %d", view.SchemaVersion)
	}

	deploy, err := plan.Decode([]byte(view.PlanDocument))
	if err != nil {
		t.Fatalf("the Controller emitted a plan its own rules refuse: %v", err)
	}
	rollback, err := plan.Decode([]byte(view.RollbackDocument))
	if err != nil {
		t.Fatalf("the Controller emitted a rollback its own rules refuse: %v", err)
	}
	state := fixture.inventory.Snapshot()
	if deploy.InfrastructureID != state.InfrastructureID || deploy.MachineID != "lab-machine-1" ||
		deploy.Operation != plan.OperationDeployOCIProbe || deploy.LocalPort != 8080 ||
		deploy.ImageReference != plan.ProbeImageReference || deploy.ImageDigest != plan.ProbeImageDigest {
		t.Fatalf("the plan does not describe what was asked for: %+v", deploy)
	}
	if rollback.Operation != plan.OperationRemoveOCIProbe || rollback.MachineID != deploy.MachineID ||
		rollback.LocalPort != deploy.LocalPort || rollback.InfrastructureID != deploy.InfrastructureID {
		t.Fatalf("the rollback does not undo the exact instance: %+v", rollback)
	}

	// The digests are the Console's to recompute; they must be the ones the
	// transported documents produce and not a claim beside them.
	planDigest, err := deploy.SHA256()
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
	replay := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 8080),
		"application/json", bearer, fixture.certificate)
	if replay.Code != http.StatusOK || replay.Body.String() != response.Body.String() {
		t.Fatalf("a repeated request produced another pair: status=%d body=%s", replay.Code, replay.Body.String())
	}

	// The reverse direction names the same two documents in the other order.
	removal := fixture.request(http.MethodPost, "/v0/probe-plans",
		probePlanBody("lab-machine-1", plan.OperationRemoveOCIProbe, 8080),
		"application/json", bearer, fixture.certificate)
	if removal.Code != http.StatusOK {
		t.Fatalf("removal plan status=%d body=%s", removal.Code, removal.Body.String())
	}
	var reverse ProbePlanView
	if err := json.Unmarshal(removal.Body.Bytes(), &reverse); err != nil {
		t.Fatal(err)
	}
	if reverse.PlanSHA256 != view.RollbackSHA256 || reverse.RollbackSHA256 != view.PlanSHA256 {
		t.Fatal("the two directions of the pair do not name the same documents")
	}
}

// TestControllerProbePlanRequiresTheSameAuthorityAsEveryOtherRoute keeps this
// endpoint on the one authenticated path rather than beside it.
func TestControllerProbePlanRequiresTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	body := probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 8080)

	if response := fixture.request(http.MethodPost, "/v0/probe-plans", body, "application/json", bearer, nil); response.Code != http.StatusForbidden {
		t.Fatalf("missing device certificate status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/probe-plans", body, "application/json", "", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing human session status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/probe-plans", body, "application/json", "Bearer wrong", fixture.certificate); response.Code != http.StatusUnauthorized {
		t.Fatalf("foreign session token status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodGet, "/v0/probe-plans", "", "application/json", bearer, fixture.certificate); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("read method status=%d body=%s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodPost, "/v0/probe-plans", body, "*/*", bearer, fixture.certificate); response.Code != http.StatusNotAcceptable {
		t.Fatalf("unacceptable media status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestControllerProbePlanRefusesEveryRequestOutsideTheContract is the hostile
// surface of the endpoint. None of these may produce bytes a human could be
// asked to approve.
func TestControllerProbePlanRefusesEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for name, check := range map[string]struct {
		body   string
		status int
		code   string
	}{
		"unsupported schema": {
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"deploy_oci_probe","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"unknown field": {
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"deploy_oci_probe","local_port":8080,"image_reference":"ghcr.io/attacker/probe"}`,
			http.StatusBadRequest, "invalid_request"},
		"chosen digest": {
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"deploy_oci_probe","local_port":8080,"image_digest":"sha256:` + strings.Repeat("0", 64) + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"chosen infrastructure": {
			`{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","machine_id":"lab-machine-1","operation":"deploy_oci_probe","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"repeated field": {
			`{"schema_version":1,"machine_id":"lab-machine-1","machine_id":"lab-machine-2","operation":"deploy_oci_probe","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"unknown operation": {
			probePlanBody("lab-machine-1", "install_container", 8080),
			http.StatusBadRequest, "invalid_request"},
		"read-only operation of the previous palier": {
			probePlanBody("lab-machine-1", "diagnose_protocol_read_only", 8080),
			http.StatusBadRequest, "invalid_request"},
		"privileged port": {
			probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 443),
			http.StatusBadRequest, "invalid_request"},
		"port above range": {
			probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 65536),
			http.StatusBadRequest, "invalid_request"},
		"absent port": {
			probePlanBody("lab-machine-1", plan.OperationDeployOCIProbe, 0),
			http.StatusBadRequest, "invalid_request"},
		"traversal machine": {
			`{"schema_version":1,"machine_id":"../../etc/shadow","operation":"deploy_oci_probe","local_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"machine this Controller does not know": {
			probePlanBody("lab-machine-2", plan.OperationDeployOCIProbe, 8080),
			http.StatusUnprocessableEntity, "machine_not_active"},
	} {
		response := fixture.request(http.MethodPost, "/v0/probe-plans", check.body, "application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	oversized := `{"schema_version":1,"machine_id":"` + strings.Repeat("a", 5000) + `","operation":"deploy_oci_probe","local_port":8080}`
	if response := fixture.request(http.MethodPost, "/v0/probe-plans", oversized, "application/json", bearer, fixture.certificate); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d body=%s", response.Code, response.Body.String())
	}
}
