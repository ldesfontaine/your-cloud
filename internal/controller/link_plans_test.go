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
	// linkPeerPublicKey is the synthetic peer key the plan package pins as its
	// own vector: thirty-two bytes counting from one, canonical standard base64.
	// A test that invented a key of its own would prove nothing about the one
	// spelling the two implementations agreed on.
	linkPeerPublicKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

	linkEndpointHost = "vps.lab.your-cloud.test"
	linkServicePort  = 8080
)

func linkPlanBody(machineID, operation, role string) string {
	return `{"schema_version":3,"machine_id":"` + machineID + `","operation":"` + operation +
		`","link_role":"` + role + `"}`
}

func listenerPeerPlanBody(machineID, operation, key string, port int) string {
	return `{"schema_version":3,"machine_id":"` + machineID + `","operation":"` + operation +
		`","peer_public_key":"` + key + `","service_port":` + strconv.Itoa(port) + `}`
}

func initiatorPeerPlanBody(machineID, operation, key, host string, port int) string {
	return `{"schema_version":3,"machine_id":"` + machineID + `","operation":"` + operation +
		`","peer_public_key":"` + key + `","peer_endpoint_host":"` + host +
		`","service_port":` + strconv.Itoa(port) + `}`
}

// TestControllerLinkPlansFreezeThePairsTheyBuilt is the nominal proof of the
// three routes of the private passage: the App receives two complete
// documents and the two digests an envelope will name, and every one of them
// survives a decode by the same rules the Auxiliary will apply.
func TestControllerLinkPlansFreezeThePairsTheyBuilt(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token
	state := fixture.inventory.Snapshot()

	for name, subject := range map[string]struct {
		route    string
		forward  string
		reverse  string
		expected func(t *testing.T, document plan.V3Document)
	}{
		"link": {
			route:   "/v0/link-plans",
			forward: linkPlanBody("lab-machine-1", plan.OperationPrepareLink, plan.LinkRoleListener),
			reverse: linkPlanBody("lab-machine-1", plan.OperationWithdrawLink, plan.LinkRoleListener),
			expected: func(t *testing.T, document plan.V3Document) {
				link, ok := document.(plan.LinkDocument)
				if !ok {
					t.Fatalf("the link route emitted %T", document)
				}
				if link.LinkRole != plan.LinkRoleListener {
					t.Fatalf("the plan does not describe what was asked for: %+v", link)
				}
			},
		},
		"listener peer": {
			route:   "/v0/listener-peer-plans",
			forward: listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer, linkPeerPublicKey, linkServicePort),
			reverse: listenerPeerPlanBody("lab-machine-1", plan.OperationDetachLinkPeer, linkPeerPublicKey, linkServicePort),
			expected: func(t *testing.T, document plan.V3Document) {
				junction, ok := document.(plan.ListenerPeerDocument)
				if !ok {
					t.Fatalf("the listener route emitted %T", document)
				}
				if junction.PeerPublicKey != linkPeerPublicKey || junction.ServicePort != linkServicePort {
					t.Fatalf("the plan does not describe what was asked for: %+v", junction)
				}
			},
		},
		"initiator peer": {
			route: "/v0/initiator-peer-plans",
			forward: initiatorPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer,
				linkPeerPublicKey, linkEndpointHost, linkServicePort),
			reverse: initiatorPeerPlanBody("lab-machine-1", plan.OperationLeaveLinkPeer,
				linkPeerPublicKey, linkEndpointHost, linkServicePort),
			expected: func(t *testing.T, document plan.V3Document) {
				junction, ok := document.(plan.InitiatorPeerDocument)
				if !ok {
					t.Fatalf("the initiator route emitted %T", document)
				}
				if junction.PeerPublicKey != linkPeerPublicKey ||
					junction.PeerEndpointHost != linkEndpointHost ||
					junction.ServicePort != linkServicePort {
					t.Fatalf("the plan does not describe what was asked for: %+v", junction)
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
		if view.SchemaVersion != plan.SchemaVersionV3 {
			t.Fatalf("%s: unexpected view schema: %d", name, view.SchemaVersion)
		}

		document, err := plan.DecodeV3([]byte(view.PlanDocument))
		if err != nil {
			t.Fatalf("%s: the Controller emitted a plan its own rules refuse: %v", name, err)
		}
		rollback, err := plan.DecodeV3([]byte(view.RollbackDocument))
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

// TestControllerLinkPlansRequireTheSameAuthorityAsEveryOtherRoute keeps the three
// endpoints on the one authenticated path rather than beside it.
func TestControllerLinkPlansRequireTheSameAuthorityAsEveryOtherRoute(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for route, body := range map[string]string{
		"/v0/link-plans": linkPlanBody("lab-machine-1", plan.OperationPrepareLink, plan.LinkRoleListener),
		"/v0/listener-peer-plans": listenerPeerPlanBody("lab-machine-1",
			plan.OperationAttachLinkPeer, linkPeerPublicKey, linkServicePort),
		"/v0/initiator-peer-plans": initiatorPeerPlanBody("lab-machine-1",
			plan.OperationJoinLinkPeer, linkPeerPublicKey, linkEndpointHost, linkServicePort),
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

// TestControllerLinkPlansRefuseEveryRequestOutsideTheContract is the hostile
// surface of the three endpoints. None of these may produce bytes a human could
// be asked to approve.
//
// The requests that carry a field of another operation group are the point of the
// three sibling routes: they are refused as unknown fields of the schema the route
// declares, before any of their values is read. The requests that name a constant
// of the reference scenario are the point of the contract: an approvable value
// that could widen the passage does not exist.
func TestControllerLinkPlansRefuseEveryRequestOutsideTheContract(t *testing.T) {
	fixture := newControllerHTTPFixture(t)
	attachProbeMachine(t, fixture, "lab-machine-1")
	bearer := "Bearer " + fixture.token

	for name, check := range map[string]struct {
		route  string
		body   string
		status int
		code   string
	}{
		"a link plan of schema 2": {"/v0/link-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan of schema 1": {"/v0/link-plans",
			`{"schema_version":1,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan choosing its infrastructure": {"/v0/link-plans",
			`{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan choosing an interface": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener","interface":"yc-link1"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan choosing a listening port": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener","listen_port":51821}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan choosing a tunnel address": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener","address":"10.66.66.3/32"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan carrying a private key": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener","private_key":"` + linkPeerPublicKey + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan carrying a peer key": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener","peer_public_key":"` + linkPeerPublicKey + `"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan carrying a service port": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener","service_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan repeating a field": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","machine_id":"lab-machine-2","operation":"prepare_link","link_role":"listener"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan on an unknown role": {"/v0/link-plans",
			linkPlanBody("lab-machine-1", plan.OperationPrepareLink, "relay"),
			http.StatusBadRequest, "invalid_request"},
		"a link plan on an upper-case role": {"/v0/link-plans",
			linkPlanBody("lab-machine-1", plan.OperationPrepareLink, "Listener"),
			http.StatusBadRequest, "invalid_request"},
		"a link plan without a role": {"/v0/link-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"prepare_link"}`,
			http.StatusBadRequest, "invalid_request"},
		"a link plan on a junction operation": {"/v0/link-plans",
			linkPlanBody("lab-machine-1", plan.OperationAttachLinkPeer, plan.LinkRoleListener),
			http.StatusBadRequest, "invalid_request"},
		"a link plan on a schema 2 operation": {"/v0/link-plans",
			linkPlanBody("lab-machine-1", plan.OperationDeployEntrypoint, plan.LinkRoleListener),
			http.StatusBadRequest, "invalid_request"},
		"a link plan on a traversal machine": {"/v0/link-plans",
			linkPlanBody("../../etc/shadow", plan.OperationPrepareLink, plan.LinkRoleListener),
			http.StatusBadRequest, "invalid_request"},
		"a link plan on a machine this Controller does not know": {"/v0/link-plans",
			linkPlanBody("lab-machine-2", plan.OperationPrepareLink, plan.LinkRoleListener),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"a listener plan of schema 2": {"/v0/listener-peer-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"attach_link_peer","peer_public_key":"` + linkPeerPublicKey + `","service_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a listener plan carrying an endpoint": {"/v0/listener-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"attach_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","peer_endpoint_host":"` + linkEndpointHost + `","service_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a listener plan carrying a role": {"/v0/listener-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"attach_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","service_port":8080,"link_role":"listener"}`,
			http.StatusBadRequest, "invalid_request"},
		"a listener plan carrying allowed IPs": {"/v0/listener-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"attach_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","service_port":8080,"allowed_ips":["0.0.0.0/0"]}`,
			http.StatusBadRequest, "invalid_request"},
		"a listener plan carrying a route host": {"/v0/listener-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"attach_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","service_port":8080,"route_host":"evil.test"}`,
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on an unpadded key": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer,
				strings.TrimSuffix(linkPeerPublicKey, "="), linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on a URL-alphabet key": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer,
				strings.Replace(linkPeerPublicKey, "HB0e", "HB0_", 1), linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on non-zero trailing bits": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer,
				strings.Replace(linkPeerPublicKey, "HyA=", "HyB=", 1), linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on a short key": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer, "AQID", linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan without a key": {"/v0/listener-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"attach_link_peer","service_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on a privileged port": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer, linkPeerPublicKey, 443),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan beyond the service range": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationAttachLinkPeer, linkPeerPublicKey, 65536),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on an initiator operation": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer, linkPeerPublicKey, linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"a listener plan on a machine this Controller does not know": {"/v0/listener-peer-plans",
			listenerPeerPlanBody("lab-machine-2", plan.OperationAttachLinkPeer, linkPeerPublicKey, linkServicePort),
			http.StatusUnprocessableEntity, "machine_not_active"},

		"an initiator plan of schema 2": {"/v0/initiator-peer-plans",
			`{"schema_version":2,"machine_id":"lab-machine-1","operation":"join_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","peer_endpoint_host":"` + linkEndpointHost + `","service_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan choosing an endpoint port": {"/v0/initiator-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"join_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","peer_endpoint_host":"` + linkEndpointHost + `","service_port":8080,"peer_endpoint_port":51821}`,
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan choosing a keepalive": {"/v0/initiator-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"join_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","peer_endpoint_host":"` + linkEndpointHost + `","service_port":8080,"keepalive_seconds":0}`,
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan carrying a role": {"/v0/initiator-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"join_link_peer","peer_public_key":"` + linkPeerPublicKey +
				`","peer_endpoint_host":"` + linkEndpointHost + `","service_port":8080,"link_role":"initiator"}`,
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan without an endpoint": {"/v0/initiator-peer-plans",
			`{"schema_version":3,"machine_id":"lab-machine-1","operation":"join_link_peer","peer_public_key":"` + linkPeerPublicKey + `","service_port":8080}`,
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on a wildcard endpoint": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer, linkPeerPublicKey,
				"*.lab.your-cloud.test", linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on an upper-case endpoint": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer, linkPeerPublicKey,
				"VPS.lab.your-cloud.test", linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on an endpoint carrying a port": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer, linkPeerPublicKey,
				"vps.lab.your-cloud.test:51820", linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on an endpoint with an empty label": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer, linkPeerPublicKey,
				"vps..lab.your-cloud.test", linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on a listener operation": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-1", plan.OperationDetachLinkPeer, linkPeerPublicKey,
				linkEndpointHost, linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on a link operation": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-1", plan.OperationPrepareLink, linkPeerPublicKey,
				linkEndpointHost, linkServicePort),
			http.StatusBadRequest, "invalid_request"},
		"an initiator plan on a machine this Controller does not know": {"/v0/initiator-peer-plans",
			initiatorPeerPlanBody("lab-machine-2", plan.OperationJoinLinkPeer, linkPeerPublicKey,
				linkEndpointHost, linkServicePort),
			http.StatusUnprocessableEntity, "machine_not_active"},
	} {
		response := fixture.request(http.MethodPost, check.route, check.body,
			"application/json", bearer, fixture.certificate)
		if response.Code != check.status || !strings.Contains(response.Body.String(), `"error_code":"`+check.code+`"`) {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	oversized := initiatorPeerPlanBody("lab-machine-1", plan.OperationJoinLinkPeer,
		linkPeerPublicKey, strings.Repeat("a", 5000), linkServicePort)
	if response := fixture.request(http.MethodPost, "/v0/initiator-peer-plans", oversized,
		"application/json", bearer, fixture.certificate); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d body=%s", response.Code, response.Body.String())
	}
}
