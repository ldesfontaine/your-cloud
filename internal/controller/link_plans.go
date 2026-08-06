package controller

import (
	"crypto/x509"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// The three requests below are everything the Console may choose about a plan of
// the private passage, one closed schema per operation group.
//
// Three sibling routes rather than one route carrying a role and a phase is the
// decision the public profile already took, for the reason the plan documents
// themselves take it: a single request schema would have to declare every field
// of every group and decide afterwards which of them were allowed, so an
// endpoint host smuggled into a listener request would be a value the Controller
// reads before refusing it. Held apart, each request is a closed field list, and
// a field belonging to another group is refused by the strict decoding before its
// value is read.
//
// The asymmetry of the passage is in the routes for the same reason it is in the
// operations: the listener has no endpoint to reach, so the route that builds its
// junction has no field for one — not an empty field, and not a field a role
// would decide the meaning of.
//
// None of them can choose the infrastructure, the tunnel addresses, the interface,
// the listening port or the keepalive: the infrastructure is the one this
// Controller is the authority for, and the rest are constants the role decides. A
// request that could name them would be a request that could aim an approval at
// another installation or widen the passage past what the contract bounds, and the
// human reading the plan would have no way to tell.

// linkPlanRequest names one machine's own side of the passage: which role, and
// nothing else.
type linkPlanRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Operation     string `json:"operation"`
	LinkRole      string `json:"link_role"`
}

// listenerPeerPlanRequest names the peer the listener joins and the one port the
// passage will carry.
//
// The peer key is the one value here that nobody chose: it is an observation the
// other machine's preparation reported, carried by the Console into this request
// so that the human approves a plan naming exactly the peer they accept. It is
// held against exactly the canonicity the document validation requires, and by
// that validation rather than beside it — a key this route accepted and the plan
// package refused would be a refusal arriving one layer too late.
type listenerPeerPlanRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Operation     string `json:"operation"`
	PeerPublicKey string `json:"peer_public_key"`
	ServicePort   int    `json:"service_port"`
}

// initiatorPeerPlanRequest names the same peer and port, plus the one host the
// initiator reaches. The endpoint port is not a field: it is the listening port
// of the contract.
type initiatorPeerPlanRequest struct {
	SchemaVersion    int    `json:"schema_version"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	PeerPublicKey    string `json:"peer_public_key"`
	PeerEndpointHost string `json:"peer_endpoint_host"`
	ServicePort      int    `json:"service_port"`
}

// serveLinkPlans builds the plan of one machine's own side of the passage and its
// withdrawal.
//
// Like every plan route, it holds no power beyond that: the Controller freezes
// bytes and cannot sign them, and the Auxiliary re-derives every meaning of these
// documents from its own root-owned anchors before touching the machine. It
// generates no key and carries none — the private key of a passage is born on its
// own machine and never leaves it, so nothing here could transport one.
func (handler *ControllerHandler) serveLinkPlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body linkPlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV3 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildLinkPair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.LinkRole)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV3, pair)
}

// serveListenerPeerPlans builds the listener's junction and its detachment.
func (handler *ControllerHandler) serveListenerPeerPlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body listenerPeerPlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV3 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildListenerPeerPair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.PeerPublicKey, body.ServicePort)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV3, pair)
}

// serveInitiatorPeerPlans builds the initiator's junction and its departure.
func (handler *ControllerHandler) serveInitiatorPeerPlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body initiatorPeerPlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV3 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildInitiatorPeerPair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.PeerPublicKey, body.PeerEndpointHost, body.ServicePort)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV3, pair)
}
