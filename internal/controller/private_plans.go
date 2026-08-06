package controller

import (
	"crypto/x509"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// The four requests below are everything the Console may choose about a plan of
// the private profile, one closed schema per operation group.
//
// Four sibling routes rather than one route carrying a discriminator is the
// decision the public profile and the private passage already took, for the
// reason the plan documents themselves take it: a single request schema would
// have to declare every field of every group and decide afterwards which of them
// were allowed, so a snapshot slot smuggled into a deployment request would be a
// value the Controller reads before refusing it. Held apart, each request is a
// closed field list, and a field belonging to another group is refused by the
// strict decoding before its value is read.
//
// Two of these groups carry exactly the fields a group of an older palier
// carries — a link route names a host and a port as a public route does, a
// restore names a profile and a slot as a snapshot does. They are still separate
// routes, because they build separate plans: the two documents describe different
// states and hash differently, and a route that decided between them from a flag
// would be a route where the human's choice becomes a value someone has to read
// correctly.
//
// None of them can choose the infrastructure, the image, the digest, the
// persistent volume, the environment lines, the egress table or the tunnel's peer
// address: the infrastructure is the one this Controller is the authority for,
// and the rest are constants the profile and the passage decide. A request that
// could name them would be a request that could aim an approval at another
// installation, at another image, or at a path a machine would then write to —
// and the human reading the plan would have no way to tell.

// privateServicePlanRequest names one data-bearing service instance: which
// profile, which loopback port it listens on, and the one origin it answers
// under.
//
// The origin is here and the route is not. Publishing is a separate, optional
// plan, and a private service deployed without one lives on its own machine's
// loopback for as long as its owner wants; the origin still has to be named,
// because the instance must know who it is on the day a route arrives.
type privateServicePlanRequest struct {
	SchemaVersion  int    `json:"schema_version"`
	MachineID      string `json:"machine_id"`
	Operation      string `json:"operation"`
	ServiceProfile string `json:"service_profile"`
	LocalPort      int    `json:"local_port"`
	OriginHost     string `json:"origin_host"`
}

// linkRoutePlanRequest names one declared host and the port the passage carries
// behind it. There is no field for the backend address: it is the constant peer
// of the tunnel, and a request that could name one could point the entrypoint
// anywhere.
type linkRoutePlanRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Operation     string `json:"operation"`
	RouteHost     string `json:"route_host"`
	BackendPort   int    `json:"backend_port"`
}

// snapshotPlanRequest names which service's data is archived and the one slot
// the archive is written to or destroyed from.
type snapshotPlanRequest struct {
	SchemaVersion  int    `json:"schema_version"`
	MachineID      string `json:"machine_id"`
	Operation      string `json:"operation"`
	ServiceProfile string `json:"service_profile"`
	SnapshotSlot   string `json:"snapshot_slot"`
}

// restorePlanRequest names which service returns and which slot it returns from.
//
// It carries no operation. A restore has one direction, so a field for it would
// be an approvable value that may only hold one value; and the document that
// undoes it is not a second choice either — it is a restore of the reserved slot,
// which the plan package builds and which no request may name.
type restorePlanRequest struct {
	SchemaVersion  int    `json:"schema_version"`
	MachineID      string `json:"machine_id"`
	ServiceProfile string `json:"service_profile"`
	SnapshotSlot   string `json:"snapshot_slot"`
}

// servePrivateServicePlans builds one data-bearing service plan and its rollback.
//
// Like every plan route, it holds no power beyond that: the Controller freezes
// bytes and cannot sign them, and the Auxiliary re-derives every meaning of these
// documents from its own root-owned anchors before touching the machine.
func (handler *ControllerHandler) servePrivateServicePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body privateServicePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildPrivateServicePair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.ServiceProfile, body.LocalPort, body.OriginHost)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}

// serveLinkRoutePlans builds the plan of one name published through the passage
// and its retirement.
func (handler *ControllerHandler) serveLinkRoutePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body linkRoutePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildLinkRoutePair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.RouteHost, body.BackendPort)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}

// serveSnapshotPlans builds the plan of one archive and its destruction.
func (handler *ControllerHandler) serveSnapshotPlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body snapshotPlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildSnapshotPair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.ServiceProfile, body.SnapshotSlot)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}

// serveRestorePlans builds the plan of one return and the document that returns
// from it.
//
// The rollback is the one document of the product naming the reserved slot, and
// this Controller does not write it: the plan package does, from the request's own
// profile and machine. That is deliberate — the slot the return mechanism owns is
// never a value a request carries, not even indirectly.
func (handler *ControllerHandler) serveRestorePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body restorePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildRestorePair(inventory.InfrastructureID,
		body.MachineID, body.ServiceProfile, body.SnapshotSlot)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}
