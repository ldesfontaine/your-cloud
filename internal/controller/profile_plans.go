package controller

import (
	"crypto/x509"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// The three requests below are everything the Console may choose about a plan of
// the public profile, one closed schema per operation group.
//
// Three sibling routes rather than one route carrying a discriminator is the
// same decision the plan documents themselves take: a single request schema
// would have to declare every field of every group and decide afterwards which
// of them were allowed, so a route host smuggled into a service request would be
// a value the Controller reads before refusing it. Held apart, each request is a
// closed field list, and a field belonging to another group is refused by the
// strict decoding before its value is read.
//
// None of them can choose the infrastructure, the image or the digest: the
// infrastructure is the one this Controller is the authority for, and the images
// are the ones the palier pins. A request that could name them would be a request
// that could aim an approval at another installation or at another image, and the
// human reading the plan would have no way to tell.

// webServicePlanRequest names one managed service instance: which profile, and
// which loopback port it listens on.
type webServicePlanRequest struct {
	SchemaVersion  int    `json:"schema_version"`
	MachineID      string `json:"machine_id"`
	Operation      string `json:"operation"`
	ServiceProfile string `json:"service_profile"`
	LocalPort      int    `json:"local_port"`
}

// entrypointPlanRequest names nothing beyond the machine and the direction. The
// public ports, the listening addresses and the file provider directory are
// constants of the contract, so an entrypoint request has no field for them.
type entrypointPlanRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Operation     string `json:"operation"`
}

// routePlanRequest names one declared host and the loopback port behind it.
type routePlanRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Operation     string `json:"operation"`
	RouteHost     string `json:"route_host"`
	BackendPort   int    `json:"backend_port"`
}

// PlanPairView is the frozen pair the Console signs over, and it is the same
// shape for every plan route of schemas 2 and 3: what differs between them is
// what a human approves, not how the bytes travel. Its schema_version says which
// contract the two documents were written in, so a Console never has to guess it
// from their content.
//
// The two documents travel as their exact canonical bytes rather than as nested
// objects, so that the Console does not have to own a canonical encoder to obtain
// the bytes the digests were taken over. What it displays, what it hashes and
// what the Auxiliary later receives are then the same bytes rather than three
// encodings that happen to agree.
//
// The digests are carried beside the documents for the envelope to name; they are
// not an authority. A Console that trusted them rather than recomputing them from
// the documents it displays would be trusting the Controller to describe what the
// human is approving.
type PlanPairView struct {
	SchemaVersion    int    `json:"schema_version"`
	PlanDocument     string `json:"plan_document"`
	PlanSHA256       string `json:"plan_sha256"`
	RollbackDocument string `json:"rollback_document"`
	RollbackSHA256   string `json:"rollback_sha256"`
}

// serveWebServicePlans builds one managed service plan and its rollback.
//
// Like every plan route, it holds no power beyond that: the Controller freezes
// bytes and cannot sign them, and the Auxiliary re-derives every meaning of these
// documents from its own root-owned anchors before touching the machine.
func (handler *ControllerHandler) serveWebServicePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body webServicePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildWebServicePair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.ServiceProfile, body.LocalPort)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}

// serveEntrypointPlans builds the plan of the public entrypoint and its removal.
func (handler *ControllerHandler) serveEntrypointPlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body entrypointPlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildEntrypointPair(body.Operation, inventory.InfrastructureID, body.MachineID)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}

// serveRoutePlans builds the plan of one published name and its retirement.
func (handler *ControllerHandler) serveRoutePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body routePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildRoutePair(body.Operation, inventory.InfrastructureID,
		body.MachineID, body.RouteHost, body.BackendPort)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}

// freezablePair is what a plan route hands to the one exit below: a pair that
// renders itself once, documents and digests together. Both the schema 2 and the
// schema 3 pairs answer it, so neither schema owns a second way out of this
// Controller.
type freezablePair interface {
	Freeze() (plan.Frozen, error)
}

// writeFrozenPair is the one exit of every profile and passage plan route, so
// that none of them can answer under rules the others do not apply.
//
// The inventory is the only place this Controller knows an enrolled machine by
// name. A machine enters it only through an attachment that required a fresh
// authenticated Relay read naming it active, so membership here is a past proof
// of enrolment rather than a present one. That is deliberate: a plan is a
// description, not a mutation, and making its construction depend on the Relay
// being reachable would add a failure mode without adding any authority the
// Auxiliary does not re-establish locally before acting.
func (handler *ControllerHandler) writeFrozenPair(
	response http.ResponseWriter,
	context SessionContext,
	inventory Inventory,
	machineID string,
	schemaVersion int,
	pair freezablePair,
) {
	if !attachedMachine(inventory, machineID) {
		handler.writeProblem(response, http.StatusUnprocessableEntity, "machine_not_active", 0)
		return
	}
	frozen, err := pair.Freeze()
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	handler.writeAccepted(response, context, http.StatusOK, PlanPairView{
		SchemaVersion:    schemaVersion,
		PlanDocument:     string(frozen.PlanDocument),
		PlanSHA256:       frozen.PlanSHA256,
		RollbackDocument: string(frozen.RollbackDocument),
		RollbackSHA256:   frozen.RollbackSHA256,
	})
}
