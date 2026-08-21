package controller

import (
	"crypto/x509"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// The request below is everything the App may choose about a plan of the
// third door, and it is one route rather than two: the two operations of this
// door carry one closed field list, exactly as the two operations of every other
// service group do, so the direction is a field of the request and not a route of
// its own. What earns a sibling route in this Controller is a second field list,
// never a second direction.
//
// It cannot choose the infrastructure, the slug's account, the home, a host path,
// a secret value or the egress table: the infrastructure is the one this
// Controller is the authority for, and everything touching the machine is derived
// from the slug by the Auxiliary. It cannot choose the repository either — that is
// the pinned definition's, read out of it here — and it names the image digest
// because the digest is the one thing about a user service that a revision
// deliberately does not fix: an update is a new plan whose digest differs.
//
// The two definition fields are spelled as the plan spells them rather than as
// the freezing route spells them. Every other field of a plan request is the
// value the plan document will carry under the plan document's own name, and
// these two are no different: what the App pastes here is what it will read
// back inside the document it displays.

// userServicePlanRequest names one instance of one frozen definition: which
// revision it runs, which image, which loopback port, and the origin it answers
// under when its definition consumes one.
type userServicePlanRequest struct {
	SchemaVersion    int    `json:"schema_version"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	DefinitionSlug   string `json:"definition_slug"`
	DefinitionDigest string `json:"definition_digest"`
	ImageDigest      string `json:"image_digest"`
	LocalPort        int    `json:"local_port"`
	OriginHost       string `json:"origin_host"`
}

// serveUserServicePlans builds one user service plan and its rollback, from a
// definition this Controller has already frozen.
//
// The lookup comes before anything else a plan needs, and it is the whole of what
// this route adds to the pattern the other plan routes follow: a definition this
// Controller never froze is not a plan it can build, because there would be no
// document behind the digest a human is asked to approve and no repository to
// name. The refusal is a lookup that fails on the pair (slug, digest) — which is
// also, without a comparison anyone had to write, the refusal a delivered profile
// receives here: `bentopdf` and `vaultwarden` are names no definition may take, so
// no revision was ever frozen under them and no plan of this door can name one.
//
// Everything the definition decides is read out of the definition and never out
// of the request, and the cross-checks the contract names — the repository, and
// the presence of the origin — are held by the plan package with the definition in
// hand. The Auxiliary re-holds them from the definition's own bytes before
// touching the machine; this Controller is trusted for none of it.
//
// Like every plan route, it holds no power beyond freezing bytes: it cannot sign
// them, and it mutates no machine.
func (handler *ControllerHandler) serveUserServicePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body userServicePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != plan.SchemaVersionV2 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	definition, frozen := handler.definitions.FrozenDefinition(body.DefinitionSlug, body.DefinitionDigest)
	if !frozen {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildUserServicePair(body.Operation, inventory.InfrastructureID,
		body.MachineID, definition, body.ImageDigest, body.LocalPort, body.OriginHost)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	handler.writeFrozenPair(response, context, inventory, body.MachineID, plan.SchemaVersionV2, pair)
}
