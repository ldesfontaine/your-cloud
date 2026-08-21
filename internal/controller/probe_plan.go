package controller

import (
	"crypto/x509"
	"net/http"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// probePlanRequest is everything the App may choose about a probe plan.
//
// It cannot choose the infrastructure, the image or the digest: the
// infrastructure is the one this Controller is the authority for, and the image
// is the single probe the palier pins. A request that could name them would be
// a request that could aim an approval at another installation or at another
// image, and the human reading the plan would have no way to tell.
type probePlanRequest struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Operation     string `json:"operation"`
	LocalPort     int    `json:"local_port"`
}

// ProbePlanView is the frozen pair the App signs over.
//
// The two documents travel as their exact canonical bytes rather than as nested
// objects, so that the App does not have to own a canonical encoder to
// obtain the bytes the digests were taken over. What it displays, what it
// hashes and what the Auxiliary later receives are then the same bytes rather
// than three encodings that happen to agree.
//
// The digests are carried beside the documents for the envelope to name; they
// are not an authority. An App that trusted them rather than recomputing
// them from the documents it displays would be trusting the Controller to
// describe what the human is approving.
type ProbePlanView struct {
	SchemaVersion    int    `json:"schema_version"`
	PlanDocument     string `json:"plan_document"`
	PlanSHA256       string `json:"plan_sha256"`
	RollbackDocument string `json:"rollback_document"`
	RollbackSHA256   string `json:"rollback_sha256"`
}

// serveProbePlans builds one plan and its rollback, and holds no power beyond
// that.
//
// The Controller freezes bytes. It cannot sign them: no approval key exists on
// this side of the product, so a compromised Controller can propose a plan and
// can never approve one. It also cannot make a plan act — the Auxiliary
// re-derives every meaning of these documents from its own root-owned anchors
// before touching the machine, and refuses them when their digests are not the
// ones a human signed.
func (handler *ControllerHandler) serveProbePlans(response http.ResponseWriter, request *http.Request, certificate *x509.Certificate) {
	context, ok := handler.authenticateSession(response, request, certificate)
	if !ok {
		return
	}
	var body probePlanRequest
	if !handler.decodeJSON(response, request, &body) {
		return
	}
	if body.SchemaVersion != 1 {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	inventory := handler.inventory.Snapshot()
	pair, err := plan.BuildPair(body.Operation, inventory.InfrastructureID, body.MachineID, body.LocalPort)
	if err != nil {
		handler.writeProblem(response, http.StatusBadRequest, "invalid_request", 0)
		return
	}
	// The inventory is the only place this Controller knows an enrolled machine
	// by name. A machine enters it only through an attachment that required a
	// fresh authenticated Relay read naming it active, so membership here is a
	// past proof of enrolment rather than a present one. That is deliberate: a
	// plan is a description, not a mutation, and making its construction depend
	// on the Relay being reachable would add a failure mode without adding any
	// authority the Auxiliary does not re-establish locally before acting.
	if !attachedMachine(inventory, body.MachineID) {
		handler.writeProblem(response, http.StatusUnprocessableEntity, "machine_not_active", 0)
		return
	}
	frozen, err := pair.Freeze()
	if err != nil {
		handler.writeProblem(response, http.StatusServiceUnavailable, "controller_state_unavailable", 0)
		return
	}
	handler.writeAccepted(response, context, http.StatusOK, ProbePlanView{
		SchemaVersion:    1,
		PlanDocument:     string(frozen.PlanDocument),
		PlanSHA256:       frozen.PlanSHA256,
		RollbackDocument: string(frozen.RollbackDocument),
		RollbackSHA256:   frozen.RollbackSHA256,
	})
}

func attachedMachine(inventory Inventory, machineID string) bool {
	for _, machine := range inventory.Machines {
		if machine.MachineID == machineID {
			return true
		}
	}
	return false
}
