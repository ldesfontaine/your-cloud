package auxiliary

// This file is the dispatch of the two plan schemas: which decoder a carried
// pair reaches, what happens when the two documents do not agree on one, and
// which schema 2 operations this Auxiliary performs rather than merely reads.
//
// The rule it holds is narrow on purpose. Adding schema 2 to this Auxiliary
// widens what it performs by exactly the two managed web service operations. The
// four entrypoint and route operations stay refused by name, before any effect
// and before this machine is even read, until the issue that owns them lands —
// and that refusal is an ordinary refusal, never a controlled failure, because
// nothing was touched and there is nothing to have undone.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestASchemaTwoServicePlanReachesTheGeneralisedDeployment is the result this
// issue owes: a schema 2 document describing the managed web service profile is
// applied through the very machinery the probe uses, against the profile's own
// account, sheet, container and pinned image.
func TestASchemaTwoServicePlanReachesTheGeneralisedDeployment(t *testing.T) {
	t.Parallel()
	executor := newFakeExecutor()
	executor.afterAccount = &Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
		AccountPresent:         true,
		RootlessPodman:         true,
	}
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal service deployment was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first service application announced no change: %+v", application)
	}
	if application.Operation != plan.OperationDeployWebService || application.LocalPort != fixturePort {
		t.Fatalf("the application named another instance: %+v", application)
	}

	// The order is the same argument as for the probe, and the names are the
	// profile's rather than the probe's: nothing of this operation touched the
	// account, the sheet or the container the previous palier owns.
	expected := []string{
		"CreateProbeAccount", "EnableLinger", "PullImage",
		"WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if application.UnitPath != bentoPDFPlacement.unitPath() || application.UnitPath == UnitPath() {
		t.Fatalf("the service was written where the probe lives: %q", application.UnitPath)
	}
	if len(executor.accountsCreated) != 1 || executor.accountsCreated[0] != BentoPDFAccount+" "+BentoPDFHome {
		t.Fatalf("another account than the profile's was created: %v", executor.accountsCreated)
	}
	if len(executor.lingeringAccounts) != 1 || executor.lingeringAccounts[0] != BentoPDFAccount {
		t.Fatalf("the service account cannot survive without a session: %v", executor.lingeringAccounts)
	}
	if len(executor.pulled) != 1 || executor.pulled[0] != bentoPDFPlacement.image {
		t.Fatalf("another image than the profile's pin was fetched: %v", executor.pulled)
	}
	// The local verification is the profile's: the loopback port a human
	// approved, and the one invariant beyond the status that this profile asks
	// for.
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the announced state was not verified locally: %v", executor.probedPorts)
	}
	if len(executor.probedContentTypes) != 1 || executor.probedContentTypes[0] != contentTypeHTMLDocument {
		t.Fatalf("the local verification asked for another answer: %v", executor.probedContentTypes)
	}
	// The sheet is the profile's, published on the port the image listens on and
	// carrying no low-port sysctl, because this image listens above 1024.
	sheet := string(executor.writtenUnit)
	for _, line := range []string{
		"Image=" + plan.BentoPDFImageReference + "@" + plan.BentoPDFImageDigest,
		"ContainerName=" + BentoPDFAccount,
		"PublishPort=127.0.0.1:8080:8080",
		"Pull=never",
		"ReadOnly=true",
		"NoNewPrivileges=true",
		"DropCapability=ALL",
	} {
		if !strings.Contains(sheet, line) {
			t.Fatalf("the service sheet does not declare %q:\n%s", line, sheet)
		}
	}
	if strings.Contains(sheet, "Sysctl=") {
		t.Fatalf("the service sheet carries a sysctl its image does not need:\n%s", sheet)
	}
}

// TestASchemaTwoServiceRemovalTakesTheProfileAwayAndNothingElse is the other
// half of the same dispatch, with the same effect list a probe removal has and
// none of the probe's names.
func TestASchemaTwoServiceRemovalTakesTheProfileAwayAndNothingElse(t *testing.T) {
	t.Parallel()
	executor := deployedServiceMachine(t, fixturePort)
	accepted, input := approvedService(t, plan.OperationRemoveWebService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("removing a present service was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the removal announced the wrong state: %+v", application)
	}
	expected := []string{"StopService", "RemoveUnitFile", "ReloadUserUnits", "RemoveImage"}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if len(executor.removedImages) != 1 || executor.removedImages[0] != bentoPDFPlacement.image {
		t.Fatalf("another image than the profile's pin was removed: %v", executor.removedImages)
	}
	if executor.unitPresent || executor.active || executor.image != "" {
		t.Fatalf("the machine still holds part of the service: %+v", executor)
	}
}

// TestAPairWrittenInTwoSchemasIsNotAPair holds the gate that keeps the two
// decoders from covering for one another.
//
// The refusal happens on what the two documents declare, before either is held
// against the digest an approval signed — so a Controller that pairs a probe
// plan with a service rollback is refused for mixing them rather than for
// happening to hash differently.
func TestAPairWrittenInTwoSchemasIsNotAPair(t *testing.T) {
	t.Parallel()
	probe := frozenPair(t, plan.OperationDeployOCIProbe, fixturePort)
	service := frozenServicePair(t, plan.OperationDeployWebService, plan.ServiceProfileBentoPDF, fixturePort)

	for name, mixed := range map[string]plan.Frozen{
		"a schema 1 plan undone by a schema 2 rollback": {
			PlanDocument:     probe.PlanDocument,
			PlanSHA256:       probe.PlanSHA256,
			RollbackDocument: service.RollbackDocument,
			RollbackSHA256:   service.RollbackSHA256,
		},
		"a schema 2 plan undone by a schema 1 rollback": {
			PlanDocument:     service.PlanDocument,
			PlanSHA256:       service.PlanSHA256,
			RollbackDocument: probe.RollbackDocument,
			RollbackSHA256:   probe.RollbackSHA256,
		},
	} {
		executor := deployedServiceMachine(t, fixturePort)
		accepted, input := approvedFrozenPair(plan.OperationDeployWebService, mixed)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), "a pair written in two schemas is not a pair") {
			t.Fatalf("%s was refused for another reason than its own: %v", name, err)
		}
		if len(executor.effects) != 0 || len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine: %q %q", name, executor.effects, executor.reads)
		}
	}
}

// TestASchemaThisAuxiliaryDoesNotReadIsRefusedByName keeps the dispatch closed
// at both ends: a document declaring a schema neither decoder owns is refused
// before either of them is asked to try.
func TestASchemaThisAuxiliaryDoesNotReadIsRefusedByName(t *testing.T) {
	t.Parallel()
	executor := deployedServiceMachine(t, fixturePort)
	accepted, input := approvedService(t, plan.OperationDeployWebService, fixturePort)
	input.PlanDocument = forgedServicePlan(t, plan.OperationDeployWebService, fixturePort, map[string]string{
		"schema_version": "3",
	})
	input.RollbackDocument = forgedServicePlan(t, plan.OperationRemoveWebService, fixturePort, map[string]string{
		"schema_version": "3",
	})

	if _, err := Apply(executor, accepted, input); err == nil {
		t.Fatal("a plan schema this Auxiliary does not read was accepted")
	} else if !strings.Contains(err.Error(), "which this Auxiliary does not read") {
		t.Fatalf("an unknown plan schema was refused for another reason: %v", err)
	}
	if len(executor.effects) != 0 || len(executor.reads) != 0 {
		t.Fatalf("an unknown plan schema reached the machine: %q %q", executor.effects, executor.reads)
	}
}

// TestTheEntrypointAndRouteOperationsAreRefusedByNameAndNotPerformed is the
// window this issue deliberately leaves closed.
//
// The four operations are valid schema 2 plans: they decode, they validate, they
// hash to what the approval signed and they target this machine. What refuses
// them is this Auxiliary saying it does not perform them yet — by name, before
// any effect and before any read — and the refusal is an ordinary error rather
// than a controlled failure, because a run that touched nothing has nothing to
// have undone.
func TestTheEntrypointAndRouteOperationsAreRefusedByNameAndNotPerformed(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		operation string
		frozen    func(*testing.T) plan.Frozen
	}{
		{plan.OperationDeployEntrypoint, func(t *testing.T) plan.Frozen {
			return frozenEntrypointPair(t, plan.OperationDeployEntrypoint)
		}},
		{plan.OperationRemoveEntrypoint, func(t *testing.T) plan.Frozen {
			return frozenEntrypointPair(t, plan.OperationRemoveEntrypoint)
		}},
		{plan.OperationPublishRoute, func(t *testing.T) plan.Frozen {
			return frozenRoutePair(t, plan.OperationPublishRoute, fixturePort)
		}},
		{plan.OperationRetireRoute, func(t *testing.T) plan.Frozen {
			return frozenRoutePair(t, plan.OperationRetireRoute, fixturePort)
		}},
	} {
		executor := deployedServiceMachine(t, fixturePort)
		accepted, input := approvedFrozenPair(subject.operation, subject.frozen(t))

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was performed by an Auxiliary that does not perform it", subject.operation)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", subject.operation, application)
		}
		// The refusal names the operation, so a reader learns which one is not
		// performed rather than that "something" was refused.
		if !strings.Contains(err.Error(), subject.operation) ||
			!strings.Contains(err.Error(), "does not perform yet") {
			t.Fatalf("%s was refused without being named: %v", subject.operation, err)
		}
		var controlled *ControlledFailure
		if errors.As(err, &controlled) {
			t.Fatalf("%s was reported as a controlled failure: %v", subject.operation, err)
		}
		if len(executor.effects) != 0 {
			t.Fatalf("%s changed the machine before being refused: %q", subject.operation, executor.effects)
		}
		if len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine before being refused: %q", subject.operation, executor.reads)
		}
	}
}
