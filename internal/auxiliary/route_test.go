package auxiliary

// This file holds for one published route what entrypoint_test.go holds for the
// entry: what publishing and retiring actually touch, idempotence and drift
// computed against the file rather than against a memory, the two refusals a
// route owes before any effect, and the rollback conduct inherited whole.
//
// The property every case here is really about is narrowness. A route is one
// file. Publishing writes that file and nothing else; retiring removes that file
// and nothing else; and neither of them stops, restarts or rewrites the entry,
// the other routes or the service the route names.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestPublishingARouteWritesExactlyOneFragmentAndVerifiesIt is the result this
// issue owes for a route.
func TestPublishingARouteWritesExactlyOneFragmentAndVerifiesIt(t *testing.T) {
	t.Parallel()
	executor := routableMachine(fixturePort)
	accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal route publication was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first route application announced no change: %+v", application)
	}
	if application.RouteHost != fixtureRouteHost ||
		application.FragmentPath != entrypointFragmentDirectory+"/"+fixtureRouteHost+".yaml" {
		t.Fatalf("the application named another route: %+v", application)
	}
	// A route has no sheet and no loopback port of its own to announce: the port
	// it names belongs to the service another plan deployed.
	if application.UnitPath != "" || application.LocalPort != 0 {
		t.Fatalf("the route named something a route does not have: %+v", application)
	}

	// One effect, and it is the fragment. Nothing was reloaded, nothing was
	// restarted and nothing of the entry was rewritten: the entry watches the
	// directory, so a route is published by the file existing.
	if strings.Join(executor.effects, ",") != "WriteUnitFile" {
		t.Fatalf("publishing a route did more than write its fragment: %q", executor.effects)
	}
	if strings.Join(executor.writtenPaths, ",") != routeFragmentPath(fixtureRouteHost) {
		t.Fatalf("publishing a route wrote elsewhere: %q", executor.writtenPaths)
	}
	if string(executor.held(routeFragmentPath(fixtureRouteHost))) !=
		string(renderRouteFragment(fixtureRouteHost, fixturePort)) {
		t.Fatal("the machine does not hold the fragment this plan describes")
	}
	// The entry's own sheet and the service's sheet are exactly as they were.
	if string(executor.held(entrypointPlacement.unitPath())) != string(renderEntrypointSheet()) ||
		string(executor.held(bentoPDFPlacement.unitPath())) != string(renderSheet(bentoPDFPlacement, fixturePort, "")) {
		t.Fatal("publishing a route rewrote something a route does not own")
	}
	// And the announced state was proven rather than assumed, for this name and
	// for no other.
	if len(executor.verifiedRoutes) != 1 || executor.verifiedRoutes[0] != fixtureRouteHost {
		t.Fatalf("the published route was not verified locally: %v", executor.verifiedRoutes)
	}
	if executor.entrypointChecks != 0 {
		t.Fatal("publishing a route re-verified the entry it did not touch")
	}
}

// TestARouteFragmentDeclaresTheContractAndNothingElse reads the fragment the way
// a reviewer reads it: every line is something the contract asks for, and the
// values a plan carries are the only two that vary.
func TestARouteFragmentDeclaresTheContractAndNothingElse(t *testing.T) {
	t.Parallel()
	fragment := string(renderRouteFragment(fixtureRouteHost, fixturePort))

	for _, line := range []string{
		"rule: \"Host(`" + fixtureRouteHost + "`)\"",
		"- websecure",
		"tls: {}",
		"- url: \"http://" + entrypointHostLoopbackAddress + ":8080\"",
		"Cross-Origin-Opener-Policy: \"same-origin\"",
		"Cross-Origin-Embedder-Policy: \"require-corp\"",
		"certFile: \"" + entrypointCertificateDirectory + "/" + fixtureRouteHost + ".crt\"",
		"keyFile: \"" + entrypointCertificateDirectory + "/" + fixtureRouteHost + ".key\"",
	} {
		if !strings.Contains(fragment, line) {
			t.Fatalf("the fragment does not declare %q:\n%s", line, fragment)
		}
	}

	// What a fragment must never carry. A clear-port router would be a second way
	// in beside the redirection; a catch-all rule or a priority would let one
	// route answer for a name nobody declared; and neither a certificate nor a
	// key ever appears in a file this Auxiliary writes.
	for _, forbidden := range []string{
		"- web\n", "PathPrefix", "HostRegexp", "priority", "insecureSkipVerify",
		"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "passTLSClientCert",
		"127.0.0.1", "0.0.0.0",
	} {
		if strings.Contains(fragment, forbidden) {
			t.Fatalf("the fragment declares %q:\n%s", forbidden, fragment)
		}
	}
	if strings.Count(fragment, "url: ") != 1 {
		t.Fatalf("the fragment names more than one backend:\n%s", fragment)
	}

	// Two plans that differ only by their port produce two fragments differing
	// only by the backend line, and two that differ only by their host differ
	// nowhere the host does not appear.
	other := strings.Split(string(renderRouteFragment(fixtureRouteHost, fixturePort+1)), "\n")
	mine := strings.Split(fragment, "\n")
	if len(mine) != len(other) {
		t.Fatal("two route plans produced fragments of different shapes")
	}
	differences := 0
	for index := range mine {
		if mine[index] != other[index] {
			differences++
			if !strings.Contains(mine[index], "url: ") {
				t.Fatalf("a value other than the backend port reached the fragment: %q", mine[index])
			}
		}
	}
	if differences != 1 {
		t.Fatalf("two plans differing by their port produced %d differences", differences)
	}
}

// TestTwoDeclaredNamesAreTwoFragmentsAndNeverOne is why the fragment name needs
// no hashing and no folding.
//
// The plan validation binds a declared name to lower-case letters, digits,
// hyphens and dots, so the name is already a file name: two different names are
// two different files, and no pair of names collapses onto one fragment or onto
// one Traefik object. The pair below is the one a naive sanitiser would have
// merged by replacing dots with hyphens.
func TestTwoDeclaredNamesAreTwoFragmentsAndNeverOne(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{
		{"lab.example.test", "lab-example-test"},
		{"a.b.test", "a-b.test"},
		{"one.example.test", "two.example.test"},
	} {
		if routeFragmentPath(pair[0]) == routeFragmentPath(pair[1]) {
			t.Fatalf("%q and %q share one fragment file", pair[0], pair[1])
		}
		if string(renderRouteFragment(pair[0], fixturePort)) == string(renderRouteFragment(pair[1], fixturePort)) {
			t.Fatalf("%q and %q produce the same fragment", pair[0], pair[1])
		}
	}
	// The fragment stays inside the directory the entry watches, whatever the
	// name: the character set carries no separator at all.
	if !strings.HasPrefix(routeFragmentPath(fixtureRouteHost), entrypointFragmentDirectory+"/") ||
		strings.Count(strings.TrimPrefix(routeFragmentPath(fixtureRouteHost), entrypointFragmentDirectory+"/"), "/") != 0 {
		t.Fatalf("a fragment left the directory it belongs to: %q", routeFragmentPath(fixtureRouteHost))
	}
}

// TestADeclaredNameThisMachineCannotHoldAsOneFileIsRefusedBeforeAnyRead is the
// one place the contract's bound and this machine's bound disagree.
//
// A declared name may be 253 bytes and a single file name may be 255, so the
// longest names cannot be held as `<name>.yaml`. That is refused by name, before
// any effect and before the machine is even read — truncating instead would let
// two declared names share one fragment, which is exactly what a deterministic
// name exists to make impossible.
func TestADeclaredNameThisMachineCannotHoldAsOneFileIsRefusedBeforeAnyRead(t *testing.T) {
	t.Parallel()
	longest := "a" + strings.Repeat("b", plan.MaxRouteHostBytes-2) + "a"
	if len(longest) != plan.MaxRouteHostBytes {
		t.Fatalf("the longest declared name is %d bytes", len(longest))
	}
	executor := routableMachine(fixturePort)
	accepted, input := approvedRoute(t, plan.OperationPublishRoute, longest, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a declared name this machine cannot hold as one file was published")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	if !strings.Contains(err.Error(), "one file name may occupy on this machine") {
		t.Fatalf("the refusal was for another reason than its own: %v", err)
	}
	var controlled *ControlledFailure
	if errors.As(err, &controlled) {
		t.Fatalf("the refusal was reported as a controlled failure: %v", err)
	}
	if len(executor.effects) != 0 || len(executor.reads) != 0 {
		t.Fatalf("the refusal reached the machine: %q %q", executor.effects, executor.reads)
	}

	// The longest name this machine can hold is accepted, so the bound is a
	// bound and not a rejection of long names in general.
	holdable := "a" + strings.Repeat("b", maxFragmentNameBytes-len(routeFragmentSuffix)-2) + "a"
	if err := requireHoldableFragmentName(holdable); err != nil {
		t.Fatalf("the longest holdable name was refused: %v", err)
	}
}

// TestARouteTowardsAPortNothingManagesIsRefusedBeforeAnyEffect holds the
// contract's own sentence: a backend port must name the loopback port of a
// managed service that is present.
func TestARouteTowardsAPortNothingManagesIsRefusedBeforeAnyEffect(t *testing.T) {
	t.Parallel()
	for name, machine := range map[string]func() *fakeExecutor{
		"a machine where no managed service was ever deployed": func() *fakeExecutor {
			executor := entrypointMachine()
			executor.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
			return executor
		},
		"a machine whose managed service publishes another port": func() *fakeExecutor {
			return routableMachine(fixturePort + 1)
		},
	} {
		executor := machine()
		accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s published a route towards a port nothing manages", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), "no managed service of this machine publishes 127.0.0.1:8080") {
			t.Fatalf("%s was refused for another reason than its own: %v", name, err)
		}
		var controlled *ControlledFailure
		if errors.As(err, &controlled) {
			t.Fatalf("%s was reported as a controlled failure: %v", name, err)
		}
		if len(executor.effects) != 0 {
			t.Fatalf("%s changed the machine before being refused: %q", name, executor.effects)
		}
	}
}

// TestARouteOnAMachineHoldingNoEntrypointIsRefusedBeforeAnyEffect is the mirror
// of the refusal removeEntrypoint takes, and it is one decision read twice: the
// entry and the routes it serves have one order, and both ends of it are
// visible.
func TestARouteOnAMachineHoldingNoEntrypointIsRefusedBeforeAnyEffect(t *testing.T) {
	t.Parallel()
	executor := entrypointMachine()
	executor.hold(bentoPDFPlacement.unitPath(), renderSheet(bentoPDFPlacement, fixturePort, ""))
	accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a route was published on a machine that holds no entrypoint")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	if !strings.Contains(err.Error(), "this machine holds no entrypoint") {
		t.Fatalf("the refusal was for another reason than its own: %v", err)
	}
	var controlled *ControlledFailure
	if errors.As(err, &controlled) {
		t.Fatalf("the refusal was reported as a controlled failure: %v", err)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("the refusal changed the machine: %q", executor.effects)
	}
	// Retiring a route on that same machine is not refused: a retirement is a
	// statement that a name is not served, and a machine without an entry serves
	// nothing.
	accepted, input = approvedRoute(t, plan.OperationRetireRoute, fixtureRouteHost, fixturePort)
	retirement, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("retiring a route on a machine without an entrypoint was refused: %v", err)
	}
	if retirement.Changed || retirement.ServiceState != ServiceStateAbsent {
		t.Fatalf("an absent route was announced as a retirement: %+v", retirement)
	}
}

// TestRepublishingAnIdenticalRouteChangesNothing is the idempotence the palier
// owes, computed against the fragment's own bytes.
func TestRepublishingAnIdenticalRouteChangesNothing(t *testing.T) {
	t.Parallel()
	executor := publishedRouteMachine(fixtureRouteHost, fixturePort)
	accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a route plan demanding the state already held was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the same route was announced as a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a route that changed nothing touched the machine: %q", executor.effects)
	}
	if len(executor.verifiedRoutes) != 0 {
		t.Fatal("a route that did nothing still claimed to have proven something")
	}
}

// TestADriftedRouteFragmentIsAChangeAndNotAnError walks the differences a
// fragment can hold against the approved plan, and settles afterwards.
func TestADriftedRouteFragmentIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"the fragment was edited": func(e *fakeExecutor) {
			e.hold(routeFragmentPath(fixtureRouteHost),
				append(e.held(routeFragmentPath(fixtureRouteHost)), "\n# edited\n"...))
		},
		"the fragment disappeared": func(e *fakeExecutor) { e.drop(routeFragmentPath(fixtureRouteHost)) },
		"the fragment names another backend": func(e *fakeExecutor) {
			e.hold(routeFragmentPath(fixtureRouteHost), renderRouteFragment(fixtureRouteHost, fixturePort+1))
		},
		"the isolation headers were taken out": func(e *fakeExecutor) {
			edited := strings.ReplaceAll(
				string(e.held(routeFragmentPath(fixtureRouteHost))), "require-corp", "unsafe-none")
			e.hold(routeFragmentPath(fixtureRouteHost), []byte(edited))
		},
	} {
		executor := publishedRouteMachine(fixtureRouteHost, fixturePort)
		drift(executor)
		accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused instead of applied: %v", name, err)
		}
		if !application.Changed || application.ServiceState != ServiceStateActive {
			t.Fatalf("%s was not announced as a change: %+v", name, application)
		}
		if string(executor.held(routeFragmentPath(fixtureRouteHost))) !=
			string(renderRouteFragment(fixtureRouteHost, fixturePort)) {
			t.Fatalf("%s left the machine describing the drifted route", name)
		}

		settled := publishedRouteMachine(fixtureRouteHost, fixturePort)
		accepted, input = approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)
		application, err = Apply(settled, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused when applied a second time: %v", name, err)
		}
		if application.Changed || len(settled.effects) != 0 {
			t.Fatalf("%s did not settle: %+v %q", name, application, settled.effects)
		}
	}
}

// TestRetiringARouteRemovesExactlyTheFragmentAndNothingElse is the sentence the
// contract writes about a retirement, asserted as a fact about a machine: the
// entry keeps running, the other route keeps being served, and the service the
// retired name pointed at is untouched.
func TestRetiringARouteRemovesExactlyTheFragmentAndNothingElse(t *testing.T) {
	t.Parallel()
	const otherHost = "other.example.test"
	executor := publishedRouteMachine(fixtureRouteHost, fixturePort)
	executor.hold(routeFragmentPath(otherHost), renderRouteFragment(otherHost, fixturePort))
	accepted, input := approvedRoute(t, plan.OperationRetireRoute, fixtureRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("retiring a published route was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the retirement announced the wrong state: %+v", application)
	}
	if strings.Join(executor.effects, ",") != "RemoveUnitFile" {
		t.Fatalf("retiring a route did more than remove its fragment: %q", executor.effects)
	}
	if strings.Join(executor.removedPaths, ",") != routeFragmentPath(fixtureRouteHost) {
		t.Fatalf("retiring a route removed another file: %q", executor.removedPaths)
	}
	if executor.holds(routeFragmentPath(fixtureRouteHost)) {
		t.Fatal("the retired route is still published")
	}
	if !executor.holds(routeFragmentPath(otherHost)) {
		t.Fatal("retiring one route retired another")
	}
	if !executor.holds(entrypointPlacement.unitPath()) || !executor.holds(bentoPDFPlacement.unitPath()) {
		t.Fatal("retiring a route took the entry or the service away")
	}
	if len(executor.stoppedServices) != 0 || len(executor.removedImages) != 0 {
		t.Fatalf("retiring a route stopped or removed something: %v %v",
			executor.stoppedServices, executor.removedImages)
	}
}

// TestRetiringAnAbsentRouteChangesNothing keeps a retirement a statement about
// one named route rather than a sweep of the directory.
func TestRetiringAnAbsentRouteChangesNothing(t *testing.T) {
	t.Parallel()
	executor := routableMachine(fixturePort)
	accepted, input := approvedRoute(t, plan.OperationRetireRoute, fixtureRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("retiring an absent route was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("an absent route was announced as a retirement: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("retiring an absent route touched the machine: %q", executor.effects)
	}
}

// TestAControlledFailureOfAPublishedRouteRetiresItAndNothingElse is the conduct
// of `#85`, inherited whole by the route.
//
// The fragment was written and the entry did not serve the name as this contract
// requires, which is what the local verification exists to catch. The machine is
// still this Auxiliary's, so the second document a human signed is applied — the
// retirement of that same name — and the effect list is the whole proof.
func TestAControlledFailureOfAPublishedRouteRetiresItAndNothingElse(t *testing.T) {
	t.Parallel()
	executor := routableMachine(fixturePort)
	executor.failures["RouteAnswers"] = errors.New("the entrypoint answered 502")
	accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a route that was never served was reported as applied")
	}
	if application != nil {
		t.Fatalf("a controlled failure returned an application: %+v", application)
	}
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failure after a mutation was reported as a plain refusal: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack || failure.Observed != nil {
		t.Fatalf("the rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationPublishRoute || failure.RouteHost != fixtureRouteHost ||
		failure.FragmentPath != routeFragmentPath(fixtureRouteHost) {
		t.Fatalf("the failure does not name the route it was publishing: %+v", failure)
	}
	if failure.UnitPath != "" {
		t.Fatalf("the failure of a route named a sheet: %+v", failure)
	}
	for _, said := range []string{"unproven", "the approved rollback was attempted", fixtureRouteHost} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the controlled failure does not state %q: %v", said, err)
		}
	}
	if strings.Join(executor.effects, ",") != "WriteUnitFile,RemoveUnitFile" {
		t.Fatalf("the rollback was not the approved retirement and nothing else: %q", executor.effects)
	}
	if executor.holds(routeFragmentPath(fixtureRouteHost)) {
		t.Fatal("the machine still publishes the route the rollback retired")
	}
	if len(executor.verifiedRoutes) != 1 {
		t.Fatalf("the failed publication was retried: %v", executor.verifiedRoutes)
	}
	// The entry and the service are untouched by the whole episode.
	if !executor.holds(entrypointPlacement.unitPath()) || !executor.holds(bentoPDFPlacement.unitPath()) {
		t.Fatal("a failed route publication took the entry or the service away")
	}
}

// TestARouteRetirementThatFailsMidwayLeavesTheRoutePublished is the mirror
// image, and it names its own shape honestly.
//
// A retirement has exactly one effect, so a retirement that fails midway is a
// retirement whose one effect failed — and the approved rollback, republishing
// that same name, then finds the fragment still there, byte for byte the one it
// describes. It therefore reaches the state it describes without doing anything,
// which is a rollback that succeeded and not a rollback that was skipped.
func TestARouteRetirementThatFailsMidwayLeavesTheRoutePublished(t *testing.T) {
	t.Parallel()
	executor := publishedRouteMachine(fixtureRouteHost, fixturePort)
	executor.failures["RemoveUnitFile"] = errors.New("the fragment could not be removed")
	accepted, input := approvedRoute(t, plan.OperationRetireRoute, fixtureRouteHost, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a retirement that failed midway was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomeRolledBack {
		t.Fatalf("the retirement's rollback did not reach the state it describes: %+v", failure)
	}
	if failure.Operation != plan.OperationRetireRoute || failure.RouteHost != fixtureRouteHost {
		t.Fatalf("the failure names another route than the one that ran: %+v", failure)
	}
	if strings.Join(executor.effects, ",") != "RemoveUnitFile" {
		t.Fatalf("the rollback did something the approved document does not describe: %q", executor.effects)
	}
	if !executor.holds(routeFragmentPath(fixtureRouteHost)) {
		t.Fatal("the route the retirement failed to remove is gone anyway")
	}
	if count(executor.effects, "RemoveUnitFile") != 1 {
		t.Fatalf("the failed retirement was retried: %q", executor.effects)
	}
}

// TestAFailedRouteRollbackObservesTheFragment keeps the partial state a
// statement about the thing that was actually being changed: for a route, that
// is one file, and the observation says so in the same closed vocabulary.
func TestAFailedRouteRollbackObservesTheFragment(t *testing.T) {
	t.Parallel()
	executor := routableMachine(fixturePort)
	executor.failures["RouteAnswers"] = errors.New("the entrypoint answered 502")
	executor.failures["RemoveUnitFile"] = errors.New("the fragment could not be removed")
	accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failed rollback was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a failed rollback was announced as a rollback: %+v", failure)
	}
	if failure.Observed.Fragment != observedPresent {
		t.Fatalf("the observation says nothing about the fragment that was left: %+v", failure.Observed)
	}
	// The four other words still answer for the entry the route was served by,
	// because that is what a partial route state is left holding.
	if failure.Observed.UnitFile != observedPresent || failure.Observed.Account != observedPresent {
		t.Fatalf("the observation does not describe the entry: %+v", failure.Observed)
	}
	if count(executor.effects, "RemoveUnitFile") != 1 {
		t.Fatalf("the failed rollback was retried: %q", executor.effects)
	}
	if !strings.Contains(err.Error(), "partial state") {
		t.Fatalf("the partial state does not say so: %v", err)
	}
}
