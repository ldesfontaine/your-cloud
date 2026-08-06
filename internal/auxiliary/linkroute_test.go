package auxiliary

// This file holds for one name published through the private passage what
// route_test.go holds for a name published locally: what publishing and retiring
// actually touch, the fragment read byte for byte, the presence rule this palier
// adds, idempotence and drift computed against the file rather than against a
// memory, the rollback conduct inherited whole — and the one thing no other route
// has, which is what happens when the thing carrying the name falls over.
//
// The property every case here is really about is that nothing is invented. The
// backend is a constant of the passage, the port is one this machine's own
// junction bounds, the failure of the tunnel is a state that is reported rather
// than repaired, and no answer of this Auxiliary is ever a success about a name it
// could not serve.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestPublishingALinkRouteWritesExactlyOneFragmentAndVerifiesItThroughThePassage
// is the result this issue owes.
func TestPublishingALinkRouteWritesExactlyOneFragmentAndVerifiesItThroughThePassage(t *testing.T) {
	t.Parallel()
	executor := linkRoutableMachine(fixturePort)
	accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal link route publication was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first link route application announced no change: %+v", application)
	}
	if application.RouteHost != fixtureLinkRouteHost ||
		application.FragmentPath != entrypointFragmentDirectory+"/"+fixtureLinkRouteHost+".yaml" {
		t.Fatalf("the application named another route: %+v", application)
	}
	if application.UnitPath != "" || application.LocalPort != 0 {
		t.Fatalf("the link route named something a route does not have: %+v", application)
	}

	// Everything that could refuse read first and read only, in the order the
	// argument is written in: this machine's capabilities, the entry's sheet, the
	// role the passage is held in, the peer attached to it, the port its bounds
	// name, the fragment itself — and the verification last, after the one write.
	if strings.Join(executor.reads, ",") !=
		"Capabilities,ReadUnitFile,ReadUnitFile,ReadUnitFile,LinkRules,ReadUnitFile,LinkRouteAnswers" {
		t.Fatalf("the publication read the machine in another order: %q", executor.reads)
	}

	// One effect, and it is the fragment. Nothing of the passage was written,
	// reloaded or bounded again: publishing a name is not a junction.
	if strings.Join(executor.effects, ",") != "WriteUnitFile" {
		t.Fatalf("publishing a link route did more than write its fragment: %q", executor.effects)
	}
	if strings.Join(executor.writtenPaths, ",") != routeFragmentPath(fixtureLinkRouteHost) {
		t.Fatalf("publishing a link route wrote elsewhere: %q", executor.writtenPaths)
	}
	if string(executor.held(routeFragmentPath(fixtureLinkRouteHost))) !=
		string(renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort)) {
		t.Fatal("the machine does not hold the fragment this plan describes")
	}
	if executor.linkRuleApplications != 0 || executor.networkReloads != 0 || executor.linkKeysGenerated != 0 {
		t.Fatalf("publishing a link route touched the passage: %+v", executor)
	}
	if string(executor.held(entrypointPlacement.unitPath())) != string(renderEntrypointSheet()) {
		t.Fatal("publishing a link route rewrote the entry it does not own")
	}
	// The announced state was proven through the tunnel and for this name alone,
	// by the verification of this kind and never by the local route's.
	if len(executor.verifiedLinkRoutes) != 1 || executor.verifiedLinkRoutes[0] != fixtureLinkRouteHost {
		t.Fatalf("the published link route was not verified locally: %v", executor.verifiedLinkRoutes)
	}
	if len(executor.verifiedRoutes) != 0 || executor.entrypointChecks != 0 {
		t.Fatalf("a link route was verified as something else: %v %d",
			executor.verifiedRoutes, executor.entrypointChecks)
	}
}

// TestALinkRouteFragmentIsExactlyTheseBytes reads the fragment the way a
// reviewer reads it, whole: every line is something the contract asks for, the
// two values a plan carries are the only ones that vary, and what is absent is
// absent on purpose.
func TestALinkRouteFragmentIsExactlyTheseBytes(t *testing.T) {
	t.Parallel()
	golden := `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
http:
  routers:
    "vault.lab.your-cloud.test":
      rule: "Host(` + "`" + `vault.lab.your-cloud.test` + "`" + `)"
      entryPoints:
        - websecure
      service: "vault.lab.your-cloud.test"
      tls: {}
  services:
    "vault.lab.your-cloud.test":
      loadBalancer:
        servers:
          - url: "http://10.66.66.2:8080"
tls:
  certificates:
    - certFile: "/etc/your-cloud/entrypoint/certificates/vault.lab.your-cloud.test.crt"
      keyFile: "/etc/your-cloud/entrypoint/certificates/vault.lab.your-cloud.test.key"
`
	fragment := string(renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort))
	if fragment != golden {
		t.Fatalf("the link route fragment is not the bytes this contract describes:\n%s", fragment)
	}
	// The backend is the constant of the passage and never this machine's own
	// loopback, in any of its spellings: whatever answers on this host answers to
	// nothing a link route names.
	if !strings.Contains(fragment, "http://"+linkInitiatorAddress+":") {
		t.Fatalf("the fragment does not reach the peer of the tunnel:\n%s", fragment)
	}
	if strings.Count(fragment, "url: ") != 1 {
		t.Fatalf("the fragment names more than one backend:\n%s", fragment)
	}

	// What a fragment of this kind must never carry. The two isolation headers and
	// the middleware that adds them belong to the public profile; a clear-port
	// router would be a second way in beside the redirection; a catch-all rule or a
	// priority would let one route answer for a name nobody declared; and neither a
	// certificate nor a key ever appears in a file this Auxiliary writes.
	for _, forbidden := range []string{
		"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
		"middlewares", "customResponseHeaders",
		"- web\n", "PathPrefix", "HostRegexp", "priority", "insecureSkipVerify",
		"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "passTLSClientCert",
		loopbackAddress, entrypointHostLoopbackAddress, "0.0.0.0",
	} {
		if strings.Contains(fragment, forbidden) {
			t.Fatalf("the link route fragment declares %q:\n%s", forbidden, fragment)
		}
	}
	// Nor a proxy header. Traefik forwards what the service expects without being
	// asked, so a middleware restating it would be a control that grants nothing.
	for _, header := range []string{"X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
		if strings.Contains(fragment, header) {
			t.Fatalf("the fragment restates %q, which the entry already forwards:\n%s", header, fragment)
		}
	}

	// Two plans that differ only by their port produce two fragments differing
	// only by the backend line.
	other := strings.Split(string(renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort+1)), "\n")
	mine := strings.Split(fragment, "\n")
	if len(mine) != len(other) {
		t.Fatal("two link route plans produced fragments of different shapes")
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

// TestTheTwoKindsOfFragmentAreTellableApartFromTheirOwnBytes is what the
// cross-kind refusal rests on.
//
// It is a fact about the files and not a record this Auxiliary keeps: each kind
// names its own backend address, exactly once, and neither address appears in the
// other's fragment.
func TestTheTwoKindsOfFragmentAreTellableApartFromTheirOwnBytes(t *testing.T) {
	t.Parallel()
	local := renderRouteFragment(fixtureLinkRouteHost, fixturePort)
	passage := renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort)

	for name, subject := range map[string]struct {
		fragment []byte
		own      string
		other    string
	}{
		"a local route":   {fragment: local, own: entrypointHostLoopbackAddress, other: linkInitiatorAddress},
		"a passage route": {fragment: passage, own: linkInitiatorAddress, other: entrypointHostLoopbackAddress},
	} {
		if strings.Count(string(subject.fragment), string(fragmentBackendMarker(subject.own))) != 1 {
			t.Fatalf("%s does not name its own backend exactly once:\n%s", name, subject.fragment)
		}
		if strings.Contains(string(subject.fragment), string(fragmentBackendMarker(subject.other))) {
			t.Fatalf("%s names the other kind's backend:\n%s", name, subject.fragment)
		}
	}
}

// TestTheApprovedServicePortIsReadFromTheBytesTheJunctionWrote holds the reader
// and the renderer of the bounding table together.
//
// The presence rule of this palier asks the machine which port its junction
// bounds, and the answer comes from the root-owned file `#97` wrote rather than
// from anything the document being applied claims. So the line it is read through
// has to be a line that table really carries — which is what this checks, over
// several ports and against the other role's table.
func TestTheApprovedServicePortIsReadFromTheBytesTheJunctionWrote(t *testing.T) {
	t.Parallel()
	listener := linkPlacements[plan.LinkRoleListener]
	for _, port := range []int{1024, fixturePort, 65535} {
		rules := renderLinkRules(listener, port)
		if strings.Count(string(rules), linkListenerServiceRulePrefix()) != 1 {
			t.Fatalf("the listener's table names its approved port %d times, not once",
				strings.Count(string(rules), linkListenerServiceRulePrefix()))
		}
		read, readable := approvedServicePort(rules)
		if !readable || read != port {
			t.Fatalf("the table bounded to %d reads back as %d (readable: %t)", port, read, readable)
		}
	}
	// The initiator's table is another table entirely: it accepts what arrives
	// rather than what leaves, so the line this reader looks for is not in it and
	// no port is read back from a machine holding the wrong side.
	if _, readable := approvedServicePort(
		renderLinkRules(linkPlacements[plan.LinkRoleInitiator], fixturePort),
	); readable {
		t.Fatal("the initiator's table answered for a listener's approved port")
	}
	if _, readable := approvedServicePort(nil); readable {
		t.Fatal("an empty table answered for an approved port")
	}
}

// TestALinkRouteTowardsAPortTheTunnelDoesNotBoundIsRefusedBeforeAnyEffect is the
// presence rule of this palier, walked through everything it can find missing.
func TestALinkRouteTowardsAPortTheTunnelDoesNotBoundIsRefusedBeforeAnyEffect(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		machine func() *fakeExecutor
		said    string
	}{
		"a machine holding no entrypoint": {
			machine: func() *fakeExecutor {
				executor := linkRoutableMachine(fixturePort)
				executor.drop(entrypointPlacement.unitPath())
				return executor
			},
			said: "this machine holds no entrypoint",
		},
		"a machine holding no passage at all": {
			machine: func() *fakeExecutor {
				executor := entrypointMachine()
				executor.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
				return executor
			},
			said: "does not hold the passage as the listener",
		},
		"a machine holding the other side of the passage": {
			machine: func() *fakeExecutor {
				where := linkPlacements[plan.LinkRoleInitiator]
				executor := linkRoutableMachine(fixturePort)
				executor.hold(linkNetdevPath, append(renderLinkNetdev(where),
					renderLinkPeerSection(where, fixturePeerPublicKey, fixtureEndpointHost)...))
				executor.hold(linkNetworkPath, append(renderLinkNetwork(where),
					renderLinkRouteSection(where)...))
				return executor
			},
			said: "does not hold the passage as the listener",
		},
		"a prepared machine no junction was ever applied to": {
			machine: func() *fakeExecutor {
				executor := linkRoutableMachine(fixturePort)
				executor.hold(linkNetdevPath, renderLinkNetdev(linkPlacements[plan.LinkRoleListener]))
				return executor
			},
			said: "holds no junction on " + LinkInterfaceName,
		},
		"a machine whose junction left its bounds behind nowhere": {
			machine: func() *fakeExecutor {
				executor := linkRoutableMachine(fixturePort)
				executor.linkRules = nil
				executor.linkRulesPresent = false
				return executor
			},
			said: "holds no bounds on " + LinkInterfaceName,
		},
		"a machine whose bounds name no service port": {
			machine: func() *fakeExecutor {
				executor := linkRoutableMachine(fixturePort)
				executor.linkRules = []byte("# somebody replaced this table\n")
				return executor
			},
			said: "name no approved service port",
		},
		"a machine whose junction bounds another port": {
			machine: func() *fakeExecutor { return linkRoutableMachine(fixturePort + 1) },
			said:    "bounds the passage to 10.66.66.2:8081 and the approved plan publishes 8080",
		},
	} {
		executor := subject.machine()
		accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s published a name the passage cannot carry", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), subject.said) {
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

// TestADeclaredNameIsOneClaimAndNeverTwoKinds is the cross-kind refusal, in both
// directions.
//
// The two kinds of route share one namespace because a declared name is one
// claim: one certificate, one router, one file. So publishing over a name this
// machine already serves from somewhere else is not a drift the plan repairs —
// it would change what answers a public name without a document saying so — and
// it is refused before any effect, leaving the order to the human.
func TestADeclaredNameIsOneClaimAndNeverTwoKinds(t *testing.T) {
	t.Parallel()

	// A name published locally cannot silently become tunnel-backed.
	overLocal := linkRoutableMachine(fixturePort)
	overLocal.hold(routeFragmentPath(fixtureLinkRouteHost), renderRouteFragment(fixtureLinkRouteHost, fixturePort))
	accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(overLocal, accepted, input)
	if err == nil {
		t.Fatal("a link route was published over a name this machine serves locally")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	for _, said := range []string{fixtureLinkRouteHost, fragmentKindLocal, fragmentKindPassage, "one claim"} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the cross-kind refusal does not state %q: %v", said, err)
		}
	}
	if len(overLocal.effects) != 0 {
		t.Fatalf("the cross-kind refusal changed the machine: %q", overLocal.effects)
	}
	if string(overLocal.held(routeFragmentPath(fixtureLinkRouteHost))) !=
		string(renderRouteFragment(fixtureLinkRouteHost, fixturePort)) {
		t.Fatal("the refusal replaced the fragment it refused to replace")
	}

	// And a name published through the passage cannot silently become local.
	overPassage := routableMachine(fixturePort)
	overPassage.hold(routeFragmentPath(fixtureRouteHost), renderLinkRouteFragment(fixtureRouteHost, fixturePort))
	accepted, input = approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)

	application, err = Apply(overPassage, accepted, input)
	if err == nil {
		t.Fatal("a local route was published over a name this machine serves through the passage")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	for _, said := range []string{fixtureRouteHost, fragmentKindPassage, fragmentKindLocal} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the cross-kind refusal does not state %q: %v", said, err)
		}
	}
	if len(overPassage.effects) != 0 {
		t.Fatalf("the cross-kind refusal changed the machine: %q", overPassage.effects)
	}

	// Retiring is the way out, and it is the one the refusal names: once the name
	// is not served at all, the other kind publishes it.
	accepted, input = approvedLinkRoute(t, plan.OperationRetireLinkRoute, fixtureLinkRouteHost, fixturePort)
	if _, err := Apply(overLocal, accepted, input); err != nil {
		t.Fatalf("retiring the contested name was refused: %v", err)
	}
	accepted, input = approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)
	republished, err := Apply(overLocal, accepted, input)
	if err != nil {
		t.Fatalf("the freed name was refused to the other kind: %v", err)
	}
	if !republished.Changed || string(overLocal.held(routeFragmentPath(fixtureLinkRouteHost))) !=
		string(renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort)) {
		t.Fatalf("the freed name was not published as the plan describes it: %+v", republished)
	}
}

// TestRepublishingAnIdenticalLinkRouteChangesNothing is the idempotence the
// palier owes, computed against the fragment's own bytes.
func TestRepublishingAnIdenticalLinkRouteChangesNothing(t *testing.T) {
	t.Parallel()
	executor := publishedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
	accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a link route plan demanding the state already held was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the same link route was announced as a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a link route that changed nothing touched the machine: %q", executor.effects)
	}
	if len(executor.verifiedLinkRoutes) != 0 {
		t.Fatal("a link route that did nothing still claimed to have proven something")
	}
}

// TestADriftedLinkRouteFragmentIsAChangeAndNotAnError walks the differences a
// fragment of this kind can hold against the approved plan, and settles
// afterwards.
func TestADriftedLinkRouteFragmentIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"the fragment was edited": func(e *fakeExecutor) {
			e.hold(routeFragmentPath(fixtureLinkRouteHost),
				append(e.held(routeFragmentPath(fixtureLinkRouteHost)), "\n# edited\n"...))
		},
		"the fragment disappeared": func(e *fakeExecutor) { e.drop(routeFragmentPath(fixtureLinkRouteHost)) },
		"the fragment names another port of the peer": func(e *fakeExecutor) {
			e.hold(routeFragmentPath(fixtureLinkRouteHost),
				renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort+1))
		},
		"somebody added the isolation headers of the other profile": func(e *fakeExecutor) {
			edited := strings.Replace(
				string(e.held(routeFragmentPath(fixtureLinkRouteHost))),
				"      tls: {}\n",
				"      middlewares:\n        - \"edited\"\n      tls: {}\n", 1)
			e.hold(routeFragmentPath(fixtureLinkRouteHost), []byte(edited))
		},
	} {
		executor := publishedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
		drift(executor)
		accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused instead of applied: %v", name, err)
		}
		if !application.Changed || application.ServiceState != ServiceStateActive {
			t.Fatalf("%s was not announced as a change: %+v", name, application)
		}
		if string(executor.held(routeFragmentPath(fixtureLinkRouteHost))) !=
			string(renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort)) {
			t.Fatalf("%s left the machine describing the drifted route", name)
		}

		settled := publishedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
		accepted, input = approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)
		application, err = Apply(settled, accepted, input)
		if err != nil {
			t.Fatalf("%s was refused when applied a second time: %v", name, err)
		}
		if application.Changed || len(settled.effects) != 0 {
			t.Fatalf("%s did not settle: %+v %q", name, application, settled.effects)
		}
	}
}

// TestRetiringALinkRouteSilencesTheNameAndLeavesThePassageStanding is the
// sentence the contract writes about a retirement, asserted as a fact about a
// machine: the tunnel, its bounds and the service at the other end are untouched.
func TestRetiringALinkRouteSilencesTheNameAndLeavesThePassageStanding(t *testing.T) {
	t.Parallel()
	const otherHost = "other.example.test"
	executor := publishedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
	executor.hold(routeFragmentPath(otherHost), renderRouteFragment(otherHost, fixturePort))
	netdev := string(executor.held(linkNetdevPath))
	rules := string(executor.linkRules)
	accepted, input := approvedLinkRoute(t, plan.OperationRetireLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("retiring a published link route was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the retirement announced the wrong state: %+v", application)
	}
	if application.PassageState != ServiceStateActive {
		t.Fatalf("the retirement did not name the passage it left standing: %+v", application)
	}
	if strings.Join(executor.effects, ",") != "RemoveUnitFile" {
		t.Fatalf("retiring a link route did more than remove its fragment: %q", executor.effects)
	}
	if strings.Join(executor.removedPaths, ",") != routeFragmentPath(fixtureLinkRouteHost) {
		t.Fatalf("retiring a link route removed another file: %q", executor.removedPaths)
	}
	if executor.holds(routeFragmentPath(fixtureLinkRouteHost)) {
		t.Fatal("the retired link route is still published")
	}
	if !executor.holds(routeFragmentPath(otherHost)) {
		t.Fatal("retiring one route retired another")
	}
	// The passage is exactly where it was: the peer, the bounds, the unit that
	// puts them back, the interface and the key.
	if string(executor.held(linkNetdevPath)) != netdev || string(executor.linkRules) != rules {
		t.Fatal("retiring a link route rewrote the passage")
	}
	if !executor.linkRulesPresent || !executor.linkRulesAtBoot || !executor.linkActive ||
		!executor.linkKeyPresent || !executor.holds(linkRulesUnitPath) {
		t.Fatalf("retiring a link route took part of the passage away: %+v", executor)
	}
	if !executor.holds(entrypointPlacement.unitPath()) {
		t.Fatal("retiring a link route took the entry away")
	}
	if len(executor.stoppedServices) != 0 || len(executor.removedImages) != 0 {
		t.Fatalf("retiring a link route stopped or removed something: %v %v",
			executor.stoppedServices, executor.removedImages)
	}
}

// TestRetiringAnAbsentLinkRouteChangesNothing keeps a retirement a statement
// about one named route rather than a sweep of the directory.
func TestRetiringAnAbsentLinkRouteChangesNothing(t *testing.T) {
	t.Parallel()
	executor := linkRoutableMachine(fixturePort)
	accepted, input := approvedLinkRoute(t, plan.OperationRetireLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("retiring an absent link route was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("an absent link route was announced as a retirement: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("retiring an absent link route touched the machine: %q", executor.effects)
	}
}

// TestTheFailureOfThePassageIsNeverAFalseSuccess is the conduct the contract asks
// for by name, in its three times.
//
// The junction is gone and the name is still published: the entry keeps answering
// and that name returns its gateway error. What this Auxiliary may do about it is
// exactly nothing — no repair, no fallback route, no publication that would claim
// otherwise. What it does instead is refuse, report and observe.
func TestTheFailureOfThePassageIsNeverAFalseSuccess(t *testing.T) {
	t.Parallel()

	// Reapplying the publication over a fallen passage is refused, before any
	// effect, and the fragment it would have rewritten is left exactly as it is.
	panned := pannedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
	accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(panned, accepted, input)
	if err == nil {
		t.Fatal("a name was published over a passage that is not there")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	if !strings.Contains(err.Error(), "holds no junction on "+LinkInterfaceName) {
		t.Fatalf("the refusal was for another reason than its own: %v", err)
	}
	if len(panned.effects) != 0 {
		t.Fatalf("the refusal changed the machine: %q", panned.effects)
	}
	if !panned.holds(routeFragmentPath(fixtureLinkRouteHost)) {
		t.Fatal("the refusal took the published name away")
	}

	// Retiring it is not refused: it is how the name stops answering at all rather
	// than answering an error, and the report says what it found.
	accepted, input = approvedLinkRoute(t, plan.OperationRetireLinkRoute, fixtureLinkRouteHost, fixturePort)
	retirement, err := Apply(panned, accepted, input)
	if err != nil {
		t.Fatalf("retiring a name over a fallen passage was refused: %v", err)
	}
	if !retirement.Changed || retirement.ServiceState != ServiceStateAbsent {
		t.Fatalf("the retirement announced the wrong state: %+v", retirement)
	}
	if retirement.PassageState != ServiceStateAbsent {
		t.Fatalf("the retirement hid the failure of the passage: %+v", retirement)
	}

	// And a new approved junction is the whole of the reprise: the same plan, the
	// same bytes, nothing else asked of anybody.
	recovered := pannedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
	where := linkPlacements[plan.LinkRoleListener]
	recovered.hold(linkNetdevPath, append(renderLinkNetdev(where),
		renderLinkPeerSection(where, fixturePeerPublicKey, fixtureEndpointHost)...))
	recovered.linkRules = renderLinkRules(where, fixturePort)
	recovered.linkRulesPresent = true
	accepted, input = approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

	back, err := Apply(recovered, accepted, input)
	if err != nil {
		t.Fatalf("the name was refused over a passage that came back: %v", err)
	}
	if back.Changed || back.PassageState != ServiceStateActive {
		t.Fatalf("the reprise rewrote a fragment that was already right: %+v", back)
	}
	if len(recovered.effects) != 0 {
		t.Fatalf("the reprise touched the machine: %q", recovered.effects)
	}
}

// TestAControlledFailureOfAPublishedLinkRouteRetiresItAndNothingElse is the
// conduct of `#85`, inherited whole.
//
// The fragment was written and the name was not served through the passage, which
// is what the local verification exists to catch — an unreachable backend at the
// other end of the tunnel is exactly that case. The machine is still this
// Auxiliary's, so the second document a human signed is applied: the retirement of
// that same name, and nothing else.
func TestAControlledFailureOfAPublishedLinkRouteRetiresItAndNothingElse(t *testing.T) {
	t.Parallel()
	executor := linkRoutableMachine(fixturePort)
	executor.failures["LinkRouteAnswers"] = errors.New("the entrypoint answered 502")
	accepted, input := approvedLinkRoute(t, plan.OperationPublishLinkRoute, fixtureLinkRouteHost, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("a name that was never served was reported as applied")
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
	if failure.Operation != plan.OperationPublishLinkRoute || failure.RouteHost != fixtureLinkRouteHost ||
		failure.FragmentPath != routeFragmentPath(fixtureLinkRouteHost) {
		t.Fatalf("the failure does not name the route it was publishing: %+v", failure)
	}
	if failure.UnitPath != "" {
		t.Fatalf("the failure of a route named a sheet: %+v", failure)
	}
	for _, said := range []string{"unproven", "the approved rollback was attempted", fixtureLinkRouteHost} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the controlled failure does not state %q: %v", said, err)
		}
	}
	if strings.Join(executor.effects, ",") != "WriteUnitFile,RemoveUnitFile" {
		t.Fatalf("the rollback was not the approved retirement and nothing else: %q", executor.effects)
	}
	if executor.holds(routeFragmentPath(fixtureLinkRouteHost)) {
		t.Fatal("the machine still publishes the route the rollback retired")
	}
	if len(executor.verifiedLinkRoutes) != 1 {
		t.Fatalf("the failed publication was retried: %v", executor.verifiedLinkRoutes)
	}
	// The passage and the entry are untouched by the whole episode.
	if !executor.linkRulesPresent || !executor.linkActive || !executor.holds(entrypointPlacement.unitPath()) {
		t.Fatalf("a failed publication took the passage or the entry away: %+v", executor)
	}
}

// TestAFailedLinkRouteRollbackObservesTheUnbackedName is the partial state of
// this kind, and it is where the word this vocabulary gained is earned.
//
// The retirement failed to remove the fragment, and its approved rollback — the
// publication of that same name — is refused because the junction is gone: a
// rollback that cannot reach the state it describes claims nothing. What is left
// is a machine publishing a name nothing carries, and the observation says
// exactly that in one word rather than leaving a reader to combine two.
func TestAFailedLinkRouteRollbackObservesTheUnbackedName(t *testing.T) {
	t.Parallel()
	executor := pannedLinkRouteMachine(fixtureLinkRouteHost, fixturePort)
	executor.failures["RemoveUnitFile"] = errors.New("the fragment could not be removed")
	accepted, input := approvedLinkRoute(t, plan.OperationRetireLinkRoute, fixtureLinkRouteHost, fixturePort)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a retirement that failed midway was not a controlled failure: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a failed rollback was announced as a rollback: %+v", failure)
	}
	if failure.Observed.Fragment != observedUnbacked {
		t.Fatalf("the observation does not name the unbacked name: %+v", failure.Observed)
	}
	if failure.Observed.LinkPeer != observedAbsent {
		t.Fatalf("the observation does not name the junction that is missing: %+v", failure.Observed)
	}
	// The four words still answer for the entry the name was served by, because
	// that is what a partial route state is left holding.
	if failure.Observed.UnitFile != observedPresent || failure.Observed.Account != observedPresent {
		t.Fatalf("the observation does not describe the entry: %+v", failure.Observed)
	}
	if count(executor.effects, "RemoveUnitFile") != 1 {
		t.Fatalf("the failed retirement was retried: %q", executor.effects)
	}
	if !strings.Contains(err.Error(), "partial state") {
		t.Fatalf("the partial state does not say so: %v", err)
	}
	// Nothing was repaired and no fallback was written: the machine is exactly as
	// the failure left it.
	if !executor.holds(routeFragmentPath(fixtureLinkRouteHost)) || executor.linkRulesPresent {
		t.Fatalf("something repaired the failure of the passage: %+v", executor)
	}
}

// TestObservingAPublishedNameOverAStandingPassageSaysSo is the other half of the
// word: a fragment beside a junction is present, not unbacked, so the state that
// has to be read stays distinguishable from the state that is fine.
func TestObservingAPublishedNameOverAStandingPassageSaysSo(t *testing.T) {
	t.Parallel()
	subject := instance{kind: kindLinkRoute, placement: entrypointPlacement, routeHost: fixtureLinkRouteHost}

	standing := observe(publishedLinkRouteMachine(fixtureLinkRouteHost, fixturePort), subject)
	if standing.Fragment != observedPresent || standing.LinkPeer != observedPresent {
		t.Fatalf("a published name over a standing passage was not observed as such: %+v", standing)
	}
	retired := observe(linkRoutableMachine(fixturePort), subject)
	if retired.Fragment != observedAbsent || retired.LinkPeer != observedPresent {
		t.Fatalf("an unpublished name over a standing passage was not observed as such: %+v", retired)
	}
	// And a local route is never observed in the passage's words, because it rests
	// on nothing of the sort.
	local := observe(publishedRouteMachine(fixtureRouteHost, fixturePort),
		instance{kind: kindRoute, placement: entrypointPlacement, routeHost: fixtureRouteHost})
	if local.Fragment != observedPresent || local.LinkPeer != "" {
		t.Fatalf("a local route was observed as something resting on a passage: %+v", local)
	}
}

// TestRemovingTheEntrypointRefusesWhileALinkRouteIsPublished holds the refusal
// removeEntrypoint takes against the other kind of fragment too.
//
// It is one decision read from both ends and it has to cover both kinds: the entry
// serves them from one directory, so removing it would stop serving a name the
// passage carries exactly as silently as one a local service backs.
func TestRemovingTheEntrypointRefusesWhileALinkRouteIsPublished(t *testing.T) {
	t.Parallel()
	executor := deployedEntrypointMachine()
	executor.hold(routeFragmentPath(fixtureLinkRouteHost),
		renderLinkRouteFragment(fixtureLinkRouteHost, fixturePort))
	accepted, input := approvedEntrypoint(t, plan.OperationRemoveEntrypoint)

	application, err := Apply(executor, accepted, input)
	if err == nil {
		t.Fatal("the entrypoint was removed while it still served a name the passage carries")
	}
	if application != nil {
		t.Fatalf("the refusal returned an application: %+v", application)
	}
	for _, said := range []string{"still publishes 1 route", fixtureLinkRouteHost + routeFragmentSuffix} {
		if !strings.Contains(err.Error(), said) {
			t.Fatalf("the refusal does not name what is in the way (%q): %v", said, err)
		}
	}
	if len(executor.effects) != 0 {
		t.Fatalf("the refusal changed the machine: %q", executor.effects)
	}
}
