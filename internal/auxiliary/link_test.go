package auxiliary

// This file is everything the private passage is on a machine, held against the
// contract that describes it: the key that is generated once and never again,
// the two files a role decides every byte of, the single peer a junction
// attaches, the refusals that keep the four plans in their order, and the
// conduct of a failure that happened after the first effect.
//
// One property runs through all of it and is proven on its own at the end: no
// operation of this passage, successful or failed, ever carries private
// material. The fake machine writes a private key that is a sentence rather than
// a plausible key, so a test grepping for those bytes can only match if
// something really did carry the private half.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestTheFirstPreparationGeneratesOneKeyAndDescribesTheClosedInterface is the
// result this issue owes on the listening side.
//
// The order is the whole argument: the key exists before a file names it, both
// files are on disk before the network manager is asked to read them, the
// manager is running before the reload that creates the interface, and the
// interface is read back afterwards rather than assumed.
func TestTheFirstPreparationGeneratesOneKeyAndDescribesTheClosedInterface(t *testing.T) {
	t.Parallel()
	executor := linkMachine()
	accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal preparation was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first preparation announced no change: %+v", application)
	}
	if application.LinkPublicKey != fixtureLinkPublicKey {
		t.Fatalf("the preparation did not report the public key of the machine: %+v", application)
	}

	expected := []string{
		"GenerateLinkKey", "WriteUnitFile", "WriteUnitFile",
		"EnableNetworkManagement", "ReloadNetworkConfiguration",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if executor.linkKeysGenerated != 1 {
		t.Fatalf("the preparation generated %d keys", executor.linkKeysGenerated)
	}

	// The description is the listener's, down to the line that says it listens.
	// The key travels by its path and never by its value, which is the whole
	// reason this mechanism was chosen over one that inlines it.
	description := string(executor.held(linkNetdevPath))
	for _, line := range []string{
		"[NetDev]",
		"Name=" + LinkInterfaceName,
		"Kind=wireguard",
		"[WireGuard]",
		"PrivateKeyFile=" + linkPrivateKeyPath,
		"ListenPort=51820",
	} {
		if !strings.Contains(description, line) {
			t.Fatalf("the passage's description does not declare %q:\n%s", line, description)
		}
	}
	if strings.Contains(description, "[WireGuardPeer]") {
		t.Fatalf("a preparation attached a peer no junction approved:\n%s", description)
	}
	addressing := string(executor.held(linkNetworkPath))
	for _, line := range []string{"Name=" + LinkInterfaceName, "Address=10.66.66.1/32"} {
		if !strings.Contains(addressing, line) {
			t.Fatalf("the passage's addressing does not declare %q:\n%s", line, addressing)
		}
	}
	if strings.Contains(addressing, "[Route]") {
		t.Fatalf("a preparation routed towards a peer no junction approved:\n%s", addressing)
	}
}

// TestTheInitiatorPreparesWithoutHoldingAnyListeningPort is the other side of
// the same asymmetry.
//
// The initiator goes out and never answers, so its description carries no
// listening port at all — absent rather than set to something harmless, because
// a machine of the LAN that held a socket would be a machine with an inbound
// port, which is exactly what this contract exists to avoid.
func TestTheInitiatorPreparesWithoutHoldingAnyListeningPort(t *testing.T) {
	t.Parallel()
	executor := linkMachine()
	accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleInitiator)

	if _, err := Apply(executor, accepted, input); err != nil {
		t.Fatalf("the nominal initiator preparation was refused: %v", err)
	}
	description := string(executor.held(linkNetdevPath))
	if strings.Contains(description, "ListenPort") {
		t.Fatalf("the initiator holds a listening port:\n%s", description)
	}
	if !strings.Contains(string(executor.held(linkNetworkPath)), "Address=10.66.66.2/32") {
		t.Fatalf("the initiator does not hold its own address:\n%s", executor.held(linkNetworkPath))
	}
}

// TestAPreparationReplayedNeverRegeneratesTheKeyAndChangesNothing is criterion
// five of the contract, read on one machine: replaying the plan finds the
// approved state already held, and the key is not touched.
//
// The public key is still reported, because it is an observation the Controller
// reads rather than something this run produced. A replay that stopped reporting
// it would make the Controller's ability to build the other machine's junction
// depend on which run it happened to read.
func TestAPreparationReplayedNeverRegeneratesTheKeyAndChangesNothing(t *testing.T) {
	t.Parallel()
	executor := preparedLinkMachine(plan.LinkRoleListener)
	accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a replayed preparation was refused: %v", err)
	}
	if application.Changed {
		t.Fatalf("a plan demanding what is already true announced a change: %+v", application)
	}
	if application.LinkPublicKey != fixtureLinkPublicKey {
		t.Fatalf("a replayed preparation stopped reporting the public key: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a replayed preparation touched the machine: %q", executor.effects)
	}
	if executor.linkKeysGenerated != 0 {
		t.Fatalf("a replayed preparation regenerated the key")
	}
}

// TestAPreparationReplayedAfterAJunctionLeavesThatJunctionStanding is the rest
// of criterion five: replaying the four plans of the contract in order changes
// nothing, which requires the first of them not to undo the third.
//
// The head of each file belongs to the preparation and the tail to the junction.
// A preparation that rendered a whole file from its own constants would detach
// the peer every time it ran, and the passage would flap on every replay.
func TestAPreparationReplayedAfterAJunctionLeavesThatJunctionStanding(t *testing.T) {
	t.Parallel()
	for _, role := range []string{plan.LinkRoleListener, plan.LinkRoleInitiator} {
		executor := joinedLinkMachine(role)
		description := string(executor.held(linkNetdevPath))
		accepted, input := approvedLink(t, plan.OperationPrepareLink, role)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("the %s replayed its preparation and was refused: %v", role, err)
		}
		if application.Changed || len(executor.effects) != 0 {
			t.Fatalf("the %s's replayed preparation acted on a joined machine: %+v %q",
				role, application, executor.effects)
		}
		if string(executor.held(linkNetdevPath)) != description {
			t.Fatalf("the %s's replayed preparation rewrote the junction:\n%s",
				role, executor.held(linkNetdevPath))
		}
	}
}

// TestADriftedPassageIsAChangeAndNotAnError holds the same rule the sheets of
// the older paliers are held to: the approved plan is the state that must hold,
// and reaching it again is a change rather than a repair somebody has to notice.
//
// The key is the one thing a drift never touches. Whatever happened to the files
// or to the interface, an existing key is carried forward: regenerating it would
// change the public key the other machine was approved to accept, and turn a
// repair into a silent revocation.
func TestADriftedPassageIsAChangeAndNotAnError(t *testing.T) {
	t.Parallel()
	for name, drift := range map[string]func(*fakeExecutor){
		"a description somebody edited": func(executor *fakeExecutor) {
			executor.hold(linkNetdevPath, []byte("[NetDev]\nName=yc-link0\nKind=wireguard\n"))
		},
		"an addressing somebody removed": func(executor *fakeExecutor) {
			executor.drop(linkNetworkPath)
		},
		"an interface somebody took down": func(executor *fakeExecutor) {
			executor.linkActive = false
		},
	} {
		executor := preparedLinkMachine(plan.LinkRoleListener)
		drift(executor)
		accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("%s was reported as an error: %v", name, err)
		}
		if !application.Changed {
			t.Fatalf("%s was not reapplied: %+v", name, application)
		}
		if executor.linkKeysGenerated != 0 {
			t.Fatalf("%s regenerated the key of this machine", name)
		}
		if !executor.linkActive {
			t.Fatalf("%s left the machine holding no interface", name)
		}
	}
}

// TestTheListenersJunctionAttachesOnePeerBoundedToItsOwnAddress is what a
// junction is on the listening side, and what it is not.
//
// AllowedIPs is the peer's own /32 and nothing else: the LAN behind the
// initiator is never announced and never routed, so the listener knows of it
// exactly one address. And the listener has nowhere to reach, so its section
// carries neither an endpoint nor a keepalive — absent rather than empty.
func TestTheListenersJunctionAttachesOnePeerBoundedToItsOwnAddress(t *testing.T) {
	t.Parallel()
	executor := preparedLinkMachine(plan.LinkRoleListener)
	accepted, input := approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal listener junction was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the junction announced no change: %+v", application)
	}
	expected := []string{"WriteUnitFile", "WriteUnitFile", "ReloadNetworkConfiguration"}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}

	description := string(executor.held(linkNetdevPath))
	for _, line := range []string{
		"[WireGuardPeer]",
		"PublicKey=" + fixturePeerPublicKey,
		"AllowedIPs=10.66.66.2/32",
	} {
		if !strings.Contains(description, line) {
			t.Fatalf("the listener's junction does not declare %q:\n%s", line, description)
		}
	}
	for _, forbidden := range []string{"Endpoint=", "PersistentKeepalive="} {
		if strings.Contains(description, forbidden) {
			t.Fatalf("the listener's junction carries %q, which is the initiator's:\n%s", forbidden, description)
		}
	}
	// The route is what makes a passage between two /32 addresses usable at all,
	// and it reaches exactly the address AllowedIPs allows.
	addressing := string(executor.held(linkNetworkPath))
	for _, line := range []string{"[Route]", "Destination=10.66.66.2/32", "Scope=link"} {
		if !strings.Contains(addressing, line) {
			t.Fatalf("the listener's junction does not route towards its peer %q:\n%s", line, addressing)
		}
	}
}

// TestTheInitiatorsJunctionReachesTheEndpointAndKeepsTheTunnelAlive is the other
// side of the asymmetry: the initiator goes out, so it alone names an endpoint
// and it alone holds the tunnel open through the NAT it sits behind.
//
// The endpoint port is not a field of any plan, and this is where that decision
// becomes visible: the port written here is the listening port of the contract.
func TestTheInitiatorsJunctionReachesTheEndpointAndKeepsTheTunnelAlive(t *testing.T) {
	t.Parallel()
	executor := preparedLinkMachine(plan.LinkRoleInitiator)
	accepted, input := approvedInitiatorPeer(t, plan.OperationJoinLinkPeer, fixturePort)

	if _, err := Apply(executor, accepted, input); err != nil {
		t.Fatalf("the nominal initiator junction was refused: %v", err)
	}
	description := string(executor.held(linkNetdevPath))
	for _, line := range []string{
		"PublicKey=" + fixturePeerPublicKey,
		"AllowedIPs=10.66.66.1/32",
		"Endpoint=" + fixtureEndpointHost + ":51820",
		"PersistentKeepalive=25",
	} {
		if !strings.Contains(description, line) {
			t.Fatalf("the initiator's junction does not declare %q:\n%s", line, description)
		}
	}
	if !strings.Contains(string(executor.held(linkNetworkPath)), "Destination=10.66.66.1/32") {
		t.Fatalf("the initiator does not route towards the listener:\n%s", executor.held(linkNetworkPath))
	}
}

// TestAJunctionReplayedChangesNothing completes criterion five over the two
// junction plans of the contract.
func TestAJunctionReplayedChangesNothing(t *testing.T) {
	t.Parallel()
	for _, role := range []string{plan.LinkRoleListener, plan.LinkRoleInitiator} {
		executor := joinedLinkMachine(role)
		accepted, input := approvedJunction(t, role, false)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("the %s's replayed junction was refused: %v", role, err)
		}
		if application.Changed || len(executor.effects) != 0 {
			t.Fatalf("the %s's replayed junction acted: %+v %q", role, application, executor.effects)
		}
	}
}

// TestADepartureTakesThePeerAwayAndLeavesThePassageStanding is what revoking a
// junction is: the peer and the route are gone, and the interface, the key and
// the machine's own address are exactly where they were.
func TestADepartureTakesThePeerAwayAndLeavesThePassageStanding(t *testing.T) {
	t.Parallel()
	for _, role := range []string{plan.LinkRoleListener, plan.LinkRoleInitiator} {
		executor := joinedLinkMachine(role)
		accepted, input := approvedJunction(t, role, true)

		application, err := Apply(executor, accepted, input)
		if err != nil {
			t.Fatalf("the %s's departure was refused: %v", role, err)
		}
		if !application.Changed || application.ServiceState != ServiceStateAbsent {
			t.Fatalf("the %s's departure announced the wrong state: %+v", role, application)
		}
		description := string(executor.held(linkNetdevPath))
		if strings.Contains(description, "[WireGuardPeer]") {
			t.Fatalf("the %s still holds the peer it left:\n%s", role, description)
		}
		if strings.Contains(string(executor.held(linkNetworkPath)), "[Route]") {
			t.Fatalf("the %s still routes towards the peer it left", role)
		}
		// The passage itself is untouched: a departure removes the junction and
		// nothing else.
		if !executor.linkKeyPresent || !executor.linkActive {
			t.Fatalf("the %s's departure withdrew the passage: %+v", role, executor)
		}
		if executor.linkInterfaceRemovals != 0 {
			t.Fatalf("the %s's departure took the interface down", role)
		}
		// The manager is made to read the detachment exactly once. Removing the
		// peer from a file the manager has already applied is not enough on its
		// own: what is on disk and what the kernel holds must be made to agree,
		// and that is one call rather than a hope.
		if executor.networkReloads != 1 {
			t.Fatalf("the %s's departure reloaded the manager %d times", role, executor.networkReloads)
		}
	}
}

// TestTheKeysTheseTestsUseAreSpellingsAPlanCouldActuallyCarry keeps the fixtures
// honest.
//
// A peer key invented for a test and refused by the plan package would make
// every refusal above pass for the wrong reason, and a machine described as
// holding "another peer" would be a machine holding a value no approval could
// ever have named.
func TestTheKeysTheseTestsUseAreSpellingsAPlanCouldActuallyCarry(t *testing.T) {
	t.Parallel()
	for _, key := range []string{fixturePeerPublicKey, fixtureOtherPeerPublicKey, fixtureLinkPublicKey} {
		if _, err := plan.BuildListenerPeerPair(plan.OperationAttachLinkPeer,
			fixtureInfrastructure, fixtureMachine, key, fixturePort); err != nil {
			t.Fatalf("%q is not a spelling a plan of this contract could carry: %v", key, err)
		}
	}
}

// TestADepartureFromAPassageWithNoPeerChangesNothing holds a departure to the
// same rule an absent service is held to: the approved state is already there,
// so nothing is touched to announce it.
func TestADepartureFromAPassageWithNoPeerChangesNothing(t *testing.T) {
	t.Parallel()
	executor := preparedLinkMachine(plan.LinkRoleListener)
	accepted, input := approvedListenerPeer(t, plan.OperationDetachLinkPeer, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("detaching an absent peer was refused: %v", err)
	}
	if application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("detaching an absent peer announced a change: %+v", application)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("detaching an absent peer touched the machine: %q", executor.effects)
	}
}

// TestAWithdrawalLeavesNeitherInterfaceNorKeyNorDescription is the complete
// removal criterion eight asks for, and the order it happens in.
//
// The interface goes down before the files that describe it are removed, and the
// key goes last: it is the one thing here that cannot be rebuilt from a constant,
// so it is taken away only once everything that referred to it is already gone.
func TestAWithdrawalLeavesNeitherInterfaceNorKeyNorDescription(t *testing.T) {
	t.Parallel()
	executor := preparedLinkMachine(plan.LinkRoleListener)
	accepted, input := approvedLink(t, plan.OperationWithdrawLink, plan.LinkRoleListener)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("withdrawing a prepared passage was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateAbsent {
		t.Fatalf("the withdrawal announced the wrong state: %+v", application)
	}
	expected := []string{
		"RemoveLinkInterface", "RemoveUnitFile", "RemoveUnitFile",
		"ReloadNetworkConfiguration", "RemoveLinkKey",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	if executor.holds(linkNetdevPath) || executor.holds(linkNetworkPath) ||
		executor.linkKeyPresent || executor.linkActive {
		t.Fatalf("the machine still holds part of the passage: %+v", executor)
	}
}

// TestWithdrawingAnAbsentPassageChangesNothing is the same rule once more, on
// the machine the contract's first criterion describes: nothing exists before an
// approval, so a withdrawal finds nothing and touches nothing.
func TestWithdrawingAnAbsentPassageChangesNothing(t *testing.T) {
	t.Parallel()
	executor := linkMachine()
	accepted, input := approvedLink(t, plan.OperationWithdrawLink, plan.LinkRoleListener)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("withdrawing an absent passage was refused: %v", err)
	}
	if application.Changed || len(executor.effects) != 0 {
		t.Fatalf("withdrawing an absent passage acted: %+v %q", application, executor.effects)
	}
}

// TestThePassageIsHeldByTheNetworkManagerSoItSurvivesAReboot is criterion seven
// read as far as a unit test can read it.
//
// A machine cannot be rebooted here, so what is proven is the mechanism rather
// than the outcome: the two files the interface is built from are on disk, they
// name the key by its path, and the manager that reads them at boot has been
// enabled rather than merely started. The reboot itself is `#98`.
func TestThePassageIsHeldByTheNetworkManagerSoItSurvivesAReboot(t *testing.T) {
	t.Parallel()
	executor := linkMachine()
	accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

	if _, err := Apply(executor, accepted, input); err != nil {
		t.Fatalf("the nominal preparation was refused: %v", err)
	}
	if executor.networkEnablings != 1 {
		t.Fatalf("the passage was not given to a manager that runs after a reboot: %+v", executor)
	}
	for _, path := range []string{linkNetdevPath, linkNetworkPath} {
		if !strings.HasPrefix(path, networkConfigurationDirectory+"/") {
			t.Fatalf("%s is not read by the network manager at boot", path)
		}
		if !executor.holds(path) {
			t.Fatalf("the machine does not hold %s", path)
		}
	}
}

// TestAPassageIsRefusedBeforeAnyEffectWhenThisMachineCannotHoldIt is the refusal
// matrix of the passage: what only the machine can answer, refused with nothing
// written.
//
// Every case asserts the same three things: the operation was refused, the
// refusal said what it was refusing, and the fake machine recorded no effect. A
// refusal that tidied something away is not a refusal.
func TestAPassageIsRefusedBeforeAnyEffectWhenThisMachineCannotHoldIt(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		machine  func() *fakeExecutor
		approved func(*testing.T) (*approval.Acceptance, *Input)
		named    string
	}{
		"a listener junction on a machine that was never prepared": {
			machine: linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)
			},
			named: "this machine holds no prepared passage",
		},
		"an initiator junction on a machine that was never prepared": {
			machine: linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedInitiatorPeer(t, plan.OperationJoinLinkPeer, fixturePort)
			},
			named: "this machine holds no prepared passage",
		},
		"a junction on a machine that holds the files but has lost its key": {
			machine: func() *fakeExecutor {
				executor := preparedLinkMachine(plan.LinkRoleListener)
				executor.linkKeyPresent = false
				return executor
			},
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)
			},
			named: "this machine holds no prepared passage",
		},
		"the listener's junction on a machine prepared as the initiator": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleInitiator) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationAttachLinkPeer, fixturePort)
			},
			named: "the two sides are not interchangeable",
		},
		"the initiator's junction on a machine prepared as the listener": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedInitiatorPeer(t, plan.OperationJoinLinkPeer, fixturePort)
			},
			named: "the two sides are not interchangeable",
		},
		"a preparation naming the role this machine does not hold": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleInitiator)
			},
			named: "a machine has one role per link",
		},
		"a withdrawal while a junction is still attached": {
			machine: func() *fakeExecutor { return joinedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationWithdrawLink, plan.LinkRoleListener)
			},
			named: "this machine still holds a junction",
		},
		"a departure naming another peer than the one this machine holds": {
			machine: func() *fakeExecutor {
				executor := preparedLinkMachine(plan.LinkRoleListener)
				where := linkPlacements[plan.LinkRoleListener]
				executor.hold(linkNetdevPath, append(renderLinkNetdev(where),
					renderLinkPeerSection(where, fixtureOtherPeerPublicKey, "")...))
				executor.hold(linkNetworkPath, append(renderLinkNetwork(where),
					renderLinkRouteSection(where)...))
				return executor
			},
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationDetachLinkPeer, fixturePort)
			},
			named: "this machine holds another peer than the one the approved plan names",
		},
		"a passage whose addressing names no address of the reserved subnet": {
			machine: func() *fakeExecutor {
				executor := preparedLinkMachine(plan.LinkRoleListener)
				executor.hold(linkNetworkPath, []byte("[Match]\nName=yc-link0\n\n[Network]\nAddress=192.0.2.1/32\n"))
				return executor
			},
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
			},
			named: "the role of this machine cannot be read back",
		},
	} {
		executor := subject.machine()
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was applied", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), subject.named) {
			t.Fatalf("%s was refused for another reason than its own: %v", name, err)
		}
		if len(executor.effects) != 0 {
			t.Fatalf("%s changed the machine before being refused: %q", name, executor.effects)
		}
		// A refusal is an ordinary error and never a controlled failure: nothing
		// happened, so there is nothing to have rolled back.
		var controlled *ControlledFailure
		if errors.As(err, &controlled) {
			t.Fatalf("%s was reported as a controlled failure: %v", name, err)
		}
	}
}

// TestAMachineWithoutSystemdHoldsNoPassageAndIsRefusedBeforeAnyWrite is what a
// passage asks of a machine, and it is deliberately less than what a managed
// service asks.
//
// A passage owns no account, no container and no image, so a machine without
// Podman or without a unified cgroup hierarchy holds one perfectly well. What it
// does need is systemd, because the manager that carries the interface across a
// reboot is one of its units.
func TestAMachineWithoutSystemdHoldsNoPassageAndIsRefusedBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	executor := linkMachine()
	executor.capabilities = Capabilities{}
	accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

	if _, err := Apply(executor, accepted, input); err == nil {
		t.Fatal("a machine without systemd prepared a passage")
	} else if !strings.Contains(err.Error(), "the private passage is refused before any write") {
		t.Fatalf("a machine without systemd was refused for another reason: %v", err)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a machine without systemd was written to: %q", executor.effects)
	}
	if strings.Join(executor.reads, ",") != "Capabilities" {
		t.Fatalf("a machine without systemd was read beyond its capabilities: %q", executor.reads)
	}

	// The three the passage does not need are proven by the passage being applied
	// on a machine that has none of them: linkMachine carries systemd alone.
	nominal := linkMachine()
	accepted, input = approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
	if _, err := Apply(nominal, accepted, input); err != nil {
		t.Fatalf("a machine with systemd and nothing else was refused a passage: %v", err)
	}
}

// TestAPreparationThatFailsAfterItsFirstEffectAttemptsTheApprovedWithdrawal is
// the conduct of a failure that happened once this machine had already been
// changed, over the one instance of this product whose first effect is a key.
//
// The rollback is the second document a human signed — the withdrawal of the
// very passage that was being prepared — applied through the ordinary path
// against whatever the machine actually holds. Nothing is retried and nothing is
// invented: the key that was generated is removed by the approved withdrawal,
// because that is what the withdrawal says, and not because this Auxiliary
// decided to tidy up after itself.
func TestAPreparationThatFailsAfterItsFirstEffectAttemptsTheApprovedWithdrawal(t *testing.T) {
	t.Parallel()
	for failing, expected := range map[string]string{
		"WriteUnitFile":              OutcomeRolledBack,
		"EnableNetworkManagement":    OutcomeRolledBack,
		"ReloadNetworkConfiguration": OutcomePartial,
	} {
		executor := linkMachine()
		executor.failures[failing] = errors.New("the machine refused this effect")
		accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

		_, err := Apply(executor, accepted, input)
		var failure *ControlledFailure
		if !errors.As(err, &failure) {
			t.Fatalf("a failure at %s was not a controlled failure: %v", failing, err)
		}
		if failure.Outcome != expected {
			t.Fatalf("a failure at %s concluded %q: %+v", failing, failure.Outcome, failure)
		}
		if failure.Operation != plan.OperationPrepareLink || failure.UnitPath != linkNetdevPath {
			t.Fatalf("a failure at %s does not name the instance it was applying: %+v", failing, failure)
		}
		// The preparation is never retried: the key is generated at most once,
		// whatever happened afterwards.
		if count(executor.effects, "GenerateLinkKey") > 1 {
			t.Fatalf("the failed preparation was retried at %s: %q", failing, executor.effects)
		}
		if expected == OutcomeRolledBack && executor.linkKeyPresent {
			t.Fatalf("a rollback at %s left the key the plan had generated: %+v", failing, executor)
		}
	}
}

// TestAPassageLeftInAPartialStateIsObservedInItsOwnWords is the limit of what
// this Auxiliary promises once a rollback has failed in its turn.
//
// A passage has no account and no container, so it is observed as what it
// actually is: a description, a key, an interface and a peer. The key is named
// present or absent and never by its value — an observation says what was seen,
// and what a key is is not something a report of this product may see.
func TestAPassageLeftInAPartialStateIsObservedInItsOwnWords(t *testing.T) {
	t.Parallel()
	executor := linkMachine()
	executor.failures["ReloadNetworkConfiguration"] = errors.New("the manager would not read it")
	accepted, input := approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)

	_, err := Apply(executor, accepted, input)
	var failure *ControlledFailure
	if !errors.As(err, &failure) {
		t.Fatalf("a failure after a mutation was reported as a plain refusal: %v", err)
	}
	if failure.Outcome != OutcomePartial || failure.Observed == nil {
		t.Fatalf("a rollback that failed claimed more than it reached: %+v", failure)
	}
	// The withdrawal got as far as removing the description and stopped at the
	// very reload that had failed the preparation, so the key it would have
	// removed last is still there. That is exactly the state worth naming: a
	// machine holding a key and no passage, which nothing but a read could have
	// established.
	observed := *failure.Observed
	if observed.LinkKey != observedPresent || observed.UnitFile != observedAbsent {
		t.Fatalf("the observation does not say what this machine was left holding: %+v", observed)
	}
	if observed.LinkPeer != observedAbsent || observed.LinkInterface != observedInactive {
		t.Fatalf("the observation claimed something no plan ever attached: %+v", observed)
	}
	// The four words of an account and a container are absent rather than
	// admitted unknown: nobody looked at them, because a passage has none.
	if observed.Account != "" || observed.Service != "" || observed.Container != "" {
		t.Fatalf("a passage was observed as if it had an account and a container: %+v", observed)
	}
	if !strings.Contains(err.Error(), "observed as description") {
		t.Fatalf("the partial state is not named in the words of a passage: %v", err)
	}
}

// TestNoOperationOfThePrivatePassageEverCarriesPrivateMaterial is the property
// the whole contract rests on, proven once over every path a value can leave by.
//
// The private key of this fake machine is a sentence rather than a plausible key,
// so a match below can only mean that something really did carry the private
// half. What is searched is everything a run produces: the conclusion, whatever
// error it failed with, every byte it wrote to this machine, and the observation
// a failed rollback leaves behind.
func TestNoOperationOfThePrivatePassageEverCarriesPrivateMaterial(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		machine  func() *fakeExecutor
		approved func(*testing.T) (*approval.Acceptance, *Input)
		failing  string
	}{
		"a preparation": {
			machine: linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
			},
		},
		"a preparation whose rollback failed in its turn": {
			machine: linkMachine,
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationPrepareLink, plan.LinkRoleListener)
			},
			failing: "ReloadNetworkConfiguration",
		},
		"a junction": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleInitiator) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedInitiatorPeer(t, plan.OperationJoinLinkPeer, fixturePort)
			},
		},
		"a departure": {
			machine: func() *fakeExecutor { return joinedLinkMachine(plan.LinkRoleListener) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedListenerPeer(t, plan.OperationDetachLinkPeer, fixturePort)
			},
		},
		"a withdrawal": {
			machine: func() *fakeExecutor { return preparedLinkMachine(plan.LinkRoleInitiator) },
			approved: func(t *testing.T) (*approval.Acceptance, *Input) {
				return approvedLink(t, plan.OperationWithdrawLink, plan.LinkRoleInitiator)
			},
		},
	} {
		executor := subject.machine()
		if subject.failing != "" {
			executor.failures[subject.failing] = errors.New("the machine refused this effect")
		}
		accepted, input := subject.approved(t)

		application, err := Apply(executor, accepted, input)

		said := []string{}
		if application != nil {
			rendered, marshalErr := json.Marshal(application)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			said = append(said, string(rendered))
		}
		if err != nil {
			said = append(said, err.Error())
			var failure *ControlledFailure
			if errors.As(err, &failure) && failure.Observed != nil {
				rendered, marshalErr := json.Marshal(failure.Observed)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				said = append(said, string(rendered))
			}
		}
		for path, content := range executor.files {
			said = append(said, path, string(content))
		}
		for _, spoken := range said {
			if strings.Contains(spoken, fixtureLinkPrivateKey) {
				t.Fatalf("%s carried the private key of its own machine: %q", name, spoken)
			}
		}
		// The public half is the one value that does travel, and only where the
		// contract says it does. The description names the private key by its
		// path, which is exactly how it is meant to be referred to.
		if executor.holds(linkNetdevPath) &&
			!strings.Contains(string(executor.held(linkNetdevPath)), "PrivateKeyFile="+linkPrivateKeyPath) {
			t.Fatalf("%s stopped naming the key by its path", name)
		}
	}
}
