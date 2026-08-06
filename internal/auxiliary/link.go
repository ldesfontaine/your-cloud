package auxiliary

import (
	"bytes"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file is everything one side of the private passage is on a machine: the
// key that is born here and never leaves, the closed WireGuard interface the two
// role constants describe, and the single peer a junction attaches to it.
//
// Three values of a plan reach this file, and all three are bounded before they
// arrive: the peer's public key, which the plan package has already required to
// be the one canonical spelling of thirty-two bytes; the endpoint host, bounded
// to the character set of a name; and the service port, an integer inside
// 1024..65535. Everything else — the subnet, the two addresses, the interface
// name, the listening port, the keepalive and the key's path — is a constant
// that the role decides, and no field of any plan reopens one of them.
//
// The passage is the one instance of this product that owns no account, no
// container and no image. It is a host-level identity held by root: the key is
// root's, the interface is the kernel's, and there is nothing here for a service
// account to run. That is why no placement appears below, and why the capability
// preflight of a passage asks for systemd and for nothing else.

const (
	// LinkInterfaceName is the one interface either machine holds for the
	// passage. Interface names are bounded to fifteen bytes and this one is well
	// inside that bound, so no machine of this product ever has to shorten it and
	// no two machines ever disagree about what it is called.
	LinkInterfaceName = "yc-link0"

	// linkListenPort is the UDP port the listener answers on and the port the
	// initiator reaches. It is a constant of the contract rather than a field of
	// a plan, on both sides at once: an endpoint port a request could choose
	// would be a passage a request could widen.
	linkListenPort = 51820

	// linkKeepaliveSeconds keeps the initiator's tunnel open through the NAT it
	// sits behind. It is written on the initiator alone, because the listener has
	// nothing to keep open — it never goes out.
	linkKeepaliveSeconds = 25

	// linkListenerAddress and linkInitiatorAddress are the two addresses of the
	// reserved subnet, one per role, and they are the whole of what either
	// machine knows of the other. AllowedIPs is the peer's own /32 and nothing
	// else: the LAN behind the initiator is never announced, never routed, and
	// the listener knows of it exactly one tunnel address.
	linkListenerAddress  = "10.66.66.1"
	linkInitiatorAddress = "10.66.66.2"

	// linkAddressPrefix is the length of every prefix this passage writes, for
	// the addresses of both machines and for the one route either of them holds.
	// A wider prefix anywhere here would be a subnet reachable through the
	// tunnel, which is exactly what naming a single address forbids.
	linkAddressPrefix = 32

	// linkRoot is the root-owned tree this machine's own passage key lives in,
	// and linkPrivateKeyPath is that key.
	//
	// Nothing in this package ever reads that file. The one seam that writes it
	// returns the public half and never the private one, so no value of this
	// process, no report and no journal of this product can carry what is in it.
	linkRoot           = "/etc/your-cloud/link"
	linkPrivateKeyPath = linkRoot + "/private.key"

	// networkConfigurationDirectory is where systemd-networkd reads the two files
	// that describe the passage, and the two paths below are those files.
	//
	// networkd is the persistence mechanism because the contract's rule about the
	// key decides it: a wg-quick configuration carries the private key inside the
	// file it is written into, so a machine holding one holds the key twice, in
	// two places with two modes. A .netdev names the key by its path instead, so
	// the key exists once, where this contract says it exists. Persistence across
	// a reboot then costs nothing extra: networkd creates the interface from
	// these two files at boot, so the passage comes back without an action —
	// which is precisely what the palier's proof requires.
	networkConfigurationDirectory = "/etc/systemd/network"
	linkNetdevPath                = networkConfigurationDirectory + "/" + LinkInterfaceName + ".netdev"
	linkNetworkPath               = networkConfigurationDirectory + "/" + LinkInterfaceName + ".network"

	// linkPeerSectionMarker and linkRouteSectionMarker separate what a
	// preparation owns in each of the two files from what a junction owns below
	// it.
	//
	// The division is the whole reason a preparation replayed after a junction
	// does not silently detach the peer: the head of each file is rendered from
	// the role's constants and the tail is taken from the machine exactly as it
	// was found. Retiring a junction takes the tail away and nothing else, and
	// withdrawing the passage refuses while a tail is there.
	linkPeerSectionMarker  = "\n[WireGuardPeer]\n"
	linkRouteSectionMarker = "\n[Route]\n"
)

// linkPlacement is everything one role of the passage is on a machine beyond the
// plan that describes it: the address this machine holds inside the tunnel, the
// one address it will ever know of its peer, and which of the two asymmetries of
// the contract this side carries.
//
// It is the passage's spelling of what placement is for a managed service, minus
// everything a passage does not have. There is no account, no home, no sheet, no
// container and no image here, because a passage is none of those things.
type linkPlacement struct {
	// role is the name the contract gives this side, and the word a refusal uses
	// when a machine is asked to hold the other one.
	role string
	// address is this machine's own address inside the tunnel, and peerAddress is
	// the single /32 it will ever route towards or accept from.
	address     string
	peerAddress string
	// listens is true for the side that answers on the port of the contract, and
	// goesOut for the side that reaches an endpoint and keeps the tunnel alive.
	// Exactly one of them is true for either role: the asymmetry is in the roles
	// and in the operations, never in a field left empty.
	listens bool
	goesOut bool
}

// linkPlacements is the closed list of roles this Auxiliary holds, and the one
// set of constants each of them means.
//
// It is held here rather than derived from the plan package's own closed list,
// for the same reason the service profiles are: a role added to a plan does not
// silently become a role this machine will configure.
var linkPlacements = map[string]linkPlacement{
	plan.LinkRoleListener: {
		role:        plan.LinkRoleListener,
		address:     linkListenerAddress,
		peerAddress: linkInitiatorAddress,
		listens:     true,
	},
	plan.LinkRoleInitiator: {
		role:        plan.LinkRoleInitiator,
		address:     linkInitiatorAddress,
		peerAddress: linkListenerAddress,
		goesOut:     true,
	},
}

// LinkNetdevPath is the file that describes this machine's passage, and the one
// a report names when it names the instance it acted on. The key's own path is
// deliberately not exported beside it: nothing outside this package has any
// business naming it, and a path nobody exports is a path no caller can be
// tempted to read.
func LinkNetdevPath() string { return linkNetdevPath }

// linkPlacementFor is the role's constants, or a refusal.
//
// The plan package already refuses a role outside the closed list before a
// document is even hashed, so this is the second reading of one decision rather
// than a parser: a role this Auxiliary has no constants for is refused before
// any effect, because there is nothing for it to be.
func linkPlacementFor(role string) (linkPlacement, error) {
	where, known := linkPlacements[role]
	if !known {
		return linkPlacement{}, fmt.Errorf("plan link_role %q is not one this Auxiliary holds", role)
	}
	return where, nil
}

// renderLinkNetdev builds the head of the interface's description: the closed
// WireGuard device, its key by path, and the listening port of the side that has
// one.
//
// No value of a plan reaches it. The interface name, the kind, the path of the
// key and the port are constants, and the role is what decides whether the port
// line exists at all — the initiator carries none, because a machine that never
// answers must not hold a socket that could.
func renderLinkNetdev(where linkPlacement) []byte {
	listen := ""
	if where.listens {
		listen = fmt.Sprintf("ListenPort=%d\n", linkListenPort)
	}
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[NetDev]
Name=%s
Kind=wireguard
Description=Your Cloud private passage (%s)

[WireGuard]
PrivateKeyFile=%s
%s`, LinkInterfaceName, where.role, linkPrivateKeyPath, listen))
}

// renderLinkPeerSection builds the tail one junction owns in that file: exactly
// one peer, named by the public key its own preparation reported, and the single
// /32 that peer is allowed to be.
//
// The endpoint and the keepalive exist on the initiator alone. The listener has
// nowhere to reach and nothing to keep open, so its section carries neither —
// absent rather than empty, exactly as the operations of the contract are.
func renderLinkPeerSection(where linkPlacement, peerPublicKey, peerEndpointHost string) []byte {
	section := fmt.Sprintf("%sPublicKey=%s\nAllowedIPs=%s/%d\n",
		linkPeerSectionMarker, peerPublicKey, where.peerAddress, linkAddressPrefix)
	if where.goesOut {
		section += fmt.Sprintf("Endpoint=%s:%d\nPersistentKeepalive=%d\n",
			peerEndpointHost, linkListenPort, linkKeepaliveSeconds)
	}
	return []byte(section)
}

// renderLinkNetwork builds the head of the interface's own addressing: the one
// address this machine holds inside the tunnel, as a /32.
func renderLinkNetwork(where linkPlacement) []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Match]
Name=%s

[Network]
Address=%s/%d
`, LinkInterfaceName, where.address, linkAddressPrefix))
}

// renderLinkRouteSection builds the tail one junction owns in that file.
//
// It exists because both addresses are /32 and a /32 gives this machine no route
// to anything: without one line naming the peer's own address on this interface,
// the tunnel would be established and unusable. The destination is the role's
// peer address — a constant, not a plan value — so what the route reaches is
// exactly what AllowedIPs allows and never one address more. It is written with
// the junction and taken away with it: a machine with no peer holds no route to
// an address nothing answers at.
func renderLinkRouteSection(where linkPlacement) []byte {
	return []byte(fmt.Sprintf("%sDestination=%s/%d\nScope=link\n",
		linkRouteSectionMarker, where.peerAddress, linkAddressPrefix))
}

// sectionAfter returns what one file holds from a marker onwards, or nothing.
//
// It is how an operation carries forward the part of a file another plan owns,
// verbatim: a preparation replayed on a joined machine writes back the very
// bytes the junction wrote, so replaying the four plans of the contract changes
// nothing rather than undoing the third with the first.
func sectionAfter(content []byte, present bool, marker string) []byte {
	if !present {
		return nil
	}
	index := bytes.Index(content, []byte(marker))
	if index < 0 {
		return nil
	}
	return content[index:]
}

// roleNamedBy reads back which role this machine already holds, from the address
// its own passage file names.
//
// The address a machine holds inside the tunnel *is* its role — the two are one
// constant of the contract — so reading the address back is reading the role
// back, rather than trusting a record this Auxiliary does not keep. A file that
// is there and names neither address is a drift nothing can attribute to a role,
// and it is refused by name rather than guessed at: acting on it would mean
// choosing a side for a machine on this Auxiliary's own authority.
func roleNamedBy(content []byte, present bool) (linkPlacement, bool, error) {
	if !present {
		return linkPlacement{}, false, nil
	}
	for _, where := range []linkPlacement{
		linkPlacements[plan.LinkRoleListener],
		linkPlacements[plan.LinkRoleInitiator],
	} {
		if bytes.Contains(content, []byte(fmt.Sprintf("\nAddress=%s/%d\n", where.address, linkAddressPrefix))) {
			return where, true, nil
		}
	}
	return linkPlacement{}, false, fmt.Errorf(
		"this machine holds a %s that names no address of the reserved subnet: the role of this machine cannot be read back, so the passage is refused before any effect",
		linkNetworkPath,
	)
}

// prepareLink brings this machine to the state one side of the passage
// describes, and says whether doing so changed anything.
//
// The key is the part that is not like anything else in this package. It is
// generated here, once, and never again: an existing key is carried forward
// untouched, so a preparation replayed on a prepared machine reports the very
// public key the Controller already read, with nothing changed. Replacing a key
// is a withdrawal followed by a preparation — two plans a human sees — and never
// a silent regeneration behind an operation that claims to be idempotent.
//
// The order below is the argument and is written once, here:
//
//  1. the role this machine already holds is read back before anything is
//     decided, so that a preparation naming the other one is refused while this
//     machine is still untouched;
//  2. the key exists before a file names it, because networkd reads the path the
//     description gives it and a description pointing at nothing is an interface
//     that will never come up;
//  3. the two files are on disk before the network manager is asked to read
//     them;
//  4. networkd is enabled and running before the reload that creates the
//     interface, because a reload asked of a manager that is not running is not
//     an error and not an effect either — it is a machine that quietly holds no
//     passage;
//  5. and only then is the announced state verified: the interface this machine
//     just described has to actually be there.
func prepareLink(executor Executor, subject instance) (*Application, bool, error) {
	where, err := linkPlacementFor(subject.linkRole)
	if err != nil {
		return nil, false, err
	}

	currentNetwork, networkPresent, err := executor.ReadUnitFile(linkNetworkPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current addressing: %w", err)
	}
	held, roleKnown, err := roleNamedBy(currentNetwork, networkPresent)
	if err != nil {
		return nil, false, err
	}
	if roleKnown && held.role != where.role {
		return nil, false, fmt.Errorf(
			"this machine already holds the passage as the %s and the approved plan prepares it as the %s: a machine has one role per link, so changing it is a withdrawal followed by a preparation — two plans a human reads — and this one is refused before any effect",
			held.role, where.role,
		)
	}
	currentNetdev, netdevPresent, err := executor.ReadUnitFile(linkNetdevPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current description: %w", err)
	}
	publicKey, keyPresent, err := executor.LinkPublicKey()
	if err != nil {
		return nil, false, fmt.Errorf("read this machine's own passage key: %w", err)
	}
	established, err := executor.LinkInterfaceActive()
	if err != nil {
		return nil, false, fmt.Errorf("read the current state of %s: %w", LinkInterfaceName, err)
	}

	// What a junction wrote is carried forward exactly as it was found. A
	// preparation owns the head of each file and nothing below it.
	desiredNetdev := append(renderLinkNetdev(where),
		sectionAfter(currentNetdev, netdevPresent, linkPeerSectionMarker)...)
	desiredNetwork := append(renderLinkNetwork(where),
		sectionAfter(currentNetwork, networkPresent, linkRouteSectionMarker)...)

	if keyPresent &&
		netdevPresent && bytes.Equal(currentNetdev, desiredNetdev) &&
		networkPresent && bytes.Equal(currentNetwork, desiredNetwork) &&
		established {
		// The approved state already holds, down to the bytes of both files and
		// the interface being there. Nothing is written, nothing is reloaded and
		// no key is generated: a plan that demands what is already true is not an
		// action. The public key is still reported, because it is an observation
		// the Controller reads rather than something this run produced.
		return &Application{
			Operation:     subject.operation,
			UnitPath:      linkNetdevPath,
			LinkPublicKey: publicKey,
			ServiceState:  ServiceStateActive,
			Changed:       false,
		}, false, nil
	}

	// Everything below this line changes the machine, so every failure below it
	// is a controlled failure and not a refusal.
	const touched = true

	if !keyPresent {
		generated, err := executor.GenerateLinkKey()
		if err != nil {
			return nil, touched, fmt.Errorf("generate this machine's own passage key: %w", err)
		}
		publicKey = generated
	}
	if err := executor.WriteUnitFile(linkNetdevPath, desiredNetdev); err != nil {
		return nil, touched, fmt.Errorf("write the passage's description: %w", err)
	}
	if err := executor.WriteUnitFile(linkNetworkPath, desiredNetwork); err != nil {
		return nil, touched, fmt.Errorf("write the passage's addressing: %w", err)
	}
	if err := executor.EnableNetworkManagement(); err != nil {
		return nil, touched, fmt.Errorf("make this machine's network manager hold the passage: %w", err)
	}
	if err := executor.ReloadNetworkConfiguration(); err != nil {
		return nil, touched, fmt.Errorf("make the network manager read the passage: %w", err)
	}
	established, err = executor.LinkInterfaceActive()
	if err != nil {
		return nil, touched, fmt.Errorf("read %s back after describing it: %w", LinkInterfaceName, err)
	}
	if !established {
		return nil, touched, fmt.Errorf(
			"the passage was described but %s never appeared: this machine held a described passage whose announced state was unproven",
			LinkInterfaceName,
		)
	}
	return &Application{
		Operation:     subject.operation,
		UnitPath:      linkNetdevPath,
		LinkPublicKey: publicKey,
		ServiceState:  ServiceStateActive,
		Changed:       true,
	}, touched, nil
}

// withdrawLink takes this machine's side of the passage away and leaves nothing
// of it behind, and refuses to do so while a junction is still attached.
//
// The refusal is the mirror of the one removeEntrypoint takes, and it is one
// decision read from both ends: withdrawing takes the interface and the key
// away, so a peer still attached to it would stop being reachable without a
// single plan saying so. The order of a removal is a sequencing concern of the
// plans a human approves — undo the junction, then withdraw the passage — so the
// refusal names what is in the way rather than deciding for the human what
// happens to it.
//
// What is not undone is named rather than hidden: the network manager stays
// enabled. It manages exactly the interfaces its own files match, and this
// operation removes this product's files; disabling a machine's network manager
// as a side effect of retiring a tunnel is a liberty this product does not take.
//
// The role the plan names is deliberately not held against the role this machine
// holds. A withdrawal reaches the same state from either side — no interface, no
// key, no description — so a refusal here would protect nothing and would leave
// a machine whose role somebody confused with no plan able to clean it up. The
// role is read back where it decides something, which is the preparation and the
// junctions, and nowhere else.
func withdrawLink(executor Executor, subject instance) (*Application, bool, error) {
	currentNetdev, netdevPresent, err := executor.ReadUnitFile(linkNetdevPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current description: %w", err)
	}
	if len(sectionAfter(currentNetdev, netdevPresent, linkPeerSectionMarker)) != 0 {
		return nil, false, fmt.Errorf(
			"this machine still holds a junction on %s: withdrawing the passage would take that peer and its bounds away without a plan saying so, so it is refused before any effect and the junction is undone by its own approved plan first",
			LinkInterfaceName,
		)
	}
	// The bounds are part of the same refusal, and not of the same reading: a
	// machine whose peer is gone and whose table is still posed is a departure
	// that stopped halfway, and withdrawing over it would leave a table, a unit
	// and a host relaxation behind — which is exactly what this operation
	// promises not to do. The departure's own approved plan takes them away.
	bounded, err := linkBoundsLeftBehind(executor)
	if err != nil {
		return nil, false, err
	}
	if bounded {
		return nil, false, fmt.Errorf(
			"this machine still holds the bounds of a junction on %s: withdrawing the passage would leave them behind with nothing left to bound, so it is refused before any effect and the junction is undone by its own approved plan first",
			LinkInterfaceName,
		)
	}
	_, networkPresent, err := executor.ReadUnitFile(linkNetworkPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current addressing: %w", err)
	}
	_, keyPresent, err := executor.LinkPublicKey()
	if err != nil {
		return nil, false, fmt.Errorf("read this machine's own passage key: %w", err)
	}
	established, err := executor.LinkInterfaceActive()
	if err != nil {
		return nil, false, fmt.Errorf("read the current state of %s: %w", LinkInterfaceName, err)
	}

	if !netdevPresent && !networkPresent && !keyPresent && !established {
		return &Application{
			Operation:    subject.operation,
			UnitPath:     linkNetdevPath,
			ServiceState: ServiceStateAbsent,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	// The interface goes first, for the same reason the entrypoint's service is
	// stopped before its policy is removed: nothing is ever running under a
	// description this machine has already forgotten.
	if established {
		if err := executor.RemoveLinkInterface(); err != nil {
			return nil, touched, fmt.Errorf("take %s down: %w", LinkInterfaceName, err)
		}
	}
	if netdevPresent {
		if err := executor.RemoveUnitFile(linkNetdevPath); err != nil {
			return nil, touched, fmt.Errorf("remove the passage's description: %w", err)
		}
	}
	if networkPresent {
		if err := executor.RemoveUnitFile(linkNetworkPath); err != nil {
			return nil, touched, fmt.Errorf("remove the passage's addressing: %w", err)
		}
	}
	if netdevPresent || networkPresent {
		if err := executor.ReloadNetworkConfiguration(); err != nil {
			return nil, touched, fmt.Errorf("make the network manager forget the passage: %w", err)
		}
	}
	// The key goes last. It is the one thing here that cannot be rebuilt from a
	// constant, so it is taken away only once everything that referred to it is
	// already gone.
	if keyPresent {
		if err := executor.RemoveLinkKey(); err != nil {
			return nil, touched, fmt.Errorf("remove this machine's own passage key: %w", err)
		}
	}
	return &Application{
		Operation:    subject.operation,
		UnitPath:     linkNetdevPath,
		ServiceState: ServiceStateAbsent,
		Changed:      true,
	}, touched, nil
}

// joinLinkPeer attaches exactly one peer to the passage this machine already
// holds, and says whether doing so changed anything.
//
// It is one function for both sides on purpose. The asymmetry of the contract
// lives in the operations and in the role's constants — the listener has no
// endpoint to reach and no keepalive to hold, and its plan carries neither field
// — so the flow itself is the same on both machines and there is no branch here
// that a reader has to hold two versions of in their head.
//
// Everything that could refuse happens first and reads only: this machine has to
// hold a prepared passage, it has to hold it in the role this junction is for,
// and — on the machine the service actually lives on — the approved port has to
// be one a managed service of this machine publishes. A junction written on a
// machine with no key and no interface would be a peer attached to nothing, and
// it is refused by name while that machine is still untouched.
//
// What a junction writes beyond its peer is the bounds of the passage: the one
// nftables table of this role, the host relaxation the initiator's redirection
// needs, and the unit that puts both back at the next boot. They are posed
// before the peer, and the whole of why is written where they are.
func joinLinkPeer(executor Executor, subject instance) (*Application, bool, error) {
	where, err := linkPlacementFor(subject.linkRole)
	if err != nil {
		return nil, false, err
	}

	currentNetwork, networkPresent, err := executor.ReadUnitFile(linkNetworkPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current addressing: %w", err)
	}
	held, roleKnown, err := roleNamedBy(currentNetwork, networkPresent)
	if err != nil {
		return nil, false, err
	}
	currentNetdev, netdevPresent, err := executor.ReadUnitFile(linkNetdevPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current description: %w", err)
	}
	_, keyPresent, err := executor.LinkPublicKey()
	if err != nil {
		return nil, false, fmt.Errorf("read this machine's own passage key: %w", err)
	}
	if !keyPresent || !netdevPresent || !roleKnown {
		return nil, false, fmt.Errorf(
			"this machine holds no prepared passage: a junction attaches a peer to an interface and a key this machine already has, so it is refused before any effect and the preparation is applied by its own approved plan first",
		)
	}
	if held.role != where.role {
		return nil, false, fmt.Errorf(
			"this machine holds the passage as the %s and the approved plan is the %s's junction: the two sides are not interchangeable, so this junction is refused before any effect",
			held.role, where.role,
		)
	}
	// The bounding table of this palier and the rule that the service port must
	// name a managed service present on the joined machine both live here, in
	// this read-only stretch, beside the refusals above and before the first
	// effect below. A port nothing manages is refused with this machine still
	// untouched, exactly as a route towards one is.
	if err := requireBoundedService(executor, where, subject.servicePort); err != nil {
		return nil, false, err
	}
	bounds, err := readLinkBounds(executor, where, subject.servicePort)
	if err != nil {
		return nil, false, err
	}
	established, err := executor.LinkInterfaceActive()
	if err != nil {
		return nil, false, fmt.Errorf("read the current state of %s: %w", LinkInterfaceName, err)
	}

	// The head of each file is rendered from the role's constants here as it is
	// in a preparation, so a junction never carries forward a head somebody
	// edited. What the division of the two files decides is who owns the *peer* —
	// a preparation carries an attached peer forward untouched — and not who is
	// allowed to write a constant back where it belongs.

	desiredNetdev := append(renderLinkNetdev(where),
		renderLinkPeerSection(where, subject.peerPublicKey, subject.peerEndpointHost)...)
	desiredNetwork := append(renderLinkNetwork(where), renderLinkRouteSection(where)...)

	if bytes.Equal(currentNetdev, desiredNetdev) &&
		networkPresent && bytes.Equal(currentNetwork, desiredNetwork) &&
		bounds.held &&
		established {
		return &Application{
			Operation:    subject.operation,
			UnitPath:     linkNetdevPath,
			ServiceState: ServiceStateActive,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	// The bounds are posed here, before the peer exists rather than after it: a
	// passage that carried anything at all before its bounds were posed would be
	// a passage that was briefly unbounded. Their own order is fixed once, where
	// they are written, and a table that drifted is reapplied from here — the
	// whole file is rewritten, so reaching the approved bounds again is one
	// application and never an accumulation.
	if err := poseLinkBounds(executor, where, subject.servicePort); err != nil {
		return nil, touched, err
	}

	if err := executor.WriteUnitFile(linkNetdevPath, desiredNetdev); err != nil {
		return nil, touched, fmt.Errorf("write the peer of the passage: %w", err)
	}
	if err := executor.WriteUnitFile(linkNetworkPath, desiredNetwork); err != nil {
		return nil, touched, fmt.Errorf("write the route of the passage: %w", err)
	}
	if err := executor.ReloadNetworkConfiguration(); err != nil {
		return nil, touched, fmt.Errorf("make the network manager read the junction: %w", err)
	}
	// What a junction would want verified locally is a handshake, and a handshake
	// is a fact about two machines rather than about this one: the other side may
	// legitimately not be prepared yet, since the contract sequences the listener
	// before the initiator. So nothing is claimed here beyond what this machine
	// itself now holds, and the tunnel actually carrying the approved service is
	// the constat of `#98`.
	return &Application{
		Operation:    subject.operation,
		UnitPath:     linkNetdevPath,
		ServiceState: ServiceStateActive,
		Changed:      true,
	}, touched, nil
}

// partLinkPeer detaches exactly the peer the approved plan names together with
// the bounds that peer was posed with, and leaves the passage itself standing.
//
// What it removes is the junction and nothing else: the table this junction
// posed is deleted by its own name, so every other table this machine carries is
// untouched, and the interface, the key, the machine's own address and its
// network manager are exactly where they were.
//
// An absent peer is not a failure and not a repair: it is the approved state,
// already held, and nothing is touched to announce it. A peer that is there but
// is not the one the plan names is refused instead — undoing it would take away
// something no human approved the removal of, and the machine holding another
// peer than the plan expects is exactly the disagreement a refusal exists for.
func partLinkPeer(executor Executor, subject instance) (*Application, bool, error) {
	where, err := linkPlacementFor(subject.linkRole)
	if err != nil {
		return nil, false, err
	}

	currentNetdev, netdevPresent, err := executor.ReadUnitFile(linkNetdevPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current description: %w", err)
	}
	currentNetwork, networkPresent, err := executor.ReadUnitFile(linkNetworkPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the passage's current addressing: %w", err)
	}
	peer := sectionAfter(currentNetdev, netdevPresent, linkPeerSectionMarker)
	route := sectionAfter(currentNetwork, networkPresent, linkRouteSectionMarker)
	bounds, err := readLinkBounds(executor, where, subject.servicePort)
	if err != nil {
		return nil, false, err
	}

	// The bounds are part of what a departure undoes, so they are part of what
	// decides that there is nothing to undo. A machine holding no peer and a
	// table somebody left behind is not the approved state: it is a drift, and
	// the departure takes the leftovers away rather than announcing that all is
	// well.
	if len(peer) == 0 && len(route) == 0 && !bounds.present() {
		return &Application{
			Operation:    subject.operation,
			UnitPath:     linkNetdevPath,
			ServiceState: ServiceStateAbsent,
			Changed:      false,
		}, false, nil
	}

	held, roleKnown, err := roleNamedBy(currentNetwork, networkPresent)
	if err != nil {
		return nil, false, err
	}
	if !roleKnown || held.role != where.role {
		return nil, false, fmt.Errorf(
			"the approved plan undoes the %s's junction and this machine does not hold the passage in that role: it is refused before any effect",
			where.role,
		)
	}
	// The peer is held against the one the plan names only where there is a peer
	// to hold: a machine that has already lost its peer and still carries the
	// bounds of it is undone by this plan, and refusing it for a peer that is not
	// there would leave a table nothing would ever take away.
	if len(peer) != 0 && !bytes.Contains(peer, []byte("\nPublicKey="+subject.peerPublicKey+"\n")) {
		return nil, false, fmt.Errorf(
			"this machine holds another peer than the one the approved plan names: undoing it would take away a junction no human approved the removal of, so it is refused before any effect",
		)
	}

	// Everything below this line changes the machine.
	const touched = true

	if err := executor.WriteUnitFile(linkNetdevPath, renderLinkNetdev(where)); err != nil {
		return nil, touched, fmt.Errorf("remove the peer of the passage: %w", err)
	}
	if err := executor.WriteUnitFile(linkNetworkPath, renderLinkNetwork(where)); err != nil {
		return nil, touched, fmt.Errorf("remove the route of the passage: %w", err)
	}
	if err := executor.ReloadNetworkConfiguration(); err != nil {
		return nil, touched, fmt.Errorf("make the network manager read the detachment: %w", err)
	}
	// The bounds are removed here, once the peer is gone and not before it. `#96`
	// pencilled this seam at the head of this stretch and it is written below it
	// instead, for the reason the junction poses them before its peer: bounds
	// removed first would leave a peer that nothing bounds for as long as the
	// detachment takes, which is the one state neither operation may pass
	// through. What a departure cuts by removing them last is an established
	// service flow whose peer has already stopped being reachable.
	if err := removeLinkBounds(executor, bounds); err != nil {
		return nil, touched, err
	}
	return &Application{
		Operation:    subject.operation,
		UnitPath:     linkNetdevPath,
		ServiceState: ServiceStateAbsent,
		Changed:      true,
	}, touched, nil
}

// observeLink establishes what can still be established about a passage after a
// rollback has itself failed, in the same closed vocabulary as everything else.
//
// Every call is read-only and every one of them may fail without that failure
// becoming a claim. The key is reported present or absent and never by its
// value: the public half would say more than an observation needs, and the
// private half is not something any function of this package can reach.
func observeLink(executor Executor) Observation {
	observed := Observation{
		UnitFile:      observedUnknown,
		LinkKey:       observedUnknown,
		LinkInterface: observedUnknown,
		LinkPeer:      observedUnknown,
		LinkBounds:    observedUnknown,
	}
	if content, present, err := executor.ReadUnitFile(linkNetdevPath); err == nil {
		observed.UnitFile = observedAbsent
		observed.LinkPeer = observedAbsent
		if present {
			observed.UnitFile = observedPresent
			if len(sectionAfter(content, present, linkPeerSectionMarker)) != 0 {
				observed.LinkPeer = observedPresent
			}
		}
	}
	if _, present, err := executor.LinkPublicKey(); err == nil {
		observed.LinkKey = observedAbsent
		if present {
			observed.LinkKey = observedPresent
		}
	}
	if established, err := executor.LinkInterfaceActive(); err == nil {
		observed.LinkInterface = observedInactive
		if established {
			observed.LinkInterface = observedActive
		}
	}
	// The bounds are read as one word for the three files they are made of, and
	// the word is deliberately the widest of the three: anything of them still
	// there is a passage this machine is still bounding, and a human reading this
	// needs to know that something is left rather than which file it is.
	if bounded, err := linkBoundsLeftBehind(executor); err == nil {
		observed.LinkBounds = observedAbsent
		if bounded {
			observed.LinkBounds = observedPresent
		}
	}
	return observed
}
