package auxiliary

import (
	"bytes"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file is everything one name published through the private passage is on a
// machine: exactly one fragment file in the directory the entrypoint's file
// provider watches, and nothing else. It is the sibling of route.go, over the
// other backend, and everything the two share is read from there rather than
// written twice.
//
// Two values of a plan reach this file, and both are bounded before they arrive:
// the declared host, whose character set is the one a public route's is, and the
// backend port, an integer inside 1024..65535 which this machine has already
// required to be the port an approved junction bounds. Everything else — the
// directories, the address the backend is reached at, the entry point the router
// is attached to — is a constant of the contract, and the backend address is the
// constant of the passage rather than of this machine's own loopback.
//
// Three decisions of `#103` live here and are each written where they act: what
// the fragment declares and deliberately does not, what "the junction bounds this
// port" is read from, and what happens when the passage is down. The contract's
// addendum for that issue carries the same three in the words a reader of the
// architecture meets them in.

const (
	// fragmentKindLocal and fragmentKindPassage are how a fragment held on this
	// machine is named to a human when the two kinds meet on one declared name.
	//
	// They are sentences rather than identifiers because they only ever appear in
	// a refusal: nothing in this package branches on them, and what decides which
	// kind a fragment is, is the backend address that fragment itself names.
	fragmentKindLocal   = "a route towards a service of this machine"
	fragmentKindPassage = "a route through the private passage"
)

// renderLinkRouteFragment builds the one Traefik fragment a name published
// through the passage owns.
//
// It is the public route's fragment minus one thing and with one thing changed,
// and both are the contract read literally:
//
//   - the backend is the tunnel's peer constant on the approved port. No plan
//     names an address, there is no field for one, and the address written here
//     is the same constant the passage's own files are built from — so a fragment
//     can only ever point at the other end of the tunnel;
//   - there is no isolation middleware, and therefore no middlewares section at
//     all. Those two headers belong to the public profile, whose pinned edition
//     needs them; declaring them on a vault would be a control that grants
//     nothing, and a control that grants nothing still reads as a control that
//     was needed.
//
// What the fragment does not declare either is a proxy header, and that is a
// decision rather than an omission. Vaultwarden expects to learn the real client
// from `X-Real-IP` and the scheme and host from the `X-Forwarded-*` family;
// Traefik sets all of them on every request it forwards, without being asked.
// A headers middleware restating them would change nothing about what reaches
// the service and would read, to the next person, as a requirement the entry did
// not already meet. So the defaults are named here instead of being copied into
// the file.
//
// Everything else is the public fragment's argument unchanged: the router carries
// the declared name on the secure entry point alone, TLS is resolved from the
// certificate and the key of that name under the entry's certificate directory,
// and every place the name appears is a double-quoted YAML scalar whose character
// set contains neither a quote nor a backslash.
func renderLinkRouteFragment(host string, backendPort int) []byte {
	quoted := `"` + host + `"`
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
http:
  routers:
    %s:
      rule: "Host(`+"`"+`%s`+"`"+`)"
      entryPoints:
        - websecure
      service: %s
      tls: {}
  services:
    %s:
      loadBalancer:
        servers:
          - url: "http://%s:%d"
tls:
  certificates:
    - certFile: "%s/%s.crt"
      keyFile: "%s/%s.key"
`,
		quoted,
		host,
		quoted,
		quoted,
		linkInitiatorAddress, backendPort,
		entrypointCertificateDirectory, host,
		entrypointCertificateDirectory, host,
	))
}

// fragmentBackendMarker is the exact opening of the one backend line a fragment
// of either kind carries, for one backend address.
//
// It is what makes the kind of a fragment a fact about the file rather than a
// record this Auxiliary keeps: the two addresses are constants of two different
// contracts, neither is a prefix of the other, and a fragment names exactly one
// of them exactly once.
func fragmentBackendMarker(address string) []byte {
	return []byte(`- url: "http://` + address + `:`)
}

// requireUncontestedName refuses to publish one kind of route over a name this
// machine already publishes as the other kind.
//
// The two kinds share one namespace, and they have to: a declared name is one
// claim, one certificate, one router and one file, and a machine serving one name
// twice is the failure a deterministic file name exists to make impossible. What
// follows is that publishing a name as the other kind is not a drift the plan
// repairs. A drift is a machine that disagrees with the document it was given
// about how a state was reached; this is a machine that already serves that name
// from somewhere else, under a plan a human approved, and silently moving it
// would change what answers a public name without a single document saying so —
// from a local service to a tunnel, or from a tunnel to whatever holds that
// loopback port here.
//
// So it is refused, before any effect, and the order is left to the human: retire
// the name, then publish it as the other kind. Two plans, both read.
//
// A fragment naming neither backend is deliberately not refused here. That is an
// edited file of this machine's own kind, which is exactly what the byte
// comparison below already treats as a drift to reapply.
func requireUncontestedName(current []byte, present bool, host, heldAddress, heldKind, askedKind string) error {
	if !present || !bytes.Contains(current, fragmentBackendMarker(heldAddress)) {
		return nil
	}
	return fmt.Errorf(
		"this machine already publishes %s as %s and the approved plan publishes it as %s: a declared name is one claim, so what serves it does not change without that name being retired first, and this route is refused before any effect",
		host, heldKind, askedKind,
	)
}

// requireBoundedJunction holds the contract's presence rule for a name the
// passage carries against this machine, before anything is written.
//
// The rule has three parts and all three are read from what this machine itself
// holds, never from the document being applied:
//
//   - this machine holds the passage as the listener. The name is served by the
//     side the tunnel is answered on — the other side is where the service lives
//     — so a link route on the initiator is a plan aimed at the wrong machine;
//   - a junction is attached. The peer section of the interface's description is
//     what a junction wrote there, and a fragment towards a tunnel with no peer
//     would be a published name nothing could ever carry;
//   - the port the fragment names is the port that junction bounds. That fact is
//     read from the root-owned rules file the junction of `#97` wrote and loaded
//     into this kernel in the same effect. It is deliberately not read from the
//     description of the interface, which carries the peer and its single /32 and
//     no port whatsoever, and it is deliberately not believed from the plan: the
//     approved service port exists on this machine in exactly one place, and that
//     place is the table that lets it through.
//
// A fragment towards a port the tunnel does not bound is refused here, with
// nothing touched, because publishing it would produce a name that answers with
// the entry's gateway error and looks, to everything but this rule, like a route.
func requireBoundedJunction(executor Executor, backendPort int) error {
	where := linkPlacements[plan.LinkRoleListener]

	currentNetwork, networkPresent, err := executor.ReadUnitFile(linkNetworkPath)
	if err != nil {
		return fmt.Errorf("read the passage's current addressing: %w", err)
	}
	held, roleKnown, err := roleNamedBy(currentNetwork, networkPresent)
	if err != nil {
		return err
	}
	if !roleKnown || held.role != where.role {
		return fmt.Errorf(
			"this machine does not hold the passage as the %s: a name published through the passage is served by the side that answers the tunnel, so this route is refused before any effect",
			where.role,
		)
	}
	currentNetdev, netdevPresent, err := executor.ReadUnitFile(linkNetdevPath)
	if err != nil {
		return fmt.Errorf("read the passage's current description: %w", err)
	}
	if len(sectionAfter(currentNetdev, netdevPresent, linkPeerSectionMarker)) == 0 {
		return fmt.Errorf(
			"this machine holds no junction on %s: a name published through the passage names a peer nothing has attached, so this route is refused before any effect and the junction is applied by its own approved plan first",
			LinkInterfaceName,
		)
	}
	rules, rulesPresent, err := executor.LinkRules()
	if err != nil {
		return fmt.Errorf("read the bounds this machine holds on the passage: %w", err)
	}
	if !rulesPresent {
		return fmt.Errorf(
			"this machine holds no bounds on %s: the port a published name reaches through the passage is the port an approved junction bounds, and this machine holds no table naming one, so this route is refused before any effect",
			LinkInterfaceName,
		)
	}
	approved, readable := approvedServicePort(rules)
	if !readable {
		return fmt.Errorf(
			"the bounds this machine holds on %s name no approved service port: the port a published name reaches cannot be read back, so this route is refused before any effect",
			LinkInterfaceName,
		)
	}
	if approved != backendPort {
		return fmt.Errorf(
			"the junction of this machine bounds the passage to %s:%d and the approved plan publishes %d: a fragment towards a port the tunnel does not bound is refused before any effect",
			linkInitiatorAddress, approved, backendPort,
		)
	}
	return nil
}

// junctionState is whether this machine still holds the junction that carries a
// published name, read-only and in the two words this palier announces.
//
// It exists for the failure of the passage. A retirement does not need a junction
// and never refuses for the lack of one, but a machine whose junction is gone is
// exactly the state the contract wants visible — so the state is read and
// reported rather than left to be inferred from a name that stopped answering.
func junctionState(executor Executor) (string, error) {
	current, present, err := executor.ReadUnitFile(linkNetdevPath)
	if err != nil {
		return "", fmt.Errorf("read the passage's current description: %w", err)
	}
	if len(sectionAfter(current, present, linkPeerSectionMarker)) == 0 {
		return ServiceStateAbsent, nil
	}
	return ServiceStateActive, nil
}

// publishLinkRoute writes the one fragment a name carried by the passage owns,
// and says whether doing so changed anything.
//
// Everything that could refuse happens first and reads only: the entry has to be
// there, exactly as it does for a local route; this machine has to hold the
// listener's side of a junction bounding the very port the plan names; and the
// name must not already be published as the other kind. Only then is the fragment
// compared, byte for byte, against the one the plan describes — so republishing
// an identical route is not an action, and a fragment somebody edited is a drift
// the plan repairs rather than an error.
//
// The verification is the one deliberate coupling of this palier. It is a request
// through the entry, on the declared name, which therefore traverses the tunnel
// and reaches the service on the other machine: publishing a name this machine
// cannot serve is a controlled failure with a rollback, and never a success
// reported about a name that answers a gateway error. Verifying anything weaker —
// that the file is there, that the entry parsed it — would report a publication
// as proven while the thing it publishes is unreachable, which is precisely what
// the contract forbids. The order the plans are approved in is what makes the
// requirement fair: the service and the junction exist before the route naming
// them.
func publishLinkRoute(executor Executor, subject instance) (*Application, bool, error) {
	path := routeFragmentPath(subject.routeHost)
	desired := renderLinkRouteFragment(subject.routeHost, subject.backendPort)

	if err := requireEntrypointPresent(executor); err != nil {
		return nil, false, err
	}
	if err := requireBoundedJunction(executor, subject.backendPort); err != nil {
		return nil, false, err
	}
	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current route fragment: %w", err)
	}
	if err := requireUncontestedName(
		current, present, subject.routeHost,
		entrypointHostLoopbackAddress, fragmentKindLocal, fragmentKindPassage,
	); err != nil {
		return nil, false, err
	}
	if present && bytes.Equal(current, desired) {
		return &Application{
			Operation:    subject.operation,
			RouteHost:    subject.routeHost,
			FragmentPath: path,
			ServiceState: ServiceStateActive,
			PassageState: ServiceStateActive,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if err := executor.WriteUnitFile(path, desired); err != nil {
		return nil, touched, fmt.Errorf("write the route fragment: %w", err)
	}
	// The entry watches the directory, so nothing is reloaded and nothing is
	// restarted: a route is published by the file existing. What is verified is
	// that the name is actually served through the passage, from this machine and
	// with certificate verification deliberately skipped, because the certificate
	// of the declared name is the proof's business and not this Auxiliary's.
	if err := executor.LinkRouteAnswers(subject.routeHost); err != nil {
		return nil, touched, fmt.Errorf(
			"the route fragment was written but %s was not served through the passage from %s:%d: this machine held a published route whose announced state was unproven: %w",
			subject.routeHost, loopbackAddress, entrypointSecurePort, err,
		)
	}
	return &Application{
		Operation:    subject.operation,
		RouteHost:    subject.routeHost,
		FragmentPath: path,
		ServiceState: ServiceStateActive,
		PassageState: ServiceStateActive,
		Changed:      true,
	}, touched, nil
}

// retireLinkRoute removes exactly the fragment of one declared name, and leaves
// the passage and the service standing.
//
// It removes the fragment and nothing else: the interface, the peer, the bounds
// and the unit that puts them back are exactly where they were, every other
// fragment keeps being served, and the service at the other end of the tunnel
// keeps answering on its own machine. An absent fragment is not a failure and not
// a repair — it is the approved state, already held.
//
// What it does read beyond the fragment is whether the junction is still there,
// and it reads it for the report rather than for a decision. A retirement on a
// machine whose passage has fallen is a legitimate, useful operation — it is how
// a name stops answering at all instead of answering a gateway error — and the
// human who runs it is told which of the two situations they were in.
func retireLinkRoute(executor Executor, subject instance) (*Application, bool, error) {
	path := routeFragmentPath(subject.routeHost)
	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current route fragment: %w", err)
	}
	passage, err := junctionState(executor)
	if err != nil {
		return nil, false, err
	}
	if !present {
		return &Application{
			Operation:    subject.operation,
			RouteHost:    subject.routeHost,
			FragmentPath: path,
			ServiceState: ServiceStateAbsent,
			PassageState: passage,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if err := executor.RemoveUnitFile(path); err != nil {
		return nil, touched, fmt.Errorf("remove the route fragment: %w", err)
	}
	return &Application{
		Operation:    subject.operation,
		RouteHost:    subject.routeHost,
		FragmentPath: path,
		ServiceState: ServiceStateAbsent,
		PassageState: passage,
		Changed:      true,
	}, touched, nil
}
