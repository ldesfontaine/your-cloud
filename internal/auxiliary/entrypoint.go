package auxiliary

import (
	"bytes"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file is everything the public entrypoint is on a machine: the account it
// runs as, the sheet that declares its container, the static Traefik
// configuration it reads, the host policy that lets a rootless account hold the
// two public ports, and the bounded local verification that the entry reached
// the state this machine announces.
//
// Not one value below comes from a plan. An entrypoint plan carries its
// existence and the pinned image, and nothing else — no port, no address, no
// directory — so every byte this file writes is a constant of the contract. That
// is why the sheet and the configuration are rendered by functions taking no
// argument at all: a value that cannot be passed cannot be smuggled.

const (
	// EntrypointAccount is the per-entrypoint system account Traefik runs under,
	// and EntrypointHome is its own home. It is a third account beside the
	// probe's and the profile's, for the same reason those two are separate: the
	// one identity allowed to listen publicly owns nothing but the entry.
	EntrypointAccount = "your-cloud-entrypoint"
	EntrypointHome    = "/var/lib/" + EntrypointAccount

	// entrypointRoot is the root-owned tree the Auxiliary writes and the entry's
	// account only ever reads. It lives outside that account's home on purpose:
	// the account that runs the entry may not rewrite the routes it serves, and a
	// directory under its own home would be one it could.
	entrypointRoot = "/etc/your-cloud/entrypoint"

	// entrypointConfigurationPath is the static configuration of Traefik, and
	// entrypointFragmentDirectory is the one directory its file provider watches.
	// entrypointCertificateDirectory is where the certificate and the key of a
	// declared name are read from; nothing in this package ever writes into it,
	// because no plan of this palier describes a certificate.
	entrypointConfigurationPath    = entrypointRoot + "/traefik.yaml"
	entrypointFragmentDirectory    = entrypointRoot + "/dynamic"
	entrypointCertificateDirectory = entrypointRoot + "/certificates"

	// entrypointConfigurationMount is where the static configuration is mounted
	// inside the container. It is the one path of the three that differs between
	// the host and the namespace, and it differs on purpose: Traefik reads
	// `/etc/traefik/traefik.yaml` without being told to, so mounting the file
	// there is what keeps the sheet free of a command line. The two directories
	// are mounted at their own host paths instead, so that the paths written
	// inside the configuration and inside every fragment mean the same thing on
	// both sides of the namespace.
	entrypointConfigurationMount = "/etc/traefik/traefik.yaml"

	// entrypointSecurePort and entrypointClearPort are the two ports the entry
	// holds, on the host and inside its namespace alike. They are constants of
	// the contract and never fields of a plan: an entrypoint has nothing
	// approvable beyond its existence and its image.
	entrypointSecurePort = 443
	entrypointClearPort  = 80

	// entrypointDialTimeoutSeconds and entrypointResponseHeaderTimeoutSeconds
	// bound how long the entry waits for a backend that is not answering before
	// it says so. Both are needed, and the machine proof of `#104` is why.
	//
	// The dial bound was written first, against the failure everyone expects: a
	// backend that cannot be reached at all. It works — a destination that
	// silently drops packets renders a gateway error in five seconds instead of
	// hanging — and it was not enough. A backend behind a fallen private
	// passage does not always refuse the connection and does not always swallow
	// it: through the rootless stack the entry runs behind, the connection can
	// be *accepted* and then answered by nobody. The dial has succeeded, so no
	// dial bound applies, and the entry waits for a first response header that
	// never comes. Measured on the machine: ninety seconds, then the client
	// gave up first and read nothing at all.
	//
	// So the wait for the first header is bounded too, and the two values are
	// chosen against the failures they stand between. A backend on this
	// machine's own loopback answers in microseconds and one across a standing
	// passage in milliseconds, so five seconds is far beyond any healthy dial
	// and ten seconds far beyond any healthy first header — the bound is on the
	// header, not on the body, so a large answer is never cut short. They are
	// constants of the contract for the same reason the ports are: an entry has
	// nothing approvable beyond its existence and its image.
	entrypointDialTimeoutSeconds           = 5
	entrypointResponseHeaderTimeoutSeconds = 10

	// hostPortsPolicyPath is where the one host relaxation this product allows
	// itself is written, and hostPortsPolicy is exactly what is written there.
	//
	// It is a declared effect of the entrypoint plan rather than a step of a
	// bootstrap: the human who approves an entry approves the machine letting
	// unprivileged accounts bind from port 80 upwards, and removing the entry
	// removes the file and re-applies what is left. The file carries the product
	// name so that an administrator reading /etc/sysctl.d learns which plan owns
	// it.
	hostPortsPolicyPath = "/etc/sysctl.d/your-cloud-entrypoint.conf"

	// entrypointHostLoopbackAddress is the address at which the entry's container
	// reaches this machine's own loopback.
	//
	// The mechanism is named in the sheet as `Network=slirp4netns:allow_host_loopback=true`
	// and the address is that stack's own fixed gateway. Two other answers were
	// considered and rejected: `Network=host` would put the entry in the host's
	// network namespace, which widens the container far beyond the one reachable
	// port this contract wants, and pasta's `--map-guest-addr` names an address
	// whose default has moved across Podman releases, so a fragment written today
	// would name a different address tomorrow. What is written here is a constant
	// of the network stack rather than of a release.
	//
	// The residual widening is real and is named rather than hidden: the entry's
	// container can reach every service on this machine's loopback, not only the
	// backend a plan approved. `#92` must constat that the declared route is
	// actually served through this address.
	entrypointHostLoopbackAddress = "10.0.2.2"
)

// entrypointPlacement is where the one public entrypoint of this palier lives.
//
// It reuses the placement of a managed service for everything the two really
// share — an account with explicitly allocated subordinate ranges, linger, a
// root-owned sheet under that account's own home, reload, start, stop and the
// drift computation — and for nothing else. The two fields a managed service
// carries about its own answer are deliberately zero here: an entry publishes no
// loopback port and its local verification is not an HTTP 200, so a value that
// would only be read by the service path is not invented for it.
var entrypointPlacement = placement{
	account:       EntrypointAccount,
	home:          EntrypointHome,
	comment:       "Your Cloud public HTTPS entrypoint",
	description:   "Your Cloud public HTTPS entrypoint",
	unitFileName:  EntrypointAccount + ".container",
	serviceName:   EntrypointAccount + ".service",
	containerName: EntrypointAccount,
	image:         plan.EntrypointImageReference + "@" + plan.EntrypointImageDigest,
}

// EntrypointUnitPath is the sheet this package writes for the entrypoint, and
// EntrypointFragmentDirectory is the directory its routes are written into.
func EntrypointUnitPath() string          { return entrypointPlacement.unitPath() }
func EntrypointFragmentDirectory() string { return entrypointFragmentDirectory }

// renderEntrypointSheet builds the Quadlet sheet of the public entrypoint.
//
// It takes no argument because there is nothing to pass: an entrypoint plan has
// no free value at all, so this sheet is the same bytes on every machine and in
// every run. The three mounts, the two published ports and every control below
// come from the constants of this file.
//
// The sheet differs from a managed service's in exactly four ways, and each of
// them is owed an explanation:
//
//   - it carries Volume= lines, which no service sheet may. A managed service
//     has no file to read and no plan field that could describe one; the entry
//     reads its own configuration, the routes a human approved and the
//     certificates of the declared names. All three are root-owned on the host,
//     written by the Auxiliary, and mounted read-only, so the account that runs
//     the entry reads what it serves and can never write it;
//   - it publishes on every address rather than on the loopback, because being
//     the one thing that listens publicly is what an entrypoint is;
//   - it carries the namespace-scoped low-port sysctl, because Traefik binds 443
//     and 80 inside its own namespace with no capability left to it. The host
//     side of the same question is not in this sheet at all: it is the declared
//     policy effect of the plan, applied and removed with it;
//   - it names a network, which is the one honest way for a container to reach
//     this machine's own loopback. What it does not name is `host`: the entry
//     never enters the host's network namespace.
//
// Everything else is the same list of controls a service sheet carries, for the
// same reasons: Pull=never, ReadOnly=true, NoNewPrivileges=true and
// DropCapability=ALL. There is no Device, no Environment, no AddCapability, no
// PodmanArgs and no Exec, because nothing may describe one.
func renderEntrypointSheet() []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=%s

[Container]
Image=%s
ContainerName=%s
Network=slirp4netns:allow_host_loopback=true
PublishPort=%d:%d
PublishPort=%d:%d
Volume=%s:%s:ro
Volume=%s:%s:ro
Volume=%s:%s:ro
Pull=never
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
Sysctl=net.ipv4.ip_unprivileged_port_start=0

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
`,
		entrypointPlacement.description,
		entrypointPlacement.image,
		entrypointPlacement.containerName,
		entrypointSecurePort, entrypointSecurePort,
		entrypointClearPort, entrypointClearPort,
		entrypointConfigurationPath, entrypointConfigurationMount,
		entrypointFragmentDirectory, entrypointFragmentDirectory,
		entrypointCertificateDirectory, entrypointCertificateDirectory,
	))
}

// renderEntrypointConfiguration builds the static configuration Traefik reads.
//
// It takes no argument for the same reason the sheet does not, and what it omits
// is as load-bearing as what it declares:
//
//   - there is no provider but the file one. Traefik never sees a container
//     engine socket, so no container running on this machine can publish itself
//     by carrying a label;
//   - there is no `api` block at all. Declaring one with the dashboard disabled
//     would enable the API, which is precisely the opposite of what a reader
//     would take that line to mean; absence is the control here;
//   - there is no certificate resolver and no default certificate store. A name
//     nobody declared has no certificate of this product, and no route: it
//     receives the entry's own generic refusal;
//   - the clear entry point does nothing but redirect, permanently, to the
//     secure one. It is not a second way in;
//   - the two calls Traefik makes home by default are refused by name, because a
//     machine of this product does not talk to the network unbidden;
//   - the dial towards a backend is bounded. A backend reached through a private
//     passage that has fallen answers nothing at all — no refusal, no
//     unreachable, just a route into a hole — and an unbounded dial turns that
//     into a client that waits a minute and a half and is told nothing. The
//     machine proof of `#104` measured exactly that. A bounded dial makes the
//     entry say what it knows, promptly: this name has a backend and the backend
//     is not answering. An entry that hangs states neither a success nor a
//     failure, and a plan of this product may not leave a reader in that place.
func renderEntrypointConfiguration() []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
global:
  checkNewVersion: false
  sendAnonymousUsage: false

entryPoints:
  web:
    address: ":%d"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
  websecure:
    address: ":%d"

providers:
  file:
    directory: %s
    watch: true

serversTransport:
  forwardingTimeouts:
    dialTimeout: %ds
    responseHeaderTimeout: %ds

log:
  level: INFO
`,
		entrypointClearPort,
		entrypointSecurePort,
		entrypointFragmentDirectory,
		entrypointDialTimeoutSeconds,
		entrypointResponseHeaderTimeoutSeconds,
	))
}

// renderHostPortsPolicy builds the one host relaxation this product declares.
//
// The value is `80` rather than `443` because the entry holds both public ports
// and the kernel's setting is a floor, not a list: everything from the floor
// upwards stops requiring a capability to bind. Writing `443` would leave the
// clear port unbindable and the redirection unreachable.
func renderHostPortsPolicy() []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary as a declared effect of one approved
# entrypoint plan. It is removed when that entrypoint is removed, and by
# nothing else. Do not edit: this machine compares this file byte for byte
# against the plan it is given.
net.ipv4.ip_unprivileged_port_start=%d
`, entrypointClearPort))
}

// deployEntrypoint brings this machine to the state an entrypoint plan
// describes, and says whether doing so changed anything.
//
// The decision is taken against what the machine actually holds — the sheet, the
// static configuration, the host policy, the service and the image the running
// container was created from — rather than against a record this Auxiliary
// keeps, exactly as for a managed service. Every one of those five is part of
// the comparison, so an edited configuration or a policy file somebody removed
// is a drift the next approved plan repairs, and not a state that survives
// unseen.
//
// The order below is the whole argument and is written once, here:
//
//  1. the account exists before it is asked to run anything;
//  2. the image is fetched before a sheet describes it;
//  3. the three directories exist before a sheet mounts them, because a mount of
//     a directory that is not there is either a failure or a directory created
//     by the engine under the wrong owner;
//  4. the static configuration is on disk before the entry that reads it starts;
//  5. **the host policy is applied before the service is started**, because a
//     rootless account that cannot bind 443 does not fail slowly — it fails at
//     start, and a machine that started an entry it had not yet allowed to
//     listen would be a machine reporting a state it never reached;
//  6. the sheet is written, systemd reads it again, a drifted service is stopped
//     before the new description is started;
//  7. and only then is the announced state verified locally.
func deployEntrypoint(executor Executor, capabilities Capabilities, subject instance) (*Application, bool, error) {
	where := subject.placement
	path := where.unitPath()
	desiredSheet := renderEntrypointSheet()
	desiredConfiguration := renderEntrypointConfiguration()
	desiredPolicy := renderHostPortsPolicy()

	currentSheet, sheetPresent, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	currentConfiguration, configurationPresent, err := executor.ReadUnitFile(entrypointConfigurationPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the current entrypoint configuration: %w", err)
	}
	currentPolicy, policyPresent, err := executor.HostPortsPolicy()
	if err != nil {
		return nil, false, fmt.Errorf("read the current host ports policy: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}

	if sheetPresent && bytes.Equal(currentSheet, desiredSheet) &&
		configurationPresent && bytes.Equal(currentConfiguration, desiredConfiguration) &&
		policyPresent && bytes.Equal(currentPolicy, desiredPolicy) &&
		active && image == where.image {
		// The approved state already holds, down to the bytes of all three files
		// and the identity of the running image. Nothing is rewritten, nothing is
		// restarted and nothing is verified again: a plan that demands what is
		// already true is not an action.
		return &Application{
			Operation:    subject.operation,
			UnitPath:     path,
			ServiceState: ServiceStateActive,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine, so every failure below it
	// is a controlled failure and not a refusal.
	const touched = true

	if !capabilities.AccountPresent {
		if err := executor.CreateProbeAccount(where.account, where.home, where.comment); err != nil {
			return nil, touched, fmt.Errorf("create the entrypoint account: %w", err)
		}
		if err := executor.EnableLinger(where.account); err != nil {
			return nil, touched, fmt.Errorf("enable lingering for the entrypoint account: %w", err)
		}
		refreshed, err := executor.Capabilities(where.account)
		if err != nil {
			return nil, touched, fmt.Errorf("observe the entrypoint account after creating it: %w", err)
		}
		if !refreshed.RootlessPodman {
			return nil, touched, fmt.Errorf(
				"the account %s was created but cannot run Podman rootless: this machine now holds that account and no unit",
				where.account,
			)
		}
	}

	if err := executor.PullImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("fetch the pinned image: %w", err)
	}
	if err := executor.EnsureEntrypointDirectories(); err != nil {
		return nil, touched, fmt.Errorf("create the entrypoint's root-owned directories: %w", err)
	}
	if err := executor.WriteUnitFile(entrypointConfigurationPath, desiredConfiguration); err != nil {
		return nil, touched, fmt.Errorf("write the entrypoint configuration: %w", err)
	}
	if err := executor.WriteHostPortsPolicy(desiredPolicy); err != nil {
		return nil, touched, fmt.Errorf("apply the host ports policy the entrypoint plan declares: %w", err)
	}
	if err := executor.WriteUnitFile(path, desiredSheet); err != nil {
		return nil, touched, fmt.Errorf("write the Quadlet sheet: %w", err)
	}
	if err := executor.ReloadUserUnits(where.account); err != nil {
		return nil, touched, fmt.Errorf("reload the entrypoint account's units: %w", err)
	}
	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the drifted entrypoint: %w", err)
		}
	}
	if err := executor.StartService(where.account, where.serviceName); err != nil {
		return nil, touched, fmt.Errorf("start the entrypoint: %w", err)
	}
	if err := executor.EntrypointAnswers(); err != nil {
		return nil, touched, fmt.Errorf(
			"the entrypoint was started but did not hold %s:%d and %s:%d as this contract requires: this machine held a started entrypoint whose announced state was unproven: %w",
			loopbackAddress, entrypointSecurePort, loopbackAddress, entrypointClearPort, err,
		)
	}
	return &Application{
		Operation:    subject.operation,
		UnitPath:     path,
		ServiceState: ServiceStateActive,
		Changed:      true,
	}, touched, nil
}

// removeEntrypoint takes the public entrypoint away and leaves nothing of it
// behind, and refuses to do so while this machine still holds a route.
//
// The refusal is the decision this issue owes, and it is taken before any
// effect. Removing the entry takes its mounts away, so every fragment left in
// the directory would stop being served without a single plan saying so — a
// silent route death, which is exactly what this contract's lifecycle wants
// visible. The order of a removal is a sequencing concern of the plans a human
// approves: retire the routes, then remove the entry. So the refusal names the
// fragments that are in the way rather than deciding for the human what happens
// to them.
//
// The order of what follows is the inverse of the deployment's, and the host
// policy is where that matters: the relaxation is taken away **after** the
// service that needed it has stopped, so that nothing is ever running while the
// machine has already forgotten that it was allowed to.
func removeEntrypoint(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	path := where.unitPath()

	fragments, err := executor.ListRouteFragments()
	if err != nil {
		return nil, false, fmt.Errorf("read the routes this machine still publishes: %w", err)
	}
	if len(fragments) != 0 {
		return nil, false, fmt.Errorf(
			"this machine still publishes %d route(s) through the entrypoint (%v): removing the entrypoint would stop serving them without a plan saying so, so it is refused before any effect and the routes are retired by their own approved plans first",
			len(fragments), fragments,
		)
	}

	_, sheetPresent, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	_, configurationPresent, err := executor.ReadUnitFile(entrypointConfigurationPath)
	if err != nil {
		return nil, false, fmt.Errorf("read the current entrypoint configuration: %w", err)
	}
	_, policyPresent, err := executor.HostPortsPolicy()
	if err != nil {
		return nil, false, fmt.Errorf("read the current host ports policy: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}

	if !sheetPresent && !configurationPresent && !policyPresent && !active && image == "" {
		return &Application{
			Operation:    subject.operation,
			UnitPath:     path,
			ServiceState: ServiceStateAbsent,
			Changed:      false,
		}, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the entrypoint: %w", err)
		}
	}
	if policyPresent {
		if err := executor.RemoveHostPortsPolicy(); err != nil {
			return nil, touched, fmt.Errorf("remove the host ports policy the entrypoint plan declared: %w", err)
		}
	}
	if sheetPresent {
		if err := executor.RemoveUnitFile(path); err != nil {
			return nil, touched, fmt.Errorf("remove the Quadlet sheet: %w", err)
		}
		if err := executor.ReloadUserUnits(where.account); err != nil {
			return nil, touched, fmt.Errorf("reload the entrypoint account's units: %w", err)
		}
	}
	if configurationPresent {
		if err := executor.RemoveUnitFile(entrypointConfigurationPath); err != nil {
			return nil, touched, fmt.Errorf("remove the entrypoint configuration: %w", err)
		}
	}
	// The three directories stay. Two of them are now empty and say nothing; the
	// third holds the certificates of declared names, which this Auxiliary never
	// wrote and therefore does not take away. Removing what no plan described is
	// exactly the liberty this product does not allow itself.
	if err := executor.RemoveImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("remove the pinned image: %w", err)
	}
	return &Application{
		Operation:    subject.operation,
		UnitPath:     path,
		ServiceState: ServiceStateAbsent,
		Changed:      true,
	}, touched, nil
}
