package auxiliary

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// This file is everything one published route is on a machine: exactly one
// fragment file in the directory the entrypoint's file provider watches, and
// nothing else. Publishing writes that file, retiring removes it, and neither
// touches the entry, the other fragments or the service the route names.
//
// Two values of a plan reach this file, and both are bounded before they arrive:
// the declared host, whose character set is lower-case letters, digits, hyphens
// and dots and which opens and closes on a letter or a digit, and the backend
// port, an integer inside 1024..65535. Everything else — the directories, the
// address the backend is reached at, the entry point the router is attached to
// and the two isolation headers — is a constant of the contract.

const (
	// routeFragmentSuffix is what a fragment file is called beyond the name it
	// serves, and maxFragmentNameBytes is what a single file name may occupy on
	// the filesystems this product runs on.
	//
	// The two exist together because they collide: a host may be 253 bytes and a
	// file name may be 255, so the longest declared names cannot be held as one
	// file here. That is refused by name, before any effect, rather than
	// truncated — two names truncated to the same file would be two routes
	// serving one fragment, which is the one failure a deterministic name exists
	// to make impossible.
	routeFragmentSuffix  = ".yaml"
	maxFragmentNameBytes = 255

	// isolationOpenerPolicy and isolationEmbedderPolicy are the two response
	// headers the profile's middleware adds. They condition SharedArrayBuffer,
	// which the pinned edition exercises, and the palier's proof constats both of
	// them on the HTTPS answer.
	isolationOpenerPolicy   = "same-origin"
	isolationEmbedderPolicy = "require-corp"
)

// routeFragmentPath is the one file a declared name owns, and the second half of
// the answer to "could two routes ever be the same file".
//
// The name is the host verbatim: the plan validation has already bound it to a
// character set that carries no separator, no upper case and no dot pair, so
// two different declared names are two different file names and no folding,
// escaping or hashing is needed to keep them apart. What the host cannot do is
// leave this directory — it contains no slash and cannot be `.` or `..`, both of
// which fail the rule that a host opens and closes on a letter or a digit.
func routeFragmentPath(host string) string {
	return entrypointFragmentDirectory + "/" + host + routeFragmentSuffix
}

// requireHoldableFragmentName refuses a declared name this machine cannot hold
// as a single file, while that machine is still untouched.
func requireHoldableFragmentName(host string) error {
	if len(host)+len(routeFragmentSuffix) > maxFragmentNameBytes {
		return fmt.Errorf(
			"the declared name is %d bytes and its fragment would need %d, which is more than the %d bytes one file name may occupy on this machine: the route is refused before any effect",
			len(host), len(host)+len(routeFragmentSuffix), maxFragmentNameBytes,
		)
	}
	return nil
}

// renderRouteFragment builds the one Traefik fragment a declared name owns.
//
// The router, the service and the middleware all carry the declared name as
// their own, each in its own namespace of the dynamic configuration, so no two
// routes can name the same object and no suffix has to be invented to keep them
// apart. Every place the name appears is a double-quoted YAML scalar, and the
// character set the plan validation bound it to contains neither a quote nor a
// backslash — so the value cannot leave the string it was written into.
//
// What the fragment declares is exactly what the contract asks for and nothing
// beside it:
//
//   - a router on the exact declared Host(), attached to the secure entry point
//     alone. There is no clear-port router: `80` only redirects, and it does so
//     at the entry point rather than per route;
//   - TLS, resolved from the certificate and the key of that name under the
//     entry's certificate directory. The paths are built from a constant and the
//     host, and no plan names a certificate;
//   - one backend, the host loopback port a human approved, reached through the
//     fixed address the entry's network gives this machine's own loopback;
//   - the profile's isolation headers, as a named middleware of this fragment.
func renderRouteFragment(host string, backendPort int) []byte {
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
      middlewares:
        - %s
      tls: {}
  services:
    %s:
      loadBalancer:
        servers:
          - url: "http://%s:%d"
  middlewares:
    %s:
      headers:
        customResponseHeaders:
          Cross-Origin-Opener-Policy: "%s"
          Cross-Origin-Embedder-Policy: "%s"
tls:
  certificates:
    - certFile: "%s/%s.crt"
      keyFile: "%s/%s.key"
`,
		quoted,
		host,
		quoted,
		quoted,
		quoted,
		entrypointHostLoopbackAddress, backendPort,
		quoted,
		isolationOpenerPolicy,
		isolationEmbedderPolicy,
		entrypointCertificateDirectory, host,
		entrypointCertificateDirectory, host,
	))
}

// managedProfiles is the closed list of service profiles this Auxiliary places,
// both doors together, in one fixed order, so that a check walking them reads the
// same sheets in the same sequence on every run.
//
// It walks the private door as well as the stateless one because the sentence its
// one caller implements is "a managed service of this machine is present", and a
// data-bearing service is a managed service: the passage of `#97` is bounded to a
// private service in the reference scenario, and a reading that only knew the
// stateless door would refuse every correct junction of it. Which door approved a
// profile is decided where a document is turned into an instance, and never here.
func managedProfiles() []string {
	profiles := make([]string, 0, len(profilePlacements)+len(privateProfilePlacements))
	for profile := range profilePlacements {
		profiles = append(profiles, profile)
	}
	for profile := range privateProfilePlacements {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	return profiles
}

// publishesLoopbackPort answers whether a managed service of this machine
// publishes one loopback port, reading only.
//
// The question is answered from the sheets this Auxiliary itself wrote and not
// from a socket that happens to be listening: what may be named is a managed
// service of this machine, described by a plan a human approved, and not
// whatever process got to the port first.
//
// It is the presence rule of the palier `#15` as a fact rather than as a
// refusal, because two contracts now hold that same sentence against a machine
// — the route the entry publishes and the passage's bounded service — and each
// of them refuses in its own words. The reading is here, once; the sentence a
// human is given belongs to the caller.
func publishesLoopbackPort(executor Executor, port int) (bool, error) {
	published := "PublishPort=" + loopbackAddress + ":" + strconv.Itoa(port) + ":"
	for _, profile := range managedProfiles() {
		where, _ := placementOf(profile)
		sheet, present, err := executor.ReadUnitFile(where.unitPath())
		if err != nil {
			return false, fmt.Errorf("read the sheet of the %s profile: %w", profile, err)
		}
		if !present {
			continue
		}
		for _, line := range strings.Split(string(sheet), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), published) {
				return true, nil
			}
		}
	}
	return false, nil
}

// requireManagedBackend holds the contract's own sentence — a backend port
// "doit nommer le port loopback d'un service géré présent" — against this
// machine, before anything is written.
//
// A port nothing manages is refused here, with nothing touched.
func requireManagedBackend(executor Executor, backendPort int) error {
	published, err := publishesLoopbackPort(executor, backendPort)
	if err != nil {
		return err
	}
	if published {
		return nil
	}
	return fmt.Errorf(
		"no managed service of this machine publishes %s:%d: a route towards a port nothing manages is refused before any effect",
		loopbackAddress, backendPort,
	)
}

// requireEntrypointPresent refuses a route on a machine that holds no entry.
//
// It is the mirror of the refusal removeEntrypoint takes, and it is one decision
// read twice: the entry and the routes it serves have one order, and both ends
// of it are visible. A fragment written where no entry exists would be a route
// nothing serves, sitting in a directory nothing watches, and the machine would
// have announced a published name it does not publish.
func requireEntrypointPresent(executor Executor) error {
	_, present, err := executor.ReadUnitFile(entrypointPlacement.unitPath())
	if err != nil {
		return fmt.Errorf("read the entrypoint's Quadlet sheet: %w", err)
	}
	if !present {
		return fmt.Errorf(
			"this machine holds no entrypoint: a route is served by the entry and cannot be published before it, so the route is refused before any effect",
		)
	}
	return nil
}

// publishRoute writes the one fragment a declared name owns, and says whether
// doing so changed anything.
//
// Everything that could refuse happens first and reads only: the entry has to be
// there, the backend port has to be one a managed service of this machine
// publishes, and the name has to be one this machine can hold as a file. Only
// then is the fragment compared, byte for byte, against the one the plan
// describes — so republishing an identical route is not an action, and a
// fragment somebody edited is a drift the plan repairs rather than an error.
func publishRoute(executor Executor, subject instance) (*Application, bool, error) {
	path := routeFragmentPath(subject.routeHost)
	desired := renderRouteFragment(subject.routeHost, subject.backendPort)

	if err := requireEntrypointPresent(executor); err != nil {
		return nil, false, err
	}
	if err := requireManagedBackend(executor, subject.backendPort); err != nil {
		return nil, false, err
	}
	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current route fragment: %w", err)
	}
	if present && bytes.Equal(current, desired) {
		return &Application{
			Operation:    subject.operation,
			RouteHost:    subject.routeHost,
			FragmentPath: path,
			ServiceState: ServiceStateActive,
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
	// that the entry actually took it — from this machine, with the declared name
	// in both the SNI and the Host header, and with certificate verification
	// deliberately skipped, because the certificate of the declared name is the
	// proof's business and not this Auxiliary's.
	if err := executor.RouteAnswers(subject.routeHost); err != nil {
		return nil, touched, fmt.Errorf(
			"the route fragment was written but %s was not served with its isolation headers from %s:%d: this machine held a published route whose announced state was unproven: %w",
			subject.routeHost, loopbackAddress, entrypointSecurePort, err,
		)
	}
	return &Application{
		Operation:    subject.operation,
		RouteHost:    subject.routeHost,
		FragmentPath: path,
		ServiceState: ServiceStateActive,
		Changed:      true,
	}, touched, nil
}

// retireRoute removes exactly the fragment of one declared name.
//
// It removes the fragment and nothing else: the entry keeps running, every other
// fragment keeps being served, and the service this route named keeps answering
// on its loopback port. An absent fragment is not a failure and not a repair —
// it is the approved state, already held.
func retireRoute(executor Executor, subject instance) (*Application, bool, error) {
	path := routeFragmentPath(subject.routeHost)
	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current route fragment: %w", err)
	}
	if !present {
		return &Application{
			Operation:    subject.operation,
			RouteHost:    subject.routeHost,
			FragmentPath: path,
			ServiceState: ServiceStateAbsent,
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
		Changed:      true,
	}, touched, nil
}
