package auxiliary

import (
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file holds the three kinds of file a plan turns into on this machine, and
// it holds them under three different rules, because they are three different
// claims.
//
// A stateless service's sheet may carry exactly one approved value — the loopback
// port — so its rule is that nothing else of a plan may reach it, and that the
// fields which would widen a container are absent rather than set to a safe
// value. Volume= is among them and stays among them: no plan of a stateless
// service has a field that could describe one.
//
// The entrypoint's sheet and configuration may carry no approved value at all,
// because an entrypoint plan has none — not a port, not an address, not a
// directory. Their rule is therefore stronger and simpler: they are byte
// constants. That is what the golden checks below assert, and it is also why the
// entrypoint's sheet is allowed the three Volume= lines the stateless service
// sheet forbids: they come from constants of the contract, they are read-only,
// and there is no value a document could put in one.
//
// The private profile's sheet is the third claim and it is its own, exactly as
// the entrypoint's was: it carries the two approved values this product allows a
// file — the port and the origin — and it carries the one Volume= and the four
// Environment= lines of the contract. Its rule is a golden check with those two
// values in it, so a fifth environment line, a second volume or an origin that
// stopped being written under https fails by existing.

// TestTheQuadletSheetDeclaresOnlyTheControlsThisPalierOwes reads the sheet the
// way a report will have to explain it: every line is a control, and the fields
// that would widen the container are absent rather than set to a safe value.
func TestTheQuadletSheetDeclaresOnlyTheControlsThisPalierOwes(t *testing.T) {
	t.Parallel()
	document, err := plan.Decode(frozenPair(t, plan.OperationDeployOCIProbe, fixturePort).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	sheet := string(renderUnit(document))

	for _, line := range []string{
		"Image=" + plan.ProbeImageReference + "@" + plan.ProbeImageDigest,
		"ContainerName=" + containerName,
		"PublishPort=127.0.0.1:8080:80",
		"Pull=never",
		"ReadOnly=true",
		"NoNewPrivileges=true",
		"DropCapability=ALL",
		"Sysctl=net.ipv4.ip_unprivileged_port_start=0",
		"WantedBy=default.target",
	} {
		if !strings.Contains(sheet, line) {
			t.Fatalf("the sheet does not declare %q:\n%s", line, sheet)
		}
	}

	// None of these can come from a plan — the plan has no field for any of them
	// — so none of them may appear in a sheet either.
	for _, forbidden := range []string{
		"Volume=", "Mount=", "Device=", "Environment=", "EnvironmentFile=",
		"AddCapability=", "Privileged=", "User=root", "PodmanArgs=", "Exec=",
		"AutoUpdate=", "0.0.0.0", "::",
	} {
		if strings.Contains(sheet, forbidden) {
			t.Fatalf("the sheet declares %q:\n%s", forbidden, sheet)
		}
	}

	// The published port is bound to the loopback address of the contract, and
	// the tag-free pinned digest is the only identity of the image.
	if strings.Count(sheet, "PublishPort=") != 1 {
		t.Fatalf("the sheet publishes more than one port:\n%s", sheet)
	}
	if strings.Contains(sheet, plan.ProbeImageReference+":") {
		t.Fatalf("the sheet names the image by a tag:\n%s", sheet)
	}
}

// TestTheScratchPathsAreAPropertyOfTheImageAndNeverOfAPlan holds the one line
// a sheet may carry beyond `#14`'s controls: the in-memory scratch an image
// requires before it can serve at all.
//
// The paths come from the placement and from nowhere else — the machine proof
// of `#92` isolated them one control at a time — and a profile whose image
// needs none carries none, because a mount that grants nothing still reads as
// a mount that was needed. The probe is that second profile, and its sheet is
// asserted free of scratch rather than assumed to be.
func TestTheScratchPathsAreAPropertyOfTheImageAndNeverOfAPlan(t *testing.T) {
	t.Parallel()

	service := string(renderSheet(bentoPDFPlacement, fixturePort, ""))
	expected := []string{
		"Tmpfs=/var/cache/nginx:rw,mode=1777",
		"Tmpfs=/etc/nginx/tmp:rw,mode=1777",
	}
	lines := []string{}
	for _, line := range strings.Split(service, "\n") {
		if strings.HasPrefix(line, "Tmpfs=") {
			lines = append(lines, line)
		}
	}
	if strings.Join(lines, ",") != strings.Join(expected, ",") {
		t.Fatalf("the BentoPDF scratch is not exactly the two proven paths: %q", lines)
	}
	if !strings.Contains(service, "ReadOnly=true") {
		t.Fatalf("the scratch replaced the read-only control instead of standing beside it:\n%s", service)
	}

	probe := string(renderSheet(probePlacement, fixturePort, ""))
	if strings.Contains(probe, "Tmpfs=") {
		t.Fatalf("the probe's sheet gained a scratch its image never asked for:\n%s", probe)
	}
	entry := string(renderEntrypointSheet())
	if strings.Contains(entry, "Tmpfs=") {
		t.Fatalf("the entrypoint's sheet gained a scratch its image never asked for:\n%s", entry)
	}
}

// TestTheOnlyPlanValueThatReachesTheSheetIsThePort holds the transport rule at
// its narrowest: two plans that differ only by their port produce two sheets
// that differ only by that one line, so no plan-derived string can ride into the
// file beside the value that is allowed to.
func TestTheOnlyPlanValueThatReachesTheSheetIsThePort(t *testing.T) {
	t.Parallel()
	first, err := plan.Decode(frozenPair(t, plan.OperationDeployOCIProbe, 8080).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	second, err := plan.Decode(frozenPair(t, plan.OperationRemoveOCIProbe, 65535).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}

	if string(renderUnit(first)) != string(renderUnit(first)) {
		t.Fatal("the sheet is not the same bytes twice, so idempotence cannot be read from it")
	}

	left := strings.Split(string(renderUnit(first)), "\n")
	right := strings.Split(string(renderUnit(second)), "\n")
	if len(left) != len(right) {
		t.Fatalf("two plans produced sheets of different shapes:\n%q\n%q", left, right)
	}
	differences := 0
	for index := range left {
		if left[index] != right[index] {
			differences++
			if !strings.HasPrefix(left[index], "PublishPort=") {
				t.Fatalf("a value other than the port reached the sheet: %q", left[index])
			}
		}
	}
	if differences != 1 {
		t.Fatalf("two plans differing by their port produced %d differences", differences)
	}
}

// TestThePrivateSheetIsTheContractDownToItsFourEnvironmentLines is the claim of
// the private profile's own sheet, held whole rather than line by line.
//
// The expected text below is the entire file. A line added to it by a future
// change — a fifth environment line, a second volume, a device, a capability —
// fails this check by existing, which is exactly what a list of forbidden strings
// cannot promise. The two values inside it are the only two a plan is allowed to
// put in a file anywhere in this product: the loopback port, and the origin,
// under the scheme the profile fixes and never one a document chose.
func TestThePrivateSheetIsTheContractDownToItsFourEnvironmentLines(t *testing.T) {
	t.Parallel()
	const expected = `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=Your Cloud managed Vaultwarden private service

[Container]
Image=docker.io/vaultwarden/server@sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8
ContainerName=your-cloud-svc-vaultwarden
PublishPort=127.0.0.1:8080:80
Pull=never
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
Volume=/var/lib/your-cloud-svc-vaultwarden/data:/data:rw
Environment=SIGNUPS_ALLOWED=false
Environment=INVITATIONS_ALLOWED=false
Environment=SHOW_PASSWORD_HINT=false
Environment=DOMAIN=https://vault.lab.your-cloud.test
Sysctl=net.ipv4.ip_unprivileged_port_start=0

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
`
	sheet := string(renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost))
	if sheet != expected {
		t.Fatalf("the private sheet is not the one this contract fixes:\n%s", sheet)
	}
	if sheet != string(renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost)) {
		t.Fatal("the private sheet is not the same bytes twice, so idempotence cannot be read from it")
	}

	// Exactly four environment lines, counted rather than looked for, and exactly
	// one volume beside them: those are the two things this sheet has that no
	// stateless sheet may ever have, so both are counted.
	environment := []string{}
	volumes := []string{}
	for _, line := range strings.Split(sheet, "\n") {
		if strings.HasPrefix(line, "Environment=") {
			environment = append(environment, line)
		}
		if strings.HasPrefix(line, "Volume=") {
			volumes = append(volumes, line)
		}
	}
	expectedEnvironment := []string{
		"Environment=SIGNUPS_ALLOWED=false",
		"Environment=INVITATIONS_ALLOWED=false",
		"Environment=SHOW_PASSWORD_HINT=false",
		"Environment=DOMAIN=https://" + fixtureOriginHost,
	}
	if strings.Join(environment, ",") != strings.Join(expectedEnvironment, ",") {
		t.Fatalf("the private sheet's environment is not the four lines of the contract: %q", environment)
	}
	if strings.Join(volumes, ",") != "Volume="+VaultwardenDataDirectory+":"+VaultwardenContainerDataPath+":rw" {
		t.Fatalf("the private sheet's volume is not the one constant of the profile: %q", volumes)
	}

	// The controls a container of this product never regains, and the mount the
	// data is the single exception to: the read-only filesystem stands beside the
	// volume rather than being replaced by it.
	for _, forbidden := range []string{
		"Device=", "EnvironmentFile=", "AddCapability=", "Privileged=",
		"User=root", "PodmanArgs=", "Exec=", "AutoUpdate=", "Network=host",
		"Volume=/var/run", "docker.sock", "podman.sock", "Tmpfs=",
		"0.0.0.0", "::", "DOMAIN=http://",
	} {
		if strings.Contains(sheet, forbidden) {
			t.Fatalf("the private sheet declares %q:\n%s", forbidden, sheet)
		}
	}
	if strings.Contains(sheet, plan.VaultwardenImageReference+":") {
		t.Fatalf("the private sheet names the image by a tag:\n%s", sheet)
	}
}

// TestNoStatelessSheetGainedAVolumeOrAnEnvironmentLine is the other half of the
// same claim, and the one a widened renderer would break.
//
// The two sheets of the stateless door declare no volume and no environment
// whatever is passed to the renderer, because their placements declare none.
// Passing an origin to them is deliberate here: a renderer that wrote the value
// it was handed rather than the value its placement asked for would be caught by
// this case and by nothing else.
func TestNoStatelessSheetGainedAVolumeOrAnEnvironmentLine(t *testing.T) {
	t.Parallel()
	for name, where := range map[string]placement{
		"the probe":    probePlacement,
		"the bentopdf": bentoPDFPlacement,
	} {
		blank := string(renderSheet(where, fixturePort, ""))
		offered := string(renderSheet(where, fixturePort, fixtureOriginHost))
		if blank != offered {
			t.Fatalf("%s profile's sheet changed because an origin was offered to it:\n%s", name, offered)
		}
		for _, forbidden := range []string{"Volume=", "Environment=", fixtureOriginHost} {
			if strings.Contains(offered, forbidden) {
				t.Fatalf("%s profile's sheet declares %q:\n%s", name, forbidden, offered)
			}
		}
	}
}

// TestTheEntrypointSheetIsAByteConstant is the strongest form the transport rule
// can take: an entrypoint plan has no free value, so the sheet it produces is
// the same bytes on every machine and in every run, and the function that
// renders it takes no argument in which one could arrive.
//
// The expected text below is the whole file rather than a list of lines it must
// contain. A line added to the sheet by a future change — a capability, a device,
// an environment file — fails this check by existing, which is exactly what a
// list of forbidden strings cannot promise.
func TestTheEntrypointSheetIsAByteConstant(t *testing.T) {
	t.Parallel()
	const expected = `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=Your Cloud public HTTPS entrypoint

[Container]
Image=docker.io/library/traefik@sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac
ContainerName=your-cloud-entrypoint
Network=slirp4netns:allow_host_loopback=true
PublishPort=443:443
PublishPort=80:80
Volume=/etc/your-cloud/entrypoint/traefik.yaml:/etc/traefik/traefik.yaml:ro
Volume=/etc/your-cloud/entrypoint/dynamic:/etc/your-cloud/entrypoint/dynamic:ro
Volume=/etc/your-cloud/entrypoint/certificates:/etc/your-cloud/entrypoint/certificates:ro
Pull=never
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
Sysctl=net.ipv4.ip_unprivileged_port_start=0

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
`
	sheet := string(renderEntrypointSheet())
	if sheet != expected {
		t.Fatalf("the entrypoint sheet is not the constant this contract fixes:\n%s", sheet)
	}
	if sheet != string(renderEntrypointSheet()) {
		t.Fatal("the entrypoint sheet is not the same bytes twice, so idempotence cannot be read from it")
	}

	// The three mounts are exactly the three constants of the contract, all
	// read-only, and there is no fourth. A mount is the one thing this sheet has
	// that a service sheet must never have, so it is counted rather than merely
	// looked for.
	mounts := []string{}
	for _, line := range strings.Split(sheet, "\n") {
		if strings.HasPrefix(line, "Volume=") {
			mounts = append(mounts, line)
		}
	}
	expectedMounts := []string{
		"Volume=" + entrypointConfigurationPath + ":" + entrypointConfigurationMount + ":ro",
		"Volume=" + entrypointFragmentDirectory + ":" + entrypointFragmentDirectory + ":ro",
		"Volume=" + entrypointCertificateDirectory + ":" + entrypointCertificateDirectory + ":ro",
	}
	if strings.Join(mounts, ",") != strings.Join(expectedMounts, ",") {
		t.Fatalf("the entrypoint mounts are not the three constants of the contract: %q", mounts)
	}

	// The controls a container of this product never regains, and the network it
	// is never given: `host` would put the entry in this machine's own network
	// namespace, which is what the chosen mechanism exists to avoid.
	for _, forbidden := range []string{
		"Device=", "Environment=", "EnvironmentFile=", "AddCapability=",
		"Privileged=", "User=root", "PodmanArgs=", "Exec=", "AutoUpdate=",
		"Network=host", "Volume=/var/run", "docker.sock", "podman.sock",
	} {
		if strings.Contains(sheet, forbidden) {
			t.Fatalf("the entrypoint sheet declares %q:\n%s", forbidden, sheet)
		}
	}
	if strings.Contains(sheet, plan.EntrypointImageReference+":") {
		t.Fatalf("the entrypoint sheet names the image by a tag:\n%s", sheet)
	}
}

// TestTheEntrypointConfigurationIsAByteConstant holds the static configuration
// to the same rule, and what it is really holding is a list of absences.
//
// There is one provider and it reads files. There is no `api` block at all —
// declaring one with the dashboard disabled would *enable* the API, so absence
// is the control here and a check for a disabled dashboard would be the wrong
// check. There is no certificate resolver and no default certificate, so a name
// nobody declared gets no certificate of this product and no route.
func TestTheEntrypointConfigurationIsAByteConstant(t *testing.T) {
	t.Parallel()
	const expected = `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
global:
  checkNewVersion: false
  sendAnonymousUsage: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
  websecure:
    address: ":443"

providers:
  file:
    directory: /etc/your-cloud/entrypoint/dynamic
    watch: true

log:
  level: INFO
`
	configuration := string(renderEntrypointConfiguration())
	if configuration != expected {
		t.Fatalf("the entrypoint configuration is not the constant this contract fixes:\n%s", configuration)
	}
	if configuration != string(renderEntrypointConfiguration()) {
		t.Fatal("the entrypoint configuration is not the same bytes twice")
	}
	for _, forbidden := range []string{
		"docker", "podman", "swarm", "kubernetes", "consul", "etcd", "redis",
		"api:", "dashboard", "certificatesResolvers", "acme",
		"insecureSkipVerify", "defaultCertificate", "ping:",
	} {
		if strings.Contains(configuration, forbidden) {
			t.Fatalf("the entrypoint configuration declares %q:\n%s", forbidden, configuration)
		}
	}
}

// TestTheHostPortsPolicyIsAByteConstantNamingTheClearPort holds the one host
// relaxation this product declares.
//
// The value is the clear port and not the secure one, because the kernel setting
// is a floor rather than a list: naming 443 would leave 80 unbindable and the
// redirection unreachable, which would be a policy that looks tighter and breaks
// the contract.
func TestTheHostPortsPolicyIsAByteConstantNamingTheClearPort(t *testing.T) {
	t.Parallel()
	policy := string(renderHostPortsPolicy())
	if !strings.HasSuffix(policy, "net.ipv4.ip_unprivileged_port_start=80\n") {
		t.Fatalf("the host policy does not open the machine from the clear port upwards:\n%s", policy)
	}
	if strings.Count(policy, "net.ipv4.ip_unprivileged_port_start") != 1 {
		t.Fatalf("the host policy names more than one setting:\n%s", policy)
	}
	if policy != string(renderHostPortsPolicy()) {
		t.Fatal("the host policy is not the same bytes twice")
	}
	if hostPortsPolicyPath != "/etc/sysctl.d/your-cloud-entrypoint.conf" {
		t.Fatalf("the host policy is not persisted where a reboot reads it: %q", hostPortsPolicyPath)
	}
}
