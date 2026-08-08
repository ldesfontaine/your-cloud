package auxiliary

import (
	"fmt"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	// ProbeAccount is the dedicated unprivileged local account the probe runs
	// as. It is neither the technical account the forced SSH command uses, nor
	// the Daemon's, nor the Relay's: a container escape reaches this account and
	// this account owns nothing but the probe.
	//
	// The name carries the product prefix on purpose. Debian already ships
	// generic system groups — `operator` among them — and an account named after
	// its role rather than after its owner would either collide with one of them
	// or silently adopt it.
	ProbeAccount = "your-cloud-probe"

	// ProbeHome is that account's home. Podman rootless needs a writable place
	// for its own storage, and putting it under /var/lib rather than /home keeps
	// it out of the directories a human account manager treats as people.
	ProbeHome = "/var/lib/your-cloud-probe"

	// unitFileName is the probe's sheet, and serviceName is the service Quadlet
	// generates from it. The two names are held together in the probe's own
	// placement so that no caller can stop one thing and describe another.
	unitFileName = "your-cloud-probe.container"
	serviceName  = "your-cloud-probe.service"

	// containerName is the container the probe's sheet declares, and the one
	// whose running image is read back to decide whether the announced state
	// holds.
	containerName = "your-cloud-probe"

	// loopbackAddress is a constant of the contract and never a field of a plan.
	// No approvable value can expose a managed service beyond its own machine.
	loopbackAddress = "127.0.0.1"

	// containerPort is the port the pinned probe listens on inside its own
	// namespace. It is a property of the image, not a choice of the plan.
	containerPort = 80
)

// UnitPath is the file this package writes for the probe.
func UnitPath() string { return probePlacement.unitPath() }

// PinnedImage is the exact reference the probe is deployed from: the pinned
// repository and the pinned digest, joined so the engine can never resolve a tag
// and never choose an image.
func PinnedImage() string { return probePlacement.image }

// renderUnit builds the Quadlet sheet for one validated schema 1 plan.
//
// It is the probe's own spelling of renderSheet below, kept so that the one
// value a probe plan may put in a file goes on travelling exactly as `#14`
// proved it: the port, an integer the plan validation already bound.
func renderUnit(document *plan.Document) []byte {
	return renderSheet(probePlacement, document.LocalPort, "")
}

// environmentLine renders one inert configuration line into the sheet, in the one
// spelling the generator that reads this file understands.
//
// It is the single place where a value a human approved crosses into another
// parser's syntax, and that is why it is a function with a contract rather than a
// concatenation. A definition admits any printable ASCII in a value — a title with
// spaces above all — while the reader of this file is systemd's own unit syntax as
// Quadlet implements it, where an unquoted value ends at the first whitespace and
// a `%` opens a specifier. Written naively, `Environment=TITLE=Your Cloud notes`
// reaches the container as `TITLE=Your`: the value a human approved, silently
// truncated, with nothing said anywhere. The machine proof of `#121` observed
// exactly that before this function existed, and the reason it is a defect rather
// than a limitation is that no error is raised at any point — a plan is applied,
// the report says the state holds, and the container runs on a value nobody wrote.
//
// Two rules, and there is no third:
//
//   - `%` is always doubled, because specifiers are expanded whether the value is
//     quoted or not;
//   - a line carrying whitespace, a quote or a backslash is wrapped in double
//     quotes with its backslashes and its double quotes escaped, which is exactly
//     the unquoting systemd performs. A line carrying none of them is written
//     verbatim, so the sheets of the delivered profiles do not move by one byte —
//     which is a closure criterion of this palier and not an optimisation.
//
// Nothing here is an escape *the contract* offers a user: a definition still has
// one interpolation and no escaping at all. This is the transport of an already
// approved value into a file, and the property it must have is that what the
// container receives is what the human read.
func environmentLine(line string) string {
	escaped := strings.ReplaceAll(line, "%", "%%")
	if !strings.ContainsAny(escaped, " \t\"'\\") {
		return escaped
	}
	escaped = strings.ReplaceAll(escaped, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// renderSheet builds the Quadlet sheet of one managed service.
//
// Two approved values may reach this file and no third: the loopback port, an
// integer the plan validation already bound to 1024..65535, and — for a profile
// that declares an origin line — the origin host, a name that validation has
// already bound to lower-case letters, digits, hyphens and dots. Everything else
// comes from the placement: the image and its digest above all, written from the
// profile's pinned constants rather than from the document, even though the
// validation has just proven the two equal. A value that cannot travel cannot be
// smuggled.
//
// The origin is written only where the placement declares a prefix for it. A
// profile that declares none carries no environment line whatever a caller
// passes here, which is how the stateless sheets keep their rule — no
// Environment at all — while one sheet of the product carries exactly four.
//
// Every field below is a control this product owes an explanation for, and the
// list is the same for every profile:
//
//   - the sheet is a rootless user unit, so no container runs under root;
//   - PublishPort binds the loopback address only, so nothing is exposed;
//   - DropCapability=ALL and NoNewPrivileges leave the process with neither the
//     capabilities of its user namespace nor a way to regain any;
//   - Sysctl opens the low ports inside the container's own network namespace,
//     and appears only where the image actually listens below 1024 — whoami does
//     and BentoPDF does not. The sysctl is scoped to that namespace and grants
//     nothing on the host; it was proven blocking in the LAB for the probe before
//     it was added, and a profile that does not need it must not carry it,
//     because a control that grants nothing still reads as a control that was
//     needed;
//   - ReadOnly makes the container's own filesystem unwritable. A stateless
//     profile can afford it outright because it keeps nothing; a data-bearing one
//     can afford it because the single place it writes is the volume below, which
//     is named rather than implied — the filesystem stays unwritable everywhere
//     else;
//   - Tmpfs gives the image the in-memory scratch it requires before it can
//     serve at all — a property of the image named by its placement, proven
//     blocking on a machine before it was added. The scratch is memory inside
//     the container, gone with it; the mode is the one /tmp carries, because
//     the image's own account must be able to write there and the profile does
//     not assume that account's identifier. A profile that needs none carries
//     none;
//   - Pull=never keeps starting the service off the network: the one fetch this
//     operation performs is explicit, and happens before the sheet is written;
//   - Volume mounts the placement's durable write paths, read-write, on the
//     paths the image declares as its volumes. Both sides of every mount are
//     decided by the placement — a constant for a delivered profile, a derivation
//     from the definition's own slug for a user service — so no plan can move a
//     write path and no plan can add one; ReadOnly still holds for everything
//     else, so the container's own filesystem stays unwritable and the data is
//     the single exception, named. A placement that keeps nothing carries none;
//   - Environment carries the placement's own lines and, last, the one approved
//     value a profile declaring a prefix appends: the origin this instance
//     answers under, under the scheme that profile fixes. The third door appends
//     no such line, because its origin is interpolated into the very lines its
//     definition declares rather than added beside them. A placement that
//     declares no environment carries none, because a line that decides nothing
//     still reads as a line that was needed;
//   - EnvironmentFile names the one file this machine generated for a placement
//     that declares secret keys, and it appears only where such keys exist. It is
//     a path derived from the placement's own home and never a value: no plan and
//     no definition of this product carries a secret, and this line is how a
//     value the machine generated reaches a container without being written into
//     anything a human reads;
//   - no Device and no extra Network exist here, and no Volume beyond the
//     placement's own, because no plan has a field that could describe one.
func renderSheet(where placement, localPort int, originHost string) []byte {
	data := ""
	for _, mount := range where.volumes {
		data += "Volume=" + mount.host + ":" + mount.container + ":rw\n"
	}
	environment := ""
	for _, line := range where.environment {
		environment += "Environment=" + environmentLine(line) + "\n"
	}
	if where.originEnvironmentPrefix != "" {
		environment += "Environment=" +
			environmentLine(where.originEnvironmentPrefix+originHost) + "\n"
	}
	if where.bearsSecrets() {
		environment += "EnvironmentFile=" + where.environmentFilePath() + "\n"
	}
	scratch := ""
	for _, path := range where.writablePaths {
		scratch += "Tmpfs=" + path + ":rw,mode=1777\n"
	}
	lowPorts := ""
	if where.containerPort < firstUnprivilegedPort {
		lowPorts = "Sysctl=net.ipv4.ip_unprivileged_port_start=0\n"
	}
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=%s

[Container]
Image=%s
ContainerName=%s
PublishPort=%s:%d:%d
Pull=never
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
%s%s%s%s
[Service]
Restart=on-failure

[Install]
WantedBy=default.target
`,
		where.description,
		where.image,
		where.containerName,
		loopbackAddress,
		localPort,
		where.containerPort,
		data,
		environment,
		scratch,
		lowPorts,
	))
}
