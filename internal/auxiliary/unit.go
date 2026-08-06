package auxiliary

import (
	"fmt"
	"path/filepath"

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

	// unitDirectory is where a rootless Quadlet sheet is read from for that
	// account. The sheet is a user unit rather than a system one because the
	// probe runs rootless: a system Quadlet would run it under root's Podman,
	// which is the arrangement this palier exists to avoid.
	unitDirectory = ProbeHome + "/.config/containers/systemd"

	// unitFileName is the sheet, and serviceName is the service Quadlet
	// generates from it. The two names are held together here so that no caller
	// can stop one thing and describe another.
	unitFileName = "your-cloud-probe.container"
	serviceName  = "your-cloud-probe.service"

	// containerName is the container the sheet declares, and the one whose
	// running image is read back to decide whether the announced state holds.
	containerName = "your-cloud-probe"

	// loopbackAddress is a constant of the contract and never a field of a plan.
	// No approvable value can expose the probe beyond its own machine.
	loopbackAddress = "127.0.0.1"

	// containerPort is the port the pinned probe listens on inside its own
	// namespace. It is a property of the image, not a choice of the plan.
	containerPort = 80
)

// UnitPath is the one file this package writes.
func UnitPath() string { return filepath.Join(unitDirectory, unitFileName) }

// PinnedImage is the exact reference the probe is deployed from: the pinned
// repository and the pinned digest, joined so the engine can never resolve a tag
// and never choose an image.
func PinnedImage() string {
	return plan.ProbeImageReference + "@" + plan.ProbeImageDigest
}

// renderUnit builds the Quadlet sheet for one validated plan.
//
// Only one value of the plan reaches this file: the local port, an integer the
// plan validation already bound to 1024..65535. The image and its digest are
// written from the pinned constants rather than from the document, even though
// the validation has just proven the two equal — a value that cannot travel
// cannot be smuggled, and this palier accepts exactly one probe.
//
// Every field below is a control this product owes an explanation for:
//
//   - the sheet is a rootless user unit, so no container runs under root;
//   - PublishPort binds the loopback address only, so nothing is exposed;
//   - DropCapability=ALL and NoNewPrivileges leave the process with neither the
//     capabilities of its user namespace nor a way to regain any;
//   - ReadOnly makes the container's own filesystem unwritable, which the probe
//     can afford because it keeps no data at all;
//   - Pull=never keeps starting the service off the network: the one fetch this
//     operation performs is explicit, and happens before the sheet is written;
//   - no Volume, no Device, no Environment and no extra Network exist here,
//     because the plan has no field that could describe one.
func renderUnit(document *plan.Document) []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=Your Cloud disposable OCI validation probe

[Container]
Image=%s
ContainerName=%s
PublishPort=%s:%d:%d
Pull=never
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
`,
		PinnedImage(),
		containerName,
		loopbackAddress,
		document.LocalPort,
		containerPort,
	))
}
