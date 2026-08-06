package auxiliary

import (
	"path/filepath"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	// BentoPDFAccount is the per-service system account the bentopdf profile
	// runs under, and BentoPDFHome is its own home.
	//
	// It is a second account beside the probe's rather than a shared one: a
	// container escape reaches an account that owns exactly one service, and two
	// managed services never share the storage, the units or the subordinate
	// ranges of a single identity. The name carries the product prefix and the
	// `svc` marker for the same reason the probe's does — Debian already ships
	// generic system groups that a role-shaped name would silently adopt.
	BentoPDFAccount = "your-cloud-svc-bentopdf"
	BentoPDFHome    = "/var/lib/" + BentoPDFAccount

	// BentoPDFContainerPort is the port the pinned BentoPDF image listens on
	// inside its own network namespace. It is a property of the image and never
	// a field of a plan: a plan chooses the loopback port this machine publishes
	// on, and the image decides what is behind it.
	//
	// The value is the one the pinned image itself declares — its config names
	// `8080/tcp` as its single exposed port, and the unprivileged NGINX it is
	// built on listens there as an ordinary user. Being above 1024 it needs no
	// namespace-scoped low-port sysctl at all, which is why the sheet of this
	// profile carries none.
	BentoPDFContainerPort = 8080

	// firstUnprivilegedPort is where the kernel stops requiring a capability to
	// bind. A profile whose container port is below it needs the low-port sysctl
	// in its sheet; a profile above it must not carry the line at all, because a
	// control that grants nothing still reads as a control that was needed.
	firstUnprivilegedPort = 1024

	// contentTypeHTMLDocument is the one invariant the local verification of a
	// static web profile asks of the answer beyond its status. It is deliberately
	// the weakest claim that still distinguishes the approved application from
	// anything else that could be listening: the verification proves that this
	// machine serves a document on this port, and it never asserts the content of
	// that document, which no plan describes and no approval covers.
	contentTypeHTMLDocument = "text/html"
)

// placement is everything a managed service owns on a machine beyond the plan
// that describes it: the account it runs as, the sheet that describes it, the
// container that sheet declares, the image it is pinned to, and the shape of the
// answer that proves it reached the state this machine announces.
//
// It exists so that the machinery `#14` proved for the probe — an account with
// explicitly allocated subordinate ranges, linger, a root-owned sheet under that
// account's own home, reload, start, stop, the bounded local verification and
// the drift computation — is parameterised by a profile rather than written once
// per profile. Nothing in it comes from a plan: a plan chooses a profile and one
// loopback port, and the profile decides everything the plan does not state.
type placement struct {
	// account and home are the identity the service runs as, and the directory
	// a rootless engine is given for its own storage.
	account string
	home    string
	// comment is what the account carries in the machine's own user database, so
	// that an administrator reading it learns which service owns the identity.
	comment string
	// description is the one line the sheet states about itself.
	description string
	// unitFileName, serviceName and containerName are held together here so that
	// no caller can stop one thing and describe another.
	unitFileName  string
	serviceName   string
	containerName string
	// image is the pinned repository and digest joined, so the engine can never
	// resolve a tag and never choose an image. It is what the sheet is written
	// from, and what the running container's own image is compared against.
	image string
	// containerPort is what the image listens on inside its own namespace.
	containerPort int
	// expectedContentType is what the local verification requires of the answer
	// beyond its status, or the empty string where the status is the whole of
	// the proof. The probe answers plain text and proves only that it answers;
	// a static web profile proves that what it answers is a document.
	expectedContentType string
	// writablePaths are the in-memory scratch directories the image requires
	// before it can serve at all, mounted as tmpfs inside the container. They
	// are a property of the image, proven on a machine, never a plan value:
	// the container's own filesystem stays read-only, the scratch lives in
	// memory and nothing reaches the host. An image that needs none names
	// none, because a mount that grants nothing still reads as a mount that
	// was needed.
	writablePaths []string
}

// quadletDirectory is where a rootless Quadlet sheet is read from, relative to
// the home of the account that runs it. The sheet is a user unit rather than a
// system one because every managed service of this product runs rootless: a
// system Quadlet would run it under root's Podman, which is the arrangement
// these paliers exist to avoid.
const quadletDirectory = ".config/containers/systemd"

func (where placement) sheetDirectory() string {
	return filepath.Join(where.home, quadletDirectory)
}

func (where placement) unitPath() string {
	return filepath.Join(where.sheetDirectory(), where.unitFileName)
}

// probePlacement is where the pinned validation probe of `#14` lives, in exactly
// the names that palier proved. Generalising the machinery is not a migration:
// the probe keeps its account, its home, its sheet and its container, and a
// machine that already holds one sees nothing move.
var probePlacement = placement{
	account:       ProbeAccount,
	home:          ProbeHome,
	comment:       "Your Cloud OCI validation probe",
	description:   "Your Cloud disposable OCI validation probe",
	unitFileName:  unitFileName,
	serviceName:   serviceName,
	containerName: containerName,
	image:         plan.ProbeImageReference + "@" + plan.ProbeImageDigest,
	containerPort: containerPort,
	// The probe answers plain text, and what `#14` proves about it is that it
	// answers at all. Requiring a content type here would tighten a verification
	// that palier already fixed, so the field stays empty.
	expectedContentType: "",
}

// bentoPDFPlacement is where the one service profile of this palier lives.
//
// Every value below is the profile's decision and none of them is approvable:
// the plan names the profile and the loopback port, and this is what naming the
// profile means on a machine.
var bentoPDFPlacement = placement{
	account:             BentoPDFAccount,
	home:                BentoPDFHome,
	comment:             "Your Cloud managed BentoPDF web service",
	description:         "Your Cloud managed BentoPDF web service",
	unitFileName:        BentoPDFAccount + ".container",
	serviceName:         BentoPDFAccount + ".service",
	containerName:       BentoPDFAccount,
	image:               plan.BentoPDFImageReference + "@" + plan.BentoPDFImageDigest,
	containerPort:       BentoPDFContainerPort,
	expectedContentType: contentTypeHTMLDocument,
	// The pinned image is an unprivileged nginx, and nginx creates its client
	// scratch and its pid file before it listens. Exactly these two paths, and
	// no third: the machine proof of `#92` isolated them one control at a time
	// (`/tmp` in particular is not among them).
	writablePaths: []string{"/var/cache/nginx", "/etc/nginx/tmp"},
}

// profilePlacements is the closed list of service profiles this Auxiliary
// places, and the one placement each of them means.
//
// It is held here rather than derived from the plan package's own closed list so
// that a profile added to a plan does not silently become a profile this machine
// will deploy: a profile without a placement is refused before any effect,
// because there is nowhere for it to be placed.
var profilePlacements = map[string]placement{
	plan.ServiceProfileBentoPDF: bentoPDFPlacement,
}

// ServiceUnitPath is the one file this package writes for one service profile,
// and reports whether that profile is one this Auxiliary places at all.
func ServiceUnitPath(serviceProfile string) (string, bool) {
	where, known := profilePlacements[serviceProfile]
	if !known {
		return "", false
	}
	return where.unitPath(), true
}
