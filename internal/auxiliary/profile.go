package auxiliary

import (
	"path/filepath"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
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

	// VaultwardenAccount is the per-service system account the vaultwarden
	// profile runs under, and VaultwardenHome is its own home.
	//
	// It is a third account beside the probe's and BentoPDF's, under the rule
	// those two already state: two managed services never share the storage, the
	// units or the subordinate ranges of a single identity. Here the rule earns
	// something the stateless profiles never needed it for — this home holds the
	// first data of the product that outlives a container, so the identity that
	// owns that data owns exactly one service and nothing else.
	VaultwardenAccount = "your-cloud-svc-vaultwarden"
	VaultwardenHome    = "/var/lib/" + VaultwardenAccount

	// VaultwardenDataDirectory is the one durable write path of this product, and
	// VaultwardenContainerDataPath is where the pinned image declares it.
	//
	// It is a constant of the placement and never a field of a plan: the rule of
	// the stateless sheets — no plan of this product describes a path a machine
	// will write to — is unchanged, and what changes is that one profile now has
	// such a path at all. It lives under the dedicated account's own home, so the
	// data of a service and the identity that may read it are one fact.
	VaultwardenDataDirectory     = VaultwardenHome + "/data"
	VaultwardenContainerDataPath = "/data"

	// VaultwardenSnapshotDirectory is where the named archives of that data live.
	// It is a sibling of the data rather than a directory inside it, so that no
	// archive is ever part of the tree the next archive walks.
	VaultwardenSnapshotDirectory = VaultwardenHome + "/snapshots"

	// VaultwardenContainerPort is the port the pinned Vaultwarden image listens
	// on inside its own network namespace. It is a property of the image and
	// never a field of a plan, read off the registry rather than believed: the
	// manifest list of the contract declares `80/tcp` as its single exposed port.
	//
	// Being below 1024 it needs the namespace-scoped low-port sysctl, exactly as
	// the probe does and exactly for the same reason — the setting is scoped to
	// the container's own network namespace and grants nothing on the host.
	VaultwardenContainerPort = 80

	// The three hardening constants of the private profile and the prefix of its
	// one approved value.
	//
	// They are the whole of the environment this profile's sheet may carry, and
	// they are constants because none of them is a choice a human makes about an
	// instance: an instance of this product never opens its own registrations,
	// never invites and never hands back a password hint. The fourth line is the
	// origin, and it is the single approved value that reaches a sheet beyond a
	// port — the scheme is fixed here, so no plan can ask this service to
	// announce itself over a clear origin.
	vaultwardenSignupsAllowed     = "SIGNUPS_ALLOWED=false"
	vaultwardenInvitationsAllowed = "INVITATIONS_ALLOWED=false"
	vaultwardenShowPasswordHint   = "SHOW_PASSWORD_HINT=false"
	vaultwardenDomainPrefix       = "DOMAIN=https://"

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

// volumeMount is one durable write path of a managed service: where it lives on
// this host, and the path the image declares inside its own filesystem.
//
// The two are held together rather than as two lists, because a mount is one
// fact: a host path without the container path it answers is a directory nothing
// reads, and the reverse is a mount nothing backs. Both sides are decided by the
// placement — a constant of the product for the delivered profiles, a derivation
// from the definition's own slug for a user service — so no plan of any door can
// move a write path or add a second one.
type volumeMount struct {
	host      string
	container string
}

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
//
// The third door fills the very same structure from a definition instead of
// enumerating it per profile, which is why the fields below say "the placement
// decides" and never "the profile decides": a user service's account, home,
// volumes, environment and secrets are derived from the one slug its definition
// declares, and the derivation is as much a constant of this package as the
// delivered profiles' own values are.
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
	// dataDirectory, volumes and snapshotDirectory are what a profile whose data
	// outlives its container has, and what every profile before it has none of.
	//
	// They are constants of the placement and not fields of a plan: the rule of
	// the stateless sheets is unchanged — no document of this product describes a
	// path a machine writes to — and what a data-bearing placement adds is such
	// paths decided here, mounted read-write on the paths the image declares, with
	// the archives beside them. A profile that keeps no data names none of the
	// three, and everything below reads that absence as the whole statement: there
	// is nothing to mount, nothing to create and nothing to archive.
	//
	// dataDirectory is the *root* of what this service durably holds, and it is
	// the one directory that is created, archived and reported. The delivered
	// private profile has one volume and that root is it; a user service has zero
	// to eight, and the root is the one directory they all live under — so an
	// archive stays what the contract says it is, a single coherent snapshot of
	// everything at once, rather than one file per mount whose order would lie.
	dataDirectory     string
	volumes           []volumeMount
	snapshotDirectory string
	// secretKeys are the names of the values this machine generates for the
	// service, and never a value: no field of this package, of a document or of a
	// report can hold one. A placement that declares none carries no secrets
	// directory, no environment file and no EnvironmentFile= line in its sheet,
	// because a line that reads nothing still reads as a line that was needed.
	secretKeys []string
	// environment is the closed list of hardening lines the sheet carries, and
	// originEnvironmentPrefix is the beginning of the one line that carries an
	// approved value — the origin the instance answers under, appended verbatim.
	//
	// They are held apart because they are two different claims. The first is a
	// constant nobody approves; the second is the second and last plan value this
	// package ever writes into a file, and holding its scheme here is what keeps
	// a plan from choosing one. A profile that declares neither carries no
	// environment line at all, which is the rule the stateless sheets keep.
	environment             []string
	originEnvironmentPrefix string
	// confined says whether deploying this profile also poses the egress table
	// that refuses everything its account emits.
	//
	// It is a flag rather than an inference from dataDirectory because the two
	// are separate decisions: a profile could hold data and legitimately need to
	// reach a registry or a mail relay, and one that does would be deployed with
	// the table absent by naming it here — never by an exception written into the
	// table itself.
	confined bool
}

// bearsData reports whether this profile has a durable write path at all, and it
// is the one question that decides whether a volume, a data directory and an
// archive exist for it.
func (where placement) bearsData() bool { return where.dataDirectory != "" }

// bearsSecrets reports whether this placement declares any generated value at
// all, and it is the one question that decides whether a secrets directory, an
// environment file and an EnvironmentFile= line exist for it.
func (where placement) bearsSecrets() bool { return len(where.secretKeys) != 0 }

// secretsDirectory is where the one value of each declared key lives, and
// environmentFilePath is the file the sheet reads them back from.
//
// They are derived from the home rather than held as two more fields, because
// they are not a choice: a placement that declares keys owns exactly these two
// paths under its own home, and every caller of them is guarded by bearsSecrets
// above. Nothing outside this package can name either of them.
func (where placement) secretsDirectory() string { return where.home + "/secrets" }

func (where placement) environmentFilePath() string { return where.home + "/secrets.env" }

// durableDirectories are every directory the data of this placement needs before
// the container starts, parents first and each one named.
//
// It is the root, then **every** directory on the way down to each volume's own
// host path, and then that path. Naming the intermediates is not tidiness: a
// container path of two segments or more — `/srv/state` is the smallest real one
// — has a parent that exists only because it was created on the way, and a
// directory created on the way is a directory whose owner and mode nobody stated.
// The machine proof of `#121` met exactly that: `volumes/srv` stayed root-owned in
// 0700 while `volumes/srv/state` belonged to the service, and the rootless engine
// could not traverse into its own mount — `statfs …: permission denied`, on every
// deployment of every definition whose volumes are not single-segment paths.
//
// The list is deduplicated and ordered parents first, because the seam that
// consumes it creates, chmods and chowns each entry in turn: two volumes under one
// parent name that parent once, and no entry is ever created before the one above
// it. The delivered private profile, whose single volume *is* the root, still names
// exactly one directory and reaches exactly the effect `#102` proved.
func (where placement) durableDirectories() []string {
	if !where.bearsData() {
		return nil
	}
	directories := []string{where.dataDirectory}
	named := map[string]struct{}{where.dataDirectory: {}}
	for _, mount := range where.volumes {
		for _, directory := range descendTo(where.dataDirectory, mount.host) {
			if _, held := named[directory]; held {
				continue
			}
			named[directory] = struct{}{}
			directories = append(directories, directory)
		}
	}
	return directories
}

// descendTo names every directory strictly under a root and down to one path,
// including that path, parents first.
//
// A path that is the root itself names nothing, which is the delivered private
// profile's case. A path that is not under the root at all names itself alone:
// this package derives every host path from the root and none can be outside it,
// and answering with the path rather than with a walk keeps a caller that somehow
// held one from silently creating directories nobody asked for.
func descendTo(root, path string) []string {
	if path == root {
		return nil
	}
	if !strings.HasPrefix(path, root+"/") {
		return []string{path}
	}
	descent := []string{}
	current := root
	for _, segment := range strings.Split(strings.TrimPrefix(path, root+"/"), "/") {
		if segment == "" {
			continue
		}
		current += "/" + segment
		descent = append(descent, current)
	}
	return descent
}

// archivePath is the one file a named slot owns for this profile.
//
// The slot is verbatim: the plan validation has already bound it to lower-case
// letters, digits and hyphens opening on a letter or a digit, so it carries no
// separator, cannot be `.` or `..` and cannot leave the directory the profile
// owns. That is the same argument a route fragment's name rests on, over a
// narrower character set.
func (where placement) archivePath(slot string) string {
	return where.snapshotDirectory + "/" + slot + archiveSuffix
}

// archiveSuffix is what an archive file is called beyond the slot that names it.
// It is the format the contract fixes, and it is here rather than in the seam so
// that nothing below can write an archive under another name.
const archiveSuffix = ".tar.gz"

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

// bentoPDFPlacement is where the one service profile of the stateless door lives.
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

// vaultwardenPlacement is where the one profile of the private door lives.
//
// Every value below is the profile's decision and none of them is approvable:
// the plan names the profile, the loopback port and the origin, and this is what
// naming the profile means on a machine. What it adds to a stateless placement is
// exactly three things — a durable write path, a closed environment and the
// egress table — and each of them is a field above rather than a branch below.
var vaultwardenPlacement = placement{
	account:       VaultwardenAccount,
	home:          VaultwardenHome,
	comment:       "Your Cloud managed Vaultwarden private service",
	description:   "Your Cloud managed Vaultwarden private service",
	unitFileName:  VaultwardenAccount + ".container",
	serviceName:   VaultwardenAccount + ".service",
	containerName: VaultwardenAccount,
	image:         plan.VaultwardenImageReference + "@" + plan.VaultwardenImageDigest,
	containerPort: VaultwardenContainerPort,
	// The verification of this profile is the status alone, and that is the
	// weakest claim rather than an oversight. What the loopback request proves is
	// that this machine serves the approved application on this port; the media
	// type of what a vault answers a plain request with is not something any plan
	// of this palier describes, and the machine proof `#104` is where the answer
	// of a real instance is constated.
	expectedContentType: "",
	// The image writes its own data and nothing else: there is no in-memory
	// scratch to give it, and a mount that grants nothing still reads as a mount
	// that was needed.
	writablePaths: nil,
	dataDirectory: VaultwardenDataDirectory,
	volumes: []volumeMount{
		{host: VaultwardenDataDirectory, container: VaultwardenContainerDataPath},
	},
	snapshotDirectory: VaultwardenSnapshotDirectory,
	environment: []string{
		vaultwardenSignupsAllowed,
		vaultwardenInvitationsAllowed,
		vaultwardenShowPasswordHint,
	},
	originEnvironmentPrefix: vaultwardenDomainPrefix,
	confined:                true,
}

// profilePlacements is the closed list of service profiles this Auxiliary
// places behind the stateless door, and the one placement each of them means.
//
// It is held here rather than derived from the plan package's own closed list so
// that a profile added to a plan does not silently become a profile this machine
// will deploy: a profile without a placement is refused before any effect,
// because there is nowhere for it to be placed.
var profilePlacements = map[string]placement{
	plan.ServiceProfileBentoPDF: bentoPDFPlacement,
}

// privateProfilePlacements is the same closed list behind the private door, and
// it is a second map for the reason the plan package keeps two: the refusal has
// to run in both directions. A stateless profile named at a private operation
// and a data-bearing profile named at a stateless one are both a lookup that
// fails, rather than a comparison somebody has to remember to write.
var privateProfilePlacements = map[string]placement{
	plan.ServiceProfileVaultwarden: vaultwardenPlacement,
}

// ServiceUnitPath is the one file this package writes for one service profile,
// and reports whether that profile is one this Auxiliary places at all.
//
// It answers for the three doors, because the question is where a managed
// service's sheet lives and not which door approved it. What stays closed against
// itself is the lookup below it: a caller that has a private document looks up the
// private list, a caller that has a stateless one looks up the stateless list, a
// caller that has a definition derives from its slug, and none of them can reach
// another's placement.
func ServiceUnitPath(serviceProfile string) (string, bool) {
	where, known := placementOf(serviceProfile)
	if !known {
		return "", false
	}
	return where.unitPath(), true
}

// placementOf finds one managed service of this machine by the name a document
// calls it: a profile in either door's closed list, or the slug of a user
// service definition.
//
// It is the one place the three doors are read together, and it exists for the
// two questions that are genuinely about "a managed service of this machine"
// rather than about a door: where a service's sheet is, and whether some service
// of this machine publishes a given loopback port. Every other caller of a
// placement comes from a document and looks up the list of that document's own
// door, which is what keeps the refusal running in every direction.
//
// The third door has no closed list to look up, and it needs none: the four
// reserved slugs make a well-formed slug a name no delivered profile can answer
// to, and everything the questions above ask of a user service — its account, its
// home and its sheet — derives from that slug alone. What such a placement
// deliberately does not carry is the definition's own decisions: no image, no
// volumes, no environment and no secrets, because those live in a revision this
// lookup was not handed.
func placementOf(serviceProfile string) (placement, bool) {
	if where, known := profilePlacements[serviceProfile]; known {
		return where, true
	}
	if where, known := privateProfilePlacements[serviceProfile]; known {
		return where, true
	}
	if servicedefinition.ValidateSlug(serviceProfile) != nil {
		return placement{}, false
	}
	return userServicePlacementOfSlug(serviceProfile), true
}
