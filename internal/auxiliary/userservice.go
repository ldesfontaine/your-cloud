package auxiliary

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

// This file is the third door of the product on a machine: a service the product
// does not know, described by a document its own user wrote, placed by the very
// engine the two delivered profiles are placed by.
//
// What is new here is not an effect. Every effect below already existed — the
// account, the root-owned sheet, the durable directories, the archives beside
// them, the confinement table, the bounded local verification — and what this
// file adds is where their values come from: a definition, rehashed and revalidated
// on this machine before anything is read, instead of a constant enumerated per
// profile.
//
// One rule runs through the whole derivation and is stated once, here: **nothing
// a user wrote ever becomes a host path or an account name.** The slug is the one
// value of a definition this file reads into a name, and it has been through the
// definition's own grammar twice by then — once wherever the document was frozen,
// once here — so it is lower-case letters, digits and hyphens, at most sixteen of
// them, and none of the four names another door answers to. Every host path is
// that slug's own home joined with a container path the definition already bound
// to absolute, normalised, separator-free segments, and no two of those paths can
// name one directory: the definition refuses two mounts where one opens the other,
// and the concatenation of an injective home with distinct normalised paths is
// injective.

const (
	// UserServiceAccountPrefix is what every account of the third door opens on,
	// and it is the whole reason a definition's slug is bounded to sixteen
	// characters.
	//
	// The product prefix is not a style: the observation of `#100` refuses an
	// external declaration pointing at a port an account of this product holds,
	// and that rule recognises those accounts by this very prefix. The `user`
	// segment holds the third family apart from the two others — `svc` and
	// `entrypoint` — so that whoever reads this machine's user database learns
	// which door created an identity. Sixteen characters of prefix plus sixteen of
	// slug is exactly the thirty-two a user name of this machine may have, and the
	// derivation never truncates: two distinct slugs are two distinct accounts by
	// construction rather than by vigilance.
	UserServiceAccountPrefix = "your-cloud-user-"

	// userServiceHomeRoot is where those accounts keep their home, beside the
	// homes of the delivered profiles and out of the directories a human account
	// manager treats as people.
	userServiceHomeRoot = "/var/lib/"

	// userServiceVolumesDirectory, userServiceSnapshotsDirectory and
	// userServiceSecretsDirectory are the three subtrees of a user service's home,
	// and the layout the contract draws.
	//
	// The volumes live under one root rather than under the home directly, and
	// that is what makes an archive of this door what the contract says it is: a
	// single coherent snapshot of every volume at once, taken with the service
	// stopped, rather than one file per mount whose order would decide what came
	// back. It is also what keeps the secrets out of every archive without a rule
	// anybody has to remember — they are a sibling of the archived root and never
	// a part of it.
	userServiceVolumesDirectory   = "/volumes"
	userServiceSnapshotsDirectory = "/snapshots"
)

// userServiceAccount and userServiceHome are the two names everything else of a
// user service derives from, and the two places the slug is ever concatenated
// into an identity of this machine.
func userServiceAccount(slug string) string { return UserServiceAccountPrefix + slug }

func userServiceHome(slug string) string { return userServiceHomeRoot + userServiceAccount(slug) }

// userServicePlacementOfSlug is everything a user service owns on this machine
// that its slug alone decides.
//
// It is what the archive operations act on and what the reading "a managed
// service of this machine publishes this port" walks, and it deliberately carries
// nothing a revision decides: no image, because an archive names no image and the
// digest of an instance lives in the plan that deployed it; no volumes, because
// which paths a container mounts is a fact of a revision and not of a home; no
// environment and no secrets, for the same reason. What it does carry is the
// durable root, the archives beside it and the confinement, because those three
// are properties of the home rather than of any revision — which is exactly why a
// snapshot of a service can be approved without the definition travelling beside
// it.
func userServicePlacementOfSlug(slug string) placement {
	home := userServiceHome(slug)
	return placement{
		account:       userServiceAccount(slug),
		home:          home,
		comment:       "Your Cloud managed " + slug + " user service",
		description:   "Your Cloud managed " + slug + " user service",
		unitFileName:  userServiceAccount(slug) + ".container",
		serviceName:   userServiceAccount(slug) + ".service",
		containerName: userServiceAccount(slug),
		// The local verification of this door is the status alone, as the private
		// profile's is and for the same reason: what an application a user chose
		// answers a plain request with is described by no plan, no definition and no
		// approval, so requiring anything of it would be this machine inventing a
		// contract on the user's behalf. What is proven is that this machine serves
		// something on this port; the content belongs to its owner and to the proof.
		expectedContentType: "",
		dataDirectory:       home + userServiceVolumesDirectory,
		snapshotDirectory:   home + userServiceSnapshotsDirectory,
		// Every service of this door is confined, and there is no field of any
		// document that could say otherwise: the contract of the palier names "aucune
		// sortie réseau, sans exception déclarable", so the flag is a constant here
		// rather than something a revision could turn off.
		confined: true,
	}
}

// userServicePlacementOf fills that same placement from one verified definition
// and the instance a plan approved.
//
// It is the whole of the derivation the contract describes, and every line of it
// is mechanical:
//
//   - the account and the home come from the slug, as above;
//   - a volume's host path is the container path itself, rooted under the home's
//     volumes directory. `/srv/data` declared by the slug `blog` lives at
//     `/var/lib/your-cloud-user-blog/volumes/srv/data`, with no escape, no fallback
//     and no fingerprint — and it is stable from one revision to the next, because
//     the identity of the data is the container path. Renaming a container path in a
//     new revision therefore mounts a fresh, empty directory and leaves the previous
//     subtree under the home, exactly as a removal leaves the data: moving it is the
//     user's business and never an inference of this machine;
//   - the environment is the definition's own lines with the one interpolation this
//     product has replaced by the origin the plan approves. A definition that names
//     no origin leaves every line untouched, and the plan carries no origin to
//     interpolate — the two are held against one another by the agreement check
//     before this function is reached;
//   - the tmpfs paths are mounted exactly as the delivered public profile's proven
//     scratch is, because they are the same statement: memory inside the container,
//     gone with it, and nothing reaching the host;
//   - the container port decides the low-port sysctl, and it is the sheet that
//     reads it — the rule stopped being a constant per profile and became a
//     function of the document, which is the same fact calculated instead of
//     enumerated.
//
// The image is the repository the definition names joined with the digest the plan
// approves. Both halves have already been required to be exactly that pair, twice,
// and the sheet is written from this string rather than from either document.
func userServicePlacementOf(
	definition servicedefinition.Document,
	imageDigest, originHost string,
) placement {
	where := userServicePlacementOfSlug(definition.Slug)
	where.image = definition.ImageRepository + "@" + imageDigest
	where.containerPort = definition.ContainerPort
	where.writablePaths = definition.Tmpfs
	where.environment = interpolatedEnvironment(definition, originHost)
	where.secretKeys = definition.SecretKeys
	for _, containerPath := range definition.Volumes {
		where.volumes = append(where.volumes, volumeMount{
			host:      where.dataDirectory + containerPath,
			container: containerPath,
		})
	}
	// A definition that declares no volume keeps nothing, and the placement says so
	// by naming no durable root at all: no directory is created, no archive
	// directory exists, and every reading below treats the absence as the whole
	// statement. An archive operation naming such a service is refused on this very
	// machine — the home holds no volumes directory — rather than on a definition
	// nobody handed the archive.
	if len(where.volumes) == 0 {
		where.dataDirectory = ""
		where.snapshotDirectory = ""
	}
	return where
}

// interpolatedEnvironment renders the definition's inert lines with the one
// interpolation this product has.
//
// The replacement is exact and total: the placeholder is the only sequence a
// brace may appear in, the validation of the definition has already refused every
// other one, and an empty origin replaces nothing because the agreement check has
// already established that no line consumes an origin. There is no second
// template and no escape, so this is a substitution rather than an evaluation.
func interpolatedEnvironment(definition servicedefinition.Document, originHost string) []string {
	if originHost == "" {
		return definition.Environment
	}
	lines := make([]string, 0, len(definition.Environment))
	for _, line := range definition.Environment {
		lines = append(lines,
			strings.ReplaceAll(line, servicedefinition.OriginHostPlaceholder, originHost))
	}
	return lines
}

// deployUserService brings this machine to the state one user service plan
// describes, and says whether doing so changed anything.
//
// It is the private profile's flow with two things added and nothing removed, and
// each of the two changes what "the approved state already holds" means:
//
//   - the generated values. A key whose file exists is kept, always and whatever
//     a revision says; a key a revision declares and this machine holds no file
//     for is generated once, exclusively. A machine whose values vanished is a
//     drift and it is reapplied as one, exactly as vanished data is: this Auxiliary
//     cannot know what was there, and announcing "nothing changed" over a service
//     whose secrets it just recreated would be a machine claiming continuity it
//     does not have;
//   - the confinement is now a table several accounts share, so what is posed is
//     the whole table rather than one profile's rules. Everything else — the order
//     of the effects, the lift around the fetch, the local verification — is the
//     order `#102` fixed, and it is fixed there rather than restated here.
//
// The lift around the fetch is where the shared table earns its shape: what is
// posed while the image is being fetched is the confinement of every *other*
// account, so no instant of this flow leaves a service somebody else approved
// running unconfined.
func deployUserService(executor Executor, capabilities Capabilities, subject instance) (*Application, bool, error) {
	where := subject.placement
	desired := renderSheet(where, subject.localPort, subject.originHost)
	path := where.unitPath()

	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}
	dataHeld, err := durableDataHeld(executor, where)
	if err != nil {
		return nil, false, err
	}
	secretsHeld, err := generatedSecretsHeld(executor, where)
	if err != nil {
		return nil, false, err
	}
	identifier := noAccountIdentifier
	if capabilities.AccountPresent {
		identifier, err = executor.AccountIdentifier(where.account)
		if err != nil {
			return nil, false, fmt.Errorf("read the identifier of the service account: %w", err)
		}
	}
	confining, err := confinementJoinedBy(executor, where, identifier)
	if err != nil {
		return nil, false, err
	}
	confinement, err := readEgressBounds(executor, confining)
	if err != nil {
		return nil, false, err
	}

	if present && bytes.Equal(current, desired) && active && image == where.image &&
		dataHeld && secretsHeld && confinement.held {
		// The approved state already holds, down to the bytes of the sheet, the
		// identity of the running image, the existence of every volume, the existence
		// of every generated value and the bytes of the confinement. Nothing is
		// rewritten and nothing is restarted.
		return userServiceApplication(subject, where, path, ServiceStateActive, false, nil), false, nil
	}

	// Everything below this line changes the machine, so every failure below it is
	// a controlled failure and not a refusal.
	const touched = true

	if !capabilities.AccountPresent {
		if err := executor.CreateProbeAccount(where.account, where.home, where.comment); err != nil {
			return nil, touched, fmt.Errorf("create the service account: %w", err)
		}
		if err := executor.EnableLinger(where.account); err != nil {
			return nil, touched, fmt.Errorf("enable lingering for the service account: %w", err)
		}
		// Whether that fresh account can really run Podman rootless is a fact about
		// subordinate identifier ranges that cannot be observed before the account
		// exists, so it is re-read rather than assumed. The approved rollback follows,
		// and it removes the service rather than the account.
		refreshed, err := executor.Capabilities(where.account)
		if err != nil {
			return nil, touched, fmt.Errorf("observe the service account after creating it: %w", err)
		}
		if !refreshed.RootlessPodman {
			return nil, touched, fmt.Errorf(
				"the account %s was created but cannot run Podman rootless: this machine now holds that account and no unit",
				where.account,
			)
		}
		identifier, err = executor.AccountIdentifier(where.account)
		if err != nil {
			return nil, touched, fmt.Errorf("read the identifier of the service account: %w", err)
		}
		confining, err = confinementJoinedBy(executor, where, identifier)
		if err != nil {
			return nil, touched, err
		}
	}

	if where.bearsData() {
		if err := executor.EnsureServiceData(
			where.account, where.durableDirectories(), where.snapshotDirectory); err != nil {
			return nil, touched, fmt.Errorf("prepare the durable data of this service: %w", err)
		}
	}
	if where.bearsSecrets() {
		if err := executor.EnsureServiceSecrets(where.account, where.secretsDirectory(),
			where.environmentFilePath(), where.secretKeys); err != nil {
			return nil, touched, fmt.Errorf("prepare the generated values of this service: %w", err)
		}
	}
	if active {
		// The running container was created from a description this machine no longer
		// holds, and it is stopped here rather than after the sheet is written because
		// what comes next lifts this account's own confinement.
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the drifted service: %w", err)
		}
	}
	// The fetch below runs as this service's own account and the table refuses
	// exactly what fetching needs, so this account leaves the table for the length
	// of the fetch — and every other confined account stays in it.
	fetching, err := confinementLeftBy(executor, where)
	if err != nil {
		return nil, touched, err
	}
	if err := settleEgressBounds(executor, confinement, fetching); err != nil {
		return nil, touched, err
	}
	if err := executor.PullImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("fetch the pinned image: %w", err)
	}
	if err := poseEgressBounds(executor, confining); err != nil {
		return nil, touched, err
	}
	if err := executor.WriteUnitFile(path, desired); err != nil {
		return nil, touched, fmt.Errorf("write the Quadlet sheet: %w", err)
	}
	if err := executor.ReloadUserUnits(where.account); err != nil {
		return nil, touched, fmt.Errorf("reload the service account's units: %w", err)
	}
	if err := executor.StartService(where.account, where.serviceName); err != nil {
		return nil, touched, fmt.Errorf("start the service: %w", err)
	}
	if err := executor.ProbeAnswers(subject.localPort, where.expectedContentType); err != nil {
		// An image that will not serve under the controls of this product fails here,
		// and it fails controlled: the approved rollback is attempted from this very
		// point. Nothing relaxes ReadOnly=true, and nothing ever will — what an image
		// needs to write outside its data is a tmpfs its author declares in the next
		// revision.
		return nil, touched, fmt.Errorf(
			"the service was started but did not answer on %s:%d: this machine held a started service whose announced state was unproven: %w",
			loopbackAddress, subject.localPort, err,
		)
	}
	return userServiceApplication(subject, where, path, ServiceStateActive, true, nil), touched, nil
}

// removeUserService takes the service away and deliberately leaves three things
// where they are: the data, the archives and the generated values.
//
// What a removal takes away is the container, the sheet, the image and this
// account's place in the confinement table — everything that runs. What it keeps
// is everything the user owns, and that is a decision rather than an omission: no
// plan of this product describes the destruction of data, of an archive or of a
// secret, so no operation of this package performs one. The report names all
// three, so that "removing keeps them, redeploying finds them" is something a
// reader is told rather than something they have to know.
//
// The presence of the data is therefore not part of the decision to act, exactly
// as it is not for the private profile: a removal whose service, sheet, image and
// confinement are already gone changes nothing, whether or not the home still
// holds the volumes.
func removeUserService(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	path := where.unitPath()

	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}
	// The confinement this machine is to hold afterwards is the one every other
	// confined account is named in, and it is established before the sheet is taken
	// away — the reading that produces it is a reading of the sheets. Holding the
	// machine against that table rather than against "any table at all" is what
	// keeps a removal idempotent on a host that still runs other confined services.
	remaining, err := confinementLeftBy(executor, where)
	if err != nil {
		return nil, false, err
	}
	confinement, err := readEgressBounds(executor, remaining)
	if err != nil {
		return nil, false, err
	}
	kept, err := archivesKeptBy(executor, where)
	if err != nil {
		return nil, false, err
	}

	if !present && !active && image == "" && confinement.held {
		return userServiceApplication(subject, where, path, ServiceStateAbsent, false, kept), false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the service: %w", err)
		}
	}
	if present {
		if err := executor.RemoveUnitFile(path); err != nil {
			return nil, touched, fmt.Errorf("remove the Quadlet sheet: %w", err)
		}
		if err := executor.ReloadUserUnits(where.account); err != nil {
			return nil, touched, fmt.Errorf("reload the service account's units: %w", err)
		}
	}
	if err := executor.RemoveImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("remove the pinned image: %w", err)
	}
	// This account leaves the table last, once nothing of its service is left
	// running: a removal that lifted it first would hold, for an instant, a running
	// service that nothing confines. Every other account named in the table stays
	// in it, which is why this is a rewrite where others remain and a removal only
	// where this was the last confined service of the machine.
	if err := settleEgressBounds(executor, confinement, remaining); err != nil {
		return nil, touched, err
	}
	return userServiceApplication(subject, where, path, ServiceStateAbsent, true, kept), touched, nil
}

// durableDataHeld reports whether this machine holds every directory the volumes
// of this revision need, and answers true where the revision declares none.
//
// The root alone is not the question: a revision that added a volume to the
// previous one is a machine holding the root and missing a subtree, and mounting
// a path the engine would have to create itself is exactly what the ownership
// decision of `#102` refuses. A service that keeps nothing has nothing to hold,
// and says so without reading the machine at all.
func durableDataHeld(executor Executor, where placement) (bool, error) {
	for _, directory := range where.durableDirectories() {
		present, err := executor.ServiceDataPresent(directory)
		if err != nil {
			return false, fmt.Errorf("read the durable data of this service: %w", err)
		}
		if !present {
			return false, nil
		}
	}
	return true, nil
}

// generatedSecretsHeld reports whether this machine holds a value for every key
// this revision declares, and an environment file naming exactly those keys.
//
// It asks for presence and for names, never for a value, which is not a weaker
// question but the only one this package is allowed to ask: a generated value
// never leaves the machine and enters no document, no report and no observation,
// so nothing here could compare one. What it catches is the drift the sheet cannot
// see — a declared key with no value behind it, an environment file the sheet
// names and systemd would refuse to start without, and above all a revision that
// changed only its declared keys, which renders the very same sheet as the one
// before it.
func generatedSecretsHeld(executor Executor, where placement) (bool, error) {
	if !where.bearsSecrets() {
		return true, nil
	}
	held, err := executor.ServiceSecretsPresent(
		where.secretsDirectory(), where.environmentFilePath(), where.secretKeys)
	if err != nil {
		return false, fmt.Errorf("read the generated values of this service: %w", err)
	}
	return held, nil
}

// archivesKeptBy names the archives a removal leaves behind, and names none for a
// service that keeps nothing.
//
// It is read from the machine rather than asserted, so the sentence the report
// carries is a fact of this host: these are the archives that survive, by the
// names a human gave them, and the reserved slot is not among them.
func archivesKeptBy(executor Executor, where placement) ([]string, error) {
	if !where.bearsData() {
		return nil, nil
	}
	kept, err := executor.ServiceArchives(where.snapshotDirectory)
	if err != nil {
		return nil, fmt.Errorf("read the archives this machine holds for this service: %w", err)
	}
	return kept, nil
}

// userServiceApplication is how a deployment and a removal of the third door name
// what they left behind, so that the two say the same things in the same fields.
//
// It names what survives in both directions and on purpose. After a deployment
// the durable root is where the data lives and the secrets directory is where the
// generated values live; after a removal both are what this machine still holds —
// the lines of the report that make "removing keeps them, redeploying finds them"
// a statement a reader is given. Neither the values nor a byte of the data can
// appear here: what travels is a path and a count of names, never a content.
func userServiceApplication(
	subject instance,
	where placement,
	path, state string,
	changed bool,
	kept []string,
) *Application {
	application := &Application{
		Operation:     subject.operation,
		LocalPort:     subject.localPort,
		UnitPath:      path,
		DataPath:      where.dataDirectory,
		SnapshotSlots: kept,
		ServiceState:  state,
		Changed:       changed,
	}
	if where.bearsSecrets() {
		application.SecretsPath = where.secretsDirectory()
	}
	return application
}
