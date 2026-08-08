package auxiliary

import "time"

// Archive is what one archiving effect left behind: the digest of the bytes it
// wrote and the instant it wrote them.
//
// Both are facts the machine established and neither is a value a human could
// have approved in advance — which is why the plan of a snapshot carries no
// digest, and why the report of one carries both. The digest is the whole of what
// this product ever says about an archive: what is inside it is the data of a
// vault, and no field of any report, error or observation of this package can
// hold a byte of it.
type Archive struct {
	SHA256  string
	TakenAt time.Time
}

// Capabilities is what the machine can be observed to offer, read before
// anything is written to it.
//
// Every field is a fact about the host and none of them is a decision: what a
// missing capability means is decided by the preflight below, once, and always
// as a refusal rather than as a fallback. Quadlet creates no OpenRC unit, no
// runit script and no implicit replacement, so a machine without systemd or
// without a unified cgroup hierarchy is a machine this operation does not run
// on at all.
type Capabilities struct {
	// Systemd reports whether this host is run by systemd.
	Systemd bool
	// UnifiedCgroupHierarchy reports whether cgroup v2 is the hierarchy in use.
	UnifiedCgroupHierarchy bool
	// PodmanPresent reports whether the container engine exists at all.
	PodmanPresent bool
	// AccountPresent reports whether the dedicated account of the service being
	// applied already exists. Which account that is comes from the profile's
	// placement, never from a plan.
	AccountPresent bool
	// RootlessPodman reports whether that account can actually run Podman
	// rootless. It is only meaningful while AccountPresent is true: an account
	// that does not exist cannot be asked anything.
	RootlessPodman bool
}

// Executor is the whole surface through which this package touches the machine.
//
// Every method names one effect and takes typed arguments. There is deliberately
// no method that runs a command, no method that takes a command line and no
// method that takes a path chosen by a plan: the real implementation shells out
// with fixed argument vectors, and the only plan-derived value that reaches any
// of them is a port already bounded by the plan validation. Everything else it
// receives — the account, its home, the sheet's path, the service, the container
// and the image reference — comes from the profile's placement, which is a
// constant of this package. A test replaces this interface entirely, which is how
// the refusals below can be proven to happen before any effect rather than after
// a tidy one.
//
// The two methods that still spell "probe" are the seam `#14` proved, kept under
// their original names so that the probe path stays byte-identical: both are
// already parameterised by the placement they act for, and both serve every
// profile.
type Executor interface {
	// Capabilities observes the host and one named account without changing
	// either.
	Capabilities(account string) (Capabilities, error)

	// CreateProbeAccount creates the dedicated unprivileged local account a
	// managed service runs as: a system account, without password, without a
	// login shell and without any supplementary group. The comment is what the
	// machine's own user database will carry for it, so that an administrator
	// reading that database learns which service owns the identity.
	CreateProbeAccount(account, home, comment string) error
	// EnableLinger lets that account's systemd user manager run without a
	// session, which is what keeps an approved service in the state a human
	// approved across a reboot instead of only while someone is logged in.
	EnableLinger(account string) error

	// ReadUnitFile returns the current Quadlet sheet, and whether there is one.
	//
	// The three methods below are the one file discipline of this package rather
	// than three methods about units: one root-owned file that the Auxiliary
	// writes and a service account only ever reads, replaced atomically and never
	// in place. The entrypoint's static configuration and the fragment of a
	// published route are exactly that, and they travel through these three
	// methods rather than through copies of them under another name — the same
	// decision, and for the same reason, as the two methods below that still
	// spell "probe". The path is always a constant of this package or a constant
	// joined with a value the plan validation has already bounded to a character
	// set carrying no separator.
	ReadUnitFile(path string) ([]byte, bool, error)
	// WriteUnitFile replaces the file atomically, root-owned, so the account that
	// runs the service cannot rewrite the description of what it runs, and the
	// account that runs the entrypoint cannot rewrite the routes it serves.
	WriteUnitFile(path string, content []byte) error
	// RemoveUnitFile removes the file, and is content with it being absent.
	RemoveUnitFile(path string) error

	// EnsureEntrypointDirectories creates, root-owned, the three fixed
	// directories the entrypoint's sheet mounts read-only: the one its static
	// configuration lives in, the one its file provider watches, and the one the
	// certificates of declared names are read from. It takes no argument at all,
	// because all three are constants of the contract.
	EnsureEntrypointDirectories() error
	// ListRouteFragments names the route fragments this machine currently holds,
	// so that removing the entrypoint can refuse while any of them would stop
	// being served without a plan saying so. It reports names and never content.
	ListRouteFragments() ([]string, error)

	// HostPortsPolicy, WriteHostPortsPolicy and RemoveHostPortsPolicy are the one
	// host relaxation this product allows itself, as a declared effect of the
	// entrypoint plan rather than as a step of a bootstrap.
	//
	// Writing applies the policy immediately as well as persisting it, and
	// removing deletes the file and re-applies what is left, so that the running
	// kernel and the file on disk never disagree about what a human approved. The
	// content is a constant of this package and never a value from a plan.
	HostPortsPolicy() ([]byte, bool, error)
	WriteHostPortsPolicy(content []byte) error
	RemoveHostPortsPolicy() error

	// ReloadUserUnits makes the account's systemd read the sheets again.
	ReloadUserUnits(account string) error
	// StartService and StopService drive the service Quadlet generated.
	StartService(account, service string) error
	StopService(account, service string) error
	// ServiceActive reports whether that service is running right now. A service
	// that is absent is not an error here: it is an answer.
	ServiceActive(account, service string) (bool, error)

	// PullImage fetches exactly the pinned reference, so that the one moment
	// this operation needs the network is explicit and has its own failure.
	PullImage(account, reference string) error
	// RemoveImage leaves no image behind once the service is removed.
	RemoveImage(account, reference string) error
	// ContainerImage reports the exact image reference the running container was
	// created from, or an empty string when there is no such container. It is
	// what makes idempotence a fact about the machine rather than about the unit
	// file, and it is read as the pinned reference itself rather than as a
	// resolved platform digest, because the plan pins the reference a human
	// approved and not the manifest an architecture selected from it.
	ContainerImage(account, container string) (string, error)

	// ProbeAnswers performs the local verification these paliers exist to make:
	// one bounded HTTP request to the loopback address, retried a bounded number
	// of times, proving the announced state rather than assuming it.
	//
	// The status is always required to be 200. expectedContentType is the one
	// further invariant a profile may ask of the answer, or the empty string
	// where the status is the whole of the proof; it is matched as the prefix of
	// the media type, so a document served with a charset still answers.
	ProbeAnswers(port int, expectedContentType string) error

	// EntrypointAnswers is the local verification of the public entrypoint, and
	// it takes no argument because the invariant it proves depends on no route.
	//
	// The invariant is named once, here: the entry holds both public ports, it
	// gives no application route to a name nobody declared, and the clear port
	// does nothing but redirect to the secure one. In practice that is one
	// bounded HTTPS request to the loopback, whose Host is an address and
	// therefore a name no fragment declares, requiring the entry's own generic
	// refusal; and one bounded clear request requiring a permanent redirection
	// towards https. Certificate verification is deliberately skipped: the
	// certificate of a declared name is the proof's business, and this
	// verification exists before any name is declared at all.
	EntrypointAnswers() error

	// RouteAnswers is the local verification of one published route: the entry
	// serves the declared name from this machine, with both isolation headers,
	// from the backend the plan named.
	//
	// The declared name travels in the SNI and in the Host header, and
	// certificate verification is skipped for the same reason as above — what is
	// being proven here is that the fragment took effect and that the backend is
	// reached, not that a certificate chains to anything. The palier's own proof
	// takes the same constat from outside the machine, against a pinned
	// authority, and that one is `#92`.
	RouteAnswers(routeHost string) error

	// LinkRouteAnswers is the local verification of one name published through
	// the private passage, and it is a second method rather than a flag on the one
	// above because the two prove different things.
	//
	// What it requires of the answer is the status and nothing else. The isolation
	// headers belong to the public profile's middleware and a link route declares
	// none, so asking for them here would fail every correct publication; and what
	// a vault answers a plain request with is described by no plan of this palier.
	//
	// The request leaves this machine's loopback and comes back through the
	// tunnel, because that is what the published name actually does: the entry
	// reaches the peer's own address, the junction's table lets exactly the
	// approved port through, and the service answers on the other machine. That
	// couples this verification to a backend that is genuinely reachable, and it is
	// the honest reading of the contract's own rule — a publication that could not
	// be served must never be reported as a success. The order the plans are
	// approved in is what makes it a fair requirement: the service and the junction
	// exist before the route that names them.
	LinkRouteAnswers(routeHost string) error

	// The six methods below are the whole of what a private passage needs, and
	// they are separate from everything above for a reason that is not
	// convenience: a passage has no account, no container and no image, so none
	// of the methods above answer for one. The two files a passage owns travel
	// through the three file methods, because they are exactly what those methods
	// describe — root-owned files this Auxiliary writes and nothing else may
	// rewrite.

	// LinkPublicKey reports the public half of this machine's own passage key,
	// and whether this machine holds such a key at all.
	//
	// It is the one value of a passage that is meant to travel: the Controller
	// reads it as an observation and carries it, readable, into the junction plan
	// of the other machine. The private half is never a return value of this
	// interface, so no caller of it can leak what it has no way of holding.
	LinkPublicKey() (string, bool, error)
	// GenerateLinkKey generates this machine's own passage key, writes the
	// private half root-owned where only the network manager may also read it,
	// and returns only the public half.
	//
	// It refuses to replace a key that already exists rather than overwriting
	// one, so a preparation can never regenerate a key even if a caller asked it
	// to: replacing a key is a withdrawal followed by a preparation, two plans a
	// human reads. Creating the root-owned directory the key lives in is part of
	// this one effect, because a key and the place it lives are one fact.
	GenerateLinkKey() (string, error)
	// RemoveLinkKey takes that private key away, and is content with it being
	// absent.
	RemoveLinkKey() error

	// LinkInterfaceActive reports whether the closed interface of the passage
	// exists on this machine right now. An interface that is absent is not an
	// error here: it is an answer.
	LinkInterfaceActive() (bool, error)
	// RemoveLinkInterface takes that interface away, and is content with it being
	// absent. It removes the interface and never the files that describe it: what
	// a withdrawal removes, it removes one named effect at a time.
	RemoveLinkInterface() error

	// LinkRules, WriteLinkRules and RemoveLinkRules are the bounding table of the
	// passage, and they are three methods rather than two for the reason the host
	// ports policy is: what is on disk and what the kernel holds are one fact
	// here, so persisting and applying are one effect and removing is its exact
	// inverse.
	//
	// Writing replaces the root-owned file and loads it into the kernel in the
	// same call, so a machine that has approved a junction is never running
	// without the bounds it just wrote. Removing deletes the table from the
	// kernel by its own name and then removes the file: it names one table, so
	// every other table this machine carries — an administrator's firewall above
	// all — is untouched. The content is rendered from constants and the one
	// approved port, and never from anything else a plan carries.
	LinkRules() ([]byte, bool, error)
	WriteLinkRules(content []byte) error
	RemoveLinkRules() error

	// LinkLoopbackPolicy, WriteLinkLoopbackPolicy and RemoveLinkLoopbackPolicy
	// are the one host relaxation a passage declares, on the initiator alone.
	//
	// They are the entrypoint's three methods again, over another file and
	// another setting, and they behave identically: writing persists and applies,
	// removing deletes the file and puts the kernel back to the value it carries
	// when nothing has raised it. The setting is scoped to the passage's own
	// interface, so what a removal puts back is scoped to it as well.
	LinkLoopbackPolicy() ([]byte, bool, error)
	WriteLinkLoopbackPolicy(content []byte) error
	RemoveLinkLoopbackPolicy() error

	// EnableLinkRulesAtBoot and DisableLinkRulesAtBoot decide whether the oneshot
	// unit that puts the bounds back after a reboot runs at the next one.
	//
	// The unit file itself travels through the three file methods above, because
	// it is exactly what they describe. What these two add is the one thing a
	// file cannot say about itself: enabling makes the manager run it at boot
	// without running it now, since the junction has already applied both files
	// itself, and disabling takes that away before the file is removed.
	EnableLinkRulesAtBoot() error
	DisableLinkRulesAtBoot() error

	// The twelve methods below are the whole of what a data-bearing placement
	// needs beyond what a stateless one already asked for, and they are separate
	// from everything above for one reason: nothing above can create a directory a
	// container writes to, hold an account's numeric identity, generate a value
	// this machine keeps to itself, or move a tree of bytes. Every one of them takes paths that are constants of this package or a
	// constant joined with a slot the plan validation has already bounded to a
	// character set carrying no separator.

	// AccountIdentifier reports the numeric identifier one account was given on
	// this machine.
	//
	// It is a fact about the machine and never a value of a plan: identifiers are
	// allocated when an account is created, so a document naming one would be a
	// document describing a machine it has never seen. It is read at the moment
	// the confinement table is rendered, which is why it is a seam and not a field
	// of a placement.
	AccountIdentifier(account string) (int, error)

	// ServiceDataPresent reports whether the durable data directory of a profile
	// exists. A directory that is absent is not an error here: it is an answer,
	// and the one that tells a deployment which has never run from a deployment
	// whose data has gone.
	ServiceDataPresent(path string) (bool, error)
	// EnsureServiceData creates, in one effect, the directories a data-bearing
	// placement owns, and is content with them already existing.
	//
	// They are created with two different owners and the difference is the whole
	// point. The data belongs to the service's own account, because a rootless
	// container's root is that account outside its user namespace and the image
	// must be able to write its volume; a directory left to root would be a
	// service that starts and cannot write, or — worse — one the engine creates
	// itself the first time it is missing, with an owner and a mode nobody decided.
	// The archives belong to root alone, because nothing but this Auxiliary ever
	// writes one and a container escape that reached the account must not be able
	// to read, alter or destroy the backups of the very data it just escaped from.
	// Both are closed to every other identity of the machine.
	//
	// The data side is a list rather than one path because a placement of the third
	// door has one durable root and one directory per declared volume under it, all
	// of them the account's. The list is given parents first and every entry of it
	// is a constant of this package or that root joined with a container path the
	// definition already bound to normalised, separator-free segments.
	EnsureServiceData(account string, dataDirectories []string, snapshotDirectory string) error

	// ServiceSecretsPresent reports whether this machine already holds a value for
	// every key a revision declares, and an environment file naming exactly those
	// keys and no others.
	//
	// It answers presence and names, never a value, and that is not a weaker
	// question but the only one this package may ask: a generated value never
	// leaves the machine and enters no document, no report and no observation, so
	// nothing above this seam could be handed one to compare. Key names are not
	// values — a definition displays them wherever it is displayed.
	//
	// The names are part of the question because they are the one thing about a
	// revision the sheet cannot say. Two revisions of one service that differ only
	// by their declared keys render the very same sheet, so a deployment holding
	// itself against the sheet alone would find "nothing changed" over an
	// environment file naming the previous revision's keys. An absent value, or a
	// file naming another set, is an answer and not a failure: it is what tells a
	// first deployment from a redeployment, and a new revision from a replay.
	ServiceSecretsPresent(directory, environmentFile string, keys []string) (bool, error)
	// EnsureServiceSecrets generates what a revision declares and this machine does
	// not hold, keeps everything it does hold, and rewrites the environment file
	// the sheet reads.
	//
	// It is one effect and not three because it has one invariant: after it, this
	// machine holds exactly one value per declared key — the value it already had
	// wherever it had one — and an environment file naming exactly those keys.
	// Nothing here ever replaces a value: a file that exists is kept whatever a
	// revision says, the creation is exclusive, and no plan of this product
	// describes the destruction of a secret, so a key a revision stopped declaring
	// leaves the environment file and keeps its own file under the home.
	//
	// The directory and the values belong to the service's own account, because
	// the account is what reads them back through the sheet; nothing else on the
	// machine may enter the directory or open a value.
	EnsureServiceSecrets(account, directory, environmentFile string, keys []string) error

	// ManagedUserServiceSlugs names the user services this machine holds a sheet
	// for, sorted, and reports names alone.
	//
	// It exists because the third door has no closed list this package could hold:
	// which user services a machine runs is a fact of that machine, and two
	// questions of this package genuinely need it — which accounts belong in the
	// one confinement table, and whether a managed service of this machine
	// publishes a given loopback port. A machine that holds none answers none.
	ManagedUserServiceSlugs() ([]string, error)

	// ServiceArchives names the ordinary slots this machine holds for one profile,
	// sorted, and never the reserved slot: the slot the return mechanism owns is
	// not one a human named, so it is not one this seam reports. It answers with
	// names and never with content.
	ServiceArchives(directory string) ([]string, error)
	// ServiceArchivePresent reports whether one named archive exists. It is the
	// one question the reserved slot is ever asked, and it is asked by path.
	ServiceArchivePresent(path string) (bool, error)
	// ArchiveServiceData writes the data directory into one named archive and
	// reports what it wrote: the digest of the bytes, and the instant it wrote
	// them.
	//
	// It refuses to replace an archive that already exists. That refusal is the
	// immutability of the backups made structural rather than checked: a caller
	// holding this seam cannot overwrite a slot even by mistake, and the only way
	// to reuse a name is the explicit discard a human approves separately.
	ArchiveServiceData(dataDirectory, archivePath string) (Archive, error)
	// ExchangeServiceData is the whole of a return, as one effect: the data
	// becomes what the named archive holds, and the state it replaced is left in
	// the reserved archive, whose digest and instant come back.
	//
	// It is one method rather than "write the reserved slot, then replace the
	// data" for a reason that is not tidiness. The one archive a return may name
	// besides an ordinary slot is the reserved slot itself — that is the signed
	// rollback of every return — and written as two effects those two would be the
	// same file: the first would overwrite what the second was about to read, and
	// the return of a return would restore the state it had just replaced. Here
	// the archive is read before the reserved one is written, so the two paths
	// being one file is a swap and not a loss.
	//
	// It is also the only seam of this package that may write over an archive that
	// exists, and the only path it ever writes is the reserved one, built by its
	// caller from the plan package's own constant. That is what keeps the
	// immutability of the ordinary slots structural: no seam here can replace one.
	//
	// What it leaves behind is the named archive's tree and nothing of the tree
	// that was there, so a return is a replacement and never a merge.
	ExchangeServiceData(archivePath, dataDirectory, reservedPath string) (Archive, error)
	// RemoveServiceArchive removes one named archive, and is content with it being
	// absent.
	RemoveServiceArchive(path string) error

	// EgressRules, WriteEgressRules and RemoveEgressRules are the one confinement
	// table of this machine, and they are three methods for the reason the
	// passage's own bounds are: what is on disk and what the kernel holds are one
	// fact, so persisting and applying are one effect and removing is its exact
	// inverse.
	//
	// Writing replaces the root-owned file and loads it into the kernel in the
	// same call, so a machine that has deployed a confined service is never
	// running it without the confinement it just wrote. Removing deletes the table
	// from the kernel by its own name and then removes the file: it names one
	// table, so every other table this machine carries — the passage's own and an
	// administrator's firewall above all — is untouched.
	EgressRules(path string) ([]byte, bool, error)
	WriteEgressRules(path string, content []byte) error
	RemoveEgressRules(path string) error

	// EnableEgressRulesAtBoot and DisableEgressRulesAtBoot decide whether the
	// oneshot unit that poses the confinement again runs at the next boot.
	//
	// The unit file itself travels through the three file methods above, because
	// it is exactly what they describe. What these two add is the one thing a file
	// cannot say about itself: enabling makes the manager run it at the next boot
	// without running it now, since the deployment has already applied the table
	// itself, and disabling takes that away before the file is removed.
	EnableEgressRulesAtBoot() error
	DisableEgressRulesAtBoot() error

	// EnableNetworkManagement makes this machine's network manager run now and
	// after a reboot, and ReloadNetworkConfiguration makes it read the passage's
	// two files again.
	//
	// The first is a declared effect of the preparation rather than a step of a
	// bootstrap, exactly as the host ports policy is a declared effect of the
	// entrypoint: the human who approves a passage approves this machine letting
	// its network manager hold the interfaces this product's files match. It is
	// scoped by those files and by nothing else — networkd manages what its own
	// [Match] sections name — which is what makes it coexist with whatever else
	// already configures this machine's real interfaces.
	EnableNetworkManagement() error
	ReloadNetworkConfiguration() error
}
