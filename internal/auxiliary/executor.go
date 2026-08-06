package auxiliary

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
	ReadUnitFile(path string) ([]byte, bool, error)
	// WriteUnitFile replaces the sheet atomically, root-owned, so the account
	// that runs the service cannot rewrite the description of what it runs.
	WriteUnitFile(path string, content []byte) error
	// RemoveUnitFile removes the sheet, and is content with it being absent.
	RemoveUnitFile(path string) error

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
}
