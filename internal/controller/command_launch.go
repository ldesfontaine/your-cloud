package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// The launch is the one place of this product whose effects leave the
// Controller's machine, and everything here is written to keep that one place
// small (docs/architecture/TRAJET-DE-COMMANDE.md, maillon 4).
//
// The App names a machine and hands over signed bytes. Everything else —
// the address, the port, the account, the expected host key, the identity — is
// a fact of enrolment this Controller reads on its own disk, in two root-owned
// places it can only read: the command endpoint sheets and the command
// identities loaded as service credentials. Nothing in a request can move any
// of them.

const (
	// maxCommandEndpointBytes bounds one endpoint sheet before it is parsed.
	// A sheet is a machine identifier, a host, a port, an account and one
	// host key: the size those bounded fields reach, rounded up once.
	maxCommandEndpointBytes = int64(4 * 1024)

	// commandEndpointSchema is the one sheet version this palier reads.
	commandEndpointSchema = 1

	// maxCommandConnectSeconds bounds connection and authentication. Nothing
	// has been written yet at that point, so exceeding it means a machine that
	// cannot be reached — a refusal before bytes rather than an unknown. It is
	// a ceiling: the effective value is the smaller of it and what is left of
	// the approval's own window.
	maxCommandConnectSeconds = 10

	// commandHostKeyAlgorithm is the one algorithm a pinned host key is read
	// in, the same single value the forced-command entry already holds for the
	// identity: the Controller pins these itself and a second accepted
	// algorithm would only be a second thing to get wrong.
	commandHostKeyAlgorithm = "ssh-ed25519"

	// maxCommandAnswerBytes bounds each of the two channels the client hands
	// back. The report a machine renders is bounded by the package that owns
	// it and a refusal sentence by the registry; this is the reader's own
	// ceiling, above both, so a machine that talks forever cannot make this
	// Controller grow.
	maxCommandAnswerBytes = int64(64 * 1024)

	// commandKnownHostsFile is derived under the service runtime directory at
	// every launch and holds the one machine being reached, never a line
	// learnt from a network.
	commandKnownHostsFile = "known_hosts"
)

// commandEndpoint is the enrolment fact, and deliberately not part of the
// inventory: the inventory is readable and writable by the App, and an
// address the App could rewrite would be an App that chooses where a
// command goes. The App names a machine; it never names an endpoint.
type commandEndpoint struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Account       string `json:"account"`
	// HostKey is the base64 key blob of the pinned host key, exactly as a
	// `known_hosts` line carries it. It comes from the observation step a human
	// confirmed during the audit; the client that authenticates never turns a
	// first contact into trust.
	HostKey string `json:"host_key"`
}

var (
	canonicalCommandAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	canonicalCommandHostKey = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

// validate refuses a sheet by name rather than trusting a file that lives in a
// root-owned directory: root-owned says who may write it, never that what was
// written is a sheet this Controller can act on.
func (endpoint commandEndpoint) validate(machineID string) error {
	switch {
	case endpoint.SchemaVersion != commandEndpointSchema:
		return errors.New("the command endpoint sheet declares an unsupported schema version")
	case machineid.Validate(endpoint.MachineID) != nil || endpoint.MachineID != machineID:
		return errors.New("the command endpoint sheet names another machine than the one it is filed under")
	case endpoint.Port < 1 || endpoint.Port > 65535:
		return errors.New("the command endpoint sheet declares no usable port")
	case !canonicalCommandAccount.MatchString(endpoint.Account):
		return errors.New("the command endpoint sheet declares no usable account")
	case !validCommandHost(endpoint.Host):
		return errors.New("the command endpoint sheet declares no usable host")
	}
	// The key is held to its own shape and to its decoded length: a blob that
	// is not an Ed25519 host key would be a `known_hosts` line that pins
	// nothing, and a pin that pins nothing is worse than no pin because it
	// reads like one.
	if !canonicalCommandHostKey.MatchString(endpoint.HostKey) {
		return errors.New("the pinned host key is not a canonical base64 blob")
	}
	decoded, err := base64.StdEncoding.DecodeString(endpoint.HostKey)
	if err != nil || len(decoded) != 51 {
		return errors.New("the pinned host key is not an Ed25519 host key blob")
	}
	return nil
}

// validCommandHost accepts a literal address or a hostname, and refuses
// anything a shell or an option list could read as something else. The value
// reaches OpenSSH as one argument, never as a fragment of a line, and this
// keeps it a destination rather than an expression.
func validCommandHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "-") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, character := range host {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '.' || character == '-':
		default:
			return false
		}
	}
	return true
}

// knownHostsLine renders the one line the derived file holds, in the form
// OpenSSH really looks the host up under.
//
// An earlier version wrote the bracketed `[host]:port` form unconditionally,
// on the belief that « one shape means one thing to read, and OpenSSH accepts
// it for port 22 too ». It does not, and the belief cost every launch to a
// machine on the default port: OpenSSH looks up the **plain host** when the
// port is 22 and the bracketed form only otherwise, so a pin written the other
// way is a pin the client never finds. Measured against a real `sshd`: the
// bracketed line answers « No ED25519 host key is known for <host> ... Host key
// verification failed », the plain line authenticates.
//
// This is not a weaker pin — it is the same key, held just as strictly, written
// where the client reads it. The shape is dictated by the program being
// interoperated with, and this is the one place the product does not get to
// choose its own convention.
func (endpoint commandEndpoint) knownHostsLine() string {
	if endpoint.Port == 22 {
		return fmt.Sprintf("%s %s %s\n",
			endpoint.Host, commandHostKeyAlgorithm, endpoint.HostKey)
	}
	return fmt.Sprintf("[%s]:%d %s %s\n",
		endpoint.Host, endpoint.Port, commandHostKeyAlgorithm, endpoint.HostKey)
}

// commandRunner is the seam the OpenSSH client enters through, defined here
// because this package is its only consumer.
//
// `WroteStandardInput` is the observation the contract rests on, and it is why
// this is not simply an exit code: `non lancé` is reserved for a failure the
// Controller *saw* happen before the first byte of the wrapper. Everything
// after that byte is a machine that may have acted, and the honest answer is
// the weaker one.
type commandRunner interface {
	Run(ctx context.Context, program string, arguments []string, standardInput []byte) commandResult
}

type commandResult struct {
	StandardOutput     []byte
	StandardError      []byte
	ExitCode           int
	WroteStandardInput bool
	// Err is this Controller's own failure to even run the client — never the
	// machine's answer.
	Err error
}

// CommandDispatcher launches the Auxiliary of one machine through the OpenSSH
// client of the distribution, bounded option by option.
//
// The client is the distribution's rather than an SSH stack embedded in Go:
// no secret crosses the command line here, no passphrase exists, there is no
// agent budget to keep, and embedding a protocol implementation plus a host-key
// policy in the component that holds every identity of the fleet would be
// owning and proving both. The other end is already OpenSSH. The named residual
// risk is that the client's version and compiled defaults belong to the
// distribution; the product bounds what it passes, not what OpenSSH is.
type CommandDispatcher struct {
	infrastructure string
	program        string
	// endpointPrefix and identityPrefix are **prefixes**, not directories, and
	// the difference is the whole reason this palier could not launch anything
	// before it was written down.
	//
	// The unit the package delivers passes each of the two root-owned
	// directories as one credential — `LoadCredential=command-endpoints:/etc/...`
	// — because the package knows no machine and a unit naming sixty-four of
	// them would carry machine-specific configuration. When the source of a
	// credential is a directory, systemd does not reproduce that directory: it
	// loads every file in it as a **separate credential named `ID_FILENAME`**,
	// flat, in `$CREDENTIALS_DIRECTORY`. Measured on systemd 257: two sheets in
	// `/etc/your-cloud/command-endpoints/` materialise as
	// `command-endpoints_lab-machine-1.json` and
	// `command-endpoints_lab-machine-2.json`, and no `command-endpoints/`
	// directory exists at all.
	//
	// This code therefore composes what the unit really produces rather than
	// what the directory on disk looks like. The unit is the authority — it is
	// what the package installs — and there is one truth between the two: the
	// credential ID in the unit and the prefix these fields hold.
	endpointPrefix string
	identityPrefix string
	// credentials is the directory both prefixes sit directly inside — the one
	// systemd gave this service — and it is the anchor every credential path is
	// held against. It is derived from the prefixes rather than passed beside
	// them so the two can never name different places.
	credentials    string
	runtime        string
	runner         commandRunner
	now            func() time.Time
	maxStderrBytes int
}

// sshClientProgram is where the distribution this palier supports keeps the
// OpenSSH client. It is named absolutely like everything else on this path: a
// relative name would be resolved by a `PATH` this service does not control,
// and this service deliberately runs the client with no environment at all.
const sshClientProgram = "/usr/bin/ssh"

// sshClientFailureExitCode is the status OpenSSH reserves for **its own**
// failures — a host key that does not match the pin, a machine that cannot be
// reached, an authentication that did not pass — as opposed to the status of
// the remote command, which it passes through. Measured against a real `sshd`
// rather than assumed: a substituted host key and an unreachable address both
// answer 255.
const sshClientFailureExitCode = 255

// NewSSHDispatcher builds the one engine whose effects leave this machine, with
// the real OpenSSH client and the real clock.
//
// The two credential arguments are the **prefixes** systemd's flattening
// produces — `$CREDENTIALS_DIRECTORY/command-identities` and
// `.../command-endpoints` — never directories to walk into; see the field
// comments on CommandDispatcher for what the unit really materialises. The
// runtime directory is the one the known hosts are derived into, and which
// disappears with the service.
func NewSSHDispatcher(infrastructureID, identities, endpoints, runtime string) (*CommandDispatcher, error) {
	return newCommandDispatcher(infrastructureID, sshClientProgram, endpoints, identities, runtime,
		systemCommandRunner{maxAnswerBytes: maxCommandAnswerBytes}, time.Now)
}

// newCommandDispatcher refuses every path that is not absolute and canonical: this
// service has no home, no `~/.ssh` and no user configuration, so every entry of
// the client must be an explicit path — there is nowhere an identity could be
// picked up by default, and this constructor keeps it that way.
func newCommandDispatcher(infrastructureID, program, endpoints, identities, runtime string, runner commandRunner, now func() time.Time) (*CommandDispatcher, error) {
	if runner == nil || now == nil {
		return nil, errors.New("a launch needs a client and a clock")
	}
	if identifier.ValidateUUIDv4(infrastructureID) != nil {
		return nil, errors.New("a launch answers for one canonical infrastructure")
	}
	for _, path := range []string{program, endpoints, identities, runtime} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("every path of the launch must be absolute and canonical")
		}
	}
	return &CommandDispatcher{
		infrastructure: infrastructureID,
		program:        program, endpointPrefix: endpoints, identityPrefix: identities,
		credentials: filepath.Dir(endpoints),
		runtime:     runtime, runner: runner, now: now,
		maxStderrBytes: maxDispatchMachineSentenceBytes,
	}, nil
}

// Dispatch runs the launch, and it runs entirely after the dispatch record is
// durably `in_flight`: everything it is handed is an authority already spent on
// this Controller, and nothing it returns can un-spend it.
//
// It reads top to bottom as the contract's order of effects: read the enrolment
// facts, derive the deadline from the authority, derive the known hosts, run
// the bounded client, and conclude.
func (dispatcher *CommandDispatcher) Dispatch(record DispatchRecord, wrapper []byte) DispatchConclusion {
	endpoint, err := dispatcher.readEndpoint(record.MachineID)
	if err != nil {
		// Nothing was opened, and the Controller saw why.
		return notLaunched("this machine has no usable command endpoint on this Controller")
	}
	// The machine identifier reached this line through readEndpoint above, which
	// refuses anything `machineid.Validate` does not accept: no separator and no
	// traversal can enter the name of a private key from here.
	identity := dispatcher.identityPrefix + "_" + record.MachineID
	if err := requireCommandIdentity(identity, dispatcher.credentials); err != nil {
		return notLaunched("this Controller holds no command identity for this machine")
	}
	remaining, ok := dispatcher.remainingAuthority(record)
	if !ok {
		// The window closed between acceptance and here. Nothing is sent: a
		// launch that outran the authority permitting it would have nothing
		// left to justify it.
		return notLaunched("the approval's own window closed before any byte was sent")
	}
	knownHosts, err := dispatcher.deriveKnownHosts(endpoint)
	if err != nil {
		return notLaunched("this Controller could not derive the known host of this machine")
	}
	defer func() { _ = os.Remove(knownHosts) }()

	context, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()
	result := dispatcher.runner.Run(context, dispatcher.program,
		commandArguments(endpoint, identity, knownHosts, remaining), wrapper)
	return concludeLaunch(record, dispatcher.infrastructure, result, dispatcher.maxStderrBytes)
}

// remainingAuthority derives the launch's whole deadline from the envelope's
// own window, never from a number written beside it. The window is itself
// bounded to `approval.MaxLifetimeSeconds` at construction, so this is at most
// that ceiling and strictly under it as soon as any time has passed.
func (dispatcher *CommandDispatcher) remainingAuthority(record DispatchRecord) (time.Duration, bool) {
	now := uint64(dispatcher.now().Unix())
	if record.ExpiresAtUnix <= now {
		return 0, false
	}
	return time.Duration(record.ExpiresAtUnix-now) * time.Second, true
}

func (dispatcher *CommandDispatcher) readEndpoint(machineID string) (commandEndpoint, error) {
	if machineid.Validate(machineID) != nil {
		return commandEndpoint{}, errors.New("malformed machine identifier")
	}
	path := dispatcher.endpointPrefix + "_" + machineID + ".json"
	data, err := readCommandCredential(path, dispatcher.credentials, maxCommandEndpointBytes)
	if err != nil {
		return commandEndpoint{}, err
	}
	var endpoint commandEndpoint
	if err := strictjson.Decode(data, &endpoint); err != nil {
		return commandEndpoint{}, err
	}
	if err := endpoint.validate(machineID); err != nil {
		return commandEndpoint{}, err
	}
	return endpoint, nil
}

// requireCommandIdentity refuses to hand the client a path that is not an
// anchored, regular, unreadable-by-others file. It holds the same four
// invariants as readCommandCredential — anchored, owned by root or by this
// service, no « other » bits, never a symbolic link — because it guards the
// same kind of object under the same custody model; it merely never reads the
// bytes, since what happens to this path is that OpenSSH is handed it.
//
// `Lstat` rather than `Stat` is what refuses the symbolic link here: a link
// would fail `IsRegular`, so an anchored name can never point out of the
// anchored directory.
func requireCommandIdentity(path, anchor string) error {
	cleaned := filepath.Clean(path)
	if anchor == "" || filepath.Dir(cleaned) != filepath.Clean(anchor) {
		return errors.New("a command identity must live in the credentials directory of this service")
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return errors.New("a command identity must be a regular file no other account may read")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("a command identity must be materialised by root or owned by this service")
	}
	return nil
}

// readCommandCredential reads one file the service was *handed* rather than one
// it wrote itself.
//
// The guard this function holds is not a relaxation of an earlier one: it is a
// **different custody model**, because the earlier one described a world this
// service never runs in. That one encoded « a private file I own », the
// `~/.ssh` model — no group or other bits, owner equal to this process. systemd
// credentials are never that, under any unit: measured on systemd 257 under the
// packaged unit, a materialised credential is owned by `root`, carries mode
// `0440` and grants this service its access through an **ACL**. The old guard
// therefore refused the only shape ever delivered, and the launch could not
// read a single identity in production (`#130`).
//
// What holds the secret is the place, not the file mode, and the invariants
// below encode that place:
//
//   - **anchored** — the file must live under the credentials directory systemd
//     gave this service. A free path is refused outright, so no caller can aim
//     this reader at a file someone else can write;
//   - **owner** — `root` or this process, and nothing else. `root` materialised
//     it, or this process owns it; a third owner is a theft;
//   - **mode** — the « other » bits are forbidden. The group bits are systemd's
//     granting mechanism, not a leak;
//   - **no symbolic link** — `O_NOFOLLOW`, so an anchored name can never be a
//     door out of the anchored directory.
//
// The store itself is a dedicated read-only tmpfs mounted
// `mode=700,nosuid,nodev,noexec,nosymfollow`, whose directory is `0550
// root:root`: no other account can even traverse into it. Trusting that
// materialisation is the residual risk, and it is the same trust every other
// credential of this unit already rests on.
func readCommandCredential(path, anchor string, maximum int64) ([]byte, error) {
	// The anchor is compared on the cleaned path before anything is opened: a
	// credential is only ever a name directly inside the directory systemd
	// filled, never a descendant reached through a component of its own.
	cleaned := filepath.Clean(path)
	if anchor == "" || filepath.Dir(cleaned) != filepath.Clean(anchor) {
		return nil, errors.New("a command credential must live in the credentials directory of this service")
	}
	file, err := os.OpenFile(cleaned, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return nil, errors.New("a command credential must be a regular file no other account may read")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("a command credential must be materialised by root or owned by this service")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, errors.New("a command credential is empty, unreadable or too large")
	}
	return data, nil
}

// deriveKnownHosts writes the one machine being reached, in the runtime
// directory that disappears with the service. Nothing else writes this file and
// nothing ever appends a learnt line to it.
func (dispatcher *CommandDispatcher) deriveKnownHosts(endpoint commandEndpoint) (string, error) {
	path := filepath.Join(dispatcher.runtime, commandKnownHostsFile)
	if err := writePrivateStateFile(dispatcher.runtime, path, ".known-hosts-",
		[]byte(endpoint.knownHostsLine())); err != nil {
		return "", err
	}
	return path, nil
}

// commandArguments is a positive list, and every entry takes something away.
// There is no remote command: the forced command on the other end decides what
// runs, and passing one would be this Controller choosing.
func commandArguments(endpoint commandEndpoint, identity, knownHosts string, remaining time.Duration) []string {
	connect := maxCommandConnectSeconds
	// The connection bound is a sub-bound of the authority, never an addition
	// to it: an approval with four seconds left does not grant itself ten
	// seconds of connecting.
	if seconds := int(remaining / time.Second); seconds < connect {
		connect = seconds
	}
	if connect < 1 {
		connect = 1
	}
	return []string{
		"-F", "/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-i", identity,
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ClearAllForwardings=yes",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=" + strconv.Itoa(connect),
		"-p", strconv.Itoa(endpoint.Port),
		"-l", endpoint.Account,
		"--",
		endpoint.Host,
	}
}

// concludeLaunch turns what happened into one of the registry's terminal
// states, and the whole point is that it never invents a stronger one.
//
// It reads top to bottom as the weakening it is: an observed failure before the
// wrapper, a channel that closed, a bare refusal, a valid report, and — for
// everything else, including a report that named another dispatch — the honest
// weaker state rather than a success nobody established.
func concludeLaunch(
	record DispatchRecord, infrastructureID string, result commandResult, maxSentence int,
) DispatchConclusion {
	if !result.WroteStandardInput {
		// The client failed before the first byte of the wrapper, and this
		// Controller observed it: a host key that changed, an unreachable
		// machine, an authentication that did not pass. No effect exists.
		return notLaunched("the connection failed before the first byte of the wrapper; the machine is unchanged")
	}
	if result.Err != nil {
		return unreported("the channel closed before this Controller could read an answer")
	}
	// The client failed on its own account, and the machine never spoke.
	//
	// `WroteStandardInput` is not enough to tell this apart, and that is the
	// defect this branch exists for: it records that the wrapper entered the
	// **pipe**, not that it reached the machine. A wrapper of a few kibibytes
	// fits the pipe buffer, so it is written even when the handshake never
	// completed — and the conclusion below would then read « the machine
	// refused » and keep the client's own words as the *machine's sentence*.
	// Under a real substitution the human would read OpenSSH's
	// « REMOTE HOST IDENTIFICATION HAS CHANGED … man-in-the-middle attack »
	// quoted as the answer of the machine being impersonated. That is a
	// security defect rather than an ergonomic one, and it is why this is
	// decided before the refusal branch.
	//
	// The discriminant is a **conjunction**: OpenSSH reserves 255 for its own
	// failures — measured here against a real `sshd`, both for a changed host
	// key and for an unreachable machine — and a launch that reached the forced
	// command would have produced an answer to read. The residual ambiguity is
	// named rather than hidden: a remote command that itself exited 255 without
	// writing one byte would be classed `not launched`. That errs in the safe
	// direction, the same one as `launched, unreported` — the product says the
	// weaker of the two things it might mean.
	//
	// The client's text is deliberately **not** carried into the observation:
	// by contract that field is this Controller's own account of its own
	// attempt, drawn from a closed set and bounded to 256 bytes, and OpenSSH's
	// warning is neither this product's words nor within that bound. What is
	// lost is a diagnostic, and it is named as a debt rather than smuggled into
	// a field that would then mean two different things.
	if result.ExitCode == sshClientFailureExitCode && len(result.StandardOutput) == 0 {
		return notLaunched("the client could not open a session with this machine; nothing was sent")
	}
	if result.ExitCode != 0 && len(result.StandardOutput) == 0 {
		// A refusal renders no report: the machine exited in failure and wrote
		// why. The sentence is kept exactly as received and never paraphrased.
		return DispatchConclusion{
			State:           DispatchMachineRefused,
			MachineSentence: boundedMachineSentence(result.StandardError, maxSentence),
		}
	}
	ingested, err := ingestReport(record, infrastructureID, result.StandardOutput)
	if err != nil {
		// A discarded report never becomes a failure and never becomes a
		// success: this Controller does not know what the machine did, and it
		// says so. The reason is its own observation, never quoted as the
		// machine's sentence.
		return unreported(err.Error())
	}
	changed, outcome, err := reportedConclusion(ingested)
	if err != nil {
		return unreported(err.Error())
	}
	// A report that was read carries no sentence of its own: the error channel
	// of a machine that concluded is noise, and storing it beside a conclusion
	// would make a success look like it had something to say.
	return DispatchConclusion{
		State: DispatchReported, ReportedChanged: changed, ReportedOutcome: outcome,
	}
}

func notLaunched(observation string) DispatchConclusion {
	return DispatchConclusion{State: DispatchNotLaunched, ControllerObservation: launchObservation(observation)}
}

func unreported(observation string) DispatchConclusion {
	return DispatchConclusion{State: DispatchLaunchedUnreported, ControllerObservation: launchObservation(observation)}
}

// boundedMachineSentence keeps at most the bound the registry holds and drops
// what a terminal or a view could read as structure rather than as text. It
// never rewrites a word: a sentence the product did not write is quoted, not
// rephrased.
func boundedMachineSentence(raw []byte, maximum int) string {
	if len(raw) > maximum {
		raw = raw[:maximum]
	}
	cleaned := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' {
			return ' '
		}
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, string(raw))
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if len(cleaned) > maximum {
		cleaned = cleaned[:maximum]
	}
	return cleaned
}

// observation holds this Controller's own sentences to the bound the registry
// validates, so a sentence added later cannot make a legitimate conclusion
// unwritable.
func launchObservation(sentence string) string {
	if len(sentence) > maxDispatchObservationBytes {
		return sentence[:maxDispatchObservationBytes]
	}
	return sentence
}
