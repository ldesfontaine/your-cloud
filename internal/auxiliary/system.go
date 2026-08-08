package auxiliary

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

const (
	// commandTimeout bounds every external command. An Auxiliary is a one-shot
	// process launched by a forced command: it may fail, and it may refuse, but
	// it may not hang holding the anti-replay lock of its machine.
	commandTimeout = 90 * time.Second
	// pullTimeout is longer because it is the one step that talks to a registry.
	pullTimeout = 300 * time.Second

	// probeAttempts and probeInterval bound the local verification. A service
	// that never answers within this window is a controlled failure, not a
	// slower success.
	probeAttempts = 15
	probeInterval = 1 * time.Second
	probeTimeout  = 5 * time.Second

	// unitDirectoryMode and unitFileMode keep the sheet readable by the account
	// that runs the probe and writable by root alone: the account may run what
	// the sheet describes and may never describe what it runs.
	unitDirectoryMode = 0o755
	unitFileMode      = 0o644

	// lingerReadyTimeout and lingerReadyPollInterval bound the wait between
	// loginctl's answer and logind actually creating the account's runtime
	// directory. The wait exists because the race was observed in the LAB;
	// the bound exists because an Auxiliary may not hang.
	lingerReadyTimeout      = 15 * time.Second
	lingerReadyPollInterval = 200 * time.Millisecond

	// linkKeyDirectoryMode and linkKeyFileMode are how this machine's own passage
	// key is held, and the second of them is the one place this implementation
	// departs from the letter of the contract.
	//
	// The contract says root-owned `0600`. A key at `0600` cannot be read by
	// systemd-networkd, which runs as the unprivileged `systemd-network` account
	// and is what holds the interface across a reboot — so a key nobody but root
	// could read would be a passage that never comes up. What is written instead
	// is root-owned `0640` with that account's own group, which is the narrowest
	// arrangement that still lets exactly one further identity read it: the one
	// this product asked to hold the interface. No human account, no service
	// account of this product and no container is in that group.
	//
	// A machine with no such group keeps `0600`. Nothing is silently widened
	// there: the interface will fail to appear and the preparation says so, which
	// is a named failure rather than a key relaxed to make an error go away.
	linkKeyDirectoryMode = 0o750
	linkKeyFileMode      = 0o640
	linkKeyStrictMode    = 0o600

	// networkAccount is the unprivileged identity systemd-networkd runs as, and
	// therefore the one identity beside root that may read the key.
	networkAccount = "systemd-network"

	// interfaceUpFlag is the bit /sys reports for an interface that is up. The
	// state is read from the kernel's own file rather than from a tool's word for
	// it, for the same reason the unified cgroup hierarchy is.
	interfaceUpFlag = 0x1
)

// SystemExecutor is the real effects of this package on a real machine.
//
// Every command below is an argument vector with a fixed program and fixed
// flags. Nothing is interpolated into a string, nothing is passed to a shell,
// and the environment is replaced rather than inherited, so that neither the
// caller's environment nor a plan can decide which binary runs or what it reads.
type SystemExecutor struct{}

// Capabilities observes the host and the probe account, and changes neither.
func (executor SystemExecutor) Capabilities(account string) (Capabilities, error) {
	capabilities := Capabilities{}
	if info, err := os.Stat("/run/systemd/system"); err == nil && info.IsDir() {
		capabilities.Systemd = true
	}
	// The unified hierarchy is read from the file that only exists under cgroup
	// v2, rather than from a version reported by a tool: the question is what
	// the kernel mounted, not what a package believes.
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		capabilities.UnifiedCgroupHierarchy = true
	}
	if _, err := exec.LookPath("podman"); err == nil {
		capabilities.PodmanPresent = true
	}
	if _, err := user.Lookup(account); err != nil {
		return capabilities, nil
	}
	capabilities.AccountPresent = true
	if capabilities.PodmanPresent {
		output, err := executor.runAs(account, commandTimeout, "podman", "info", "--format", "{{.Host.Security.Rootless}}")
		capabilities.RootlessPodman = err == nil && strings.TrimSpace(output) == "true"
	}
	return capabilities, nil
}

// CreateProbeAccount creates a locked system account with its own group, its own
// home, no login shell, and the subordinate identifier ranges a rootless engine
// maps containers into.
//
// The ranges are allocated here explicitly because useradd does not do it for
// system accounts: shadow reserves automatic allocation for ordinary users, and
// an account without ranges runs an engine that can map nothing beyond its own
// identifier — proven blocking in the LAB before this allocation was written.
//
// Every value below the fixed flags comes from the profile's placement, and none
// of them from a plan: one managed service, one account, one home, and one
// comment that says which service owns the identity.
func (executor SystemExecutor) CreateProbeAccount(account, home, comment string) error {
	if _, err := executor.run(commandTimeout, "useradd",
		"--system",
		"--user-group",
		"--home-dir", home,
		"--create-home",
		"--shell", "/usr/sbin/nologin",
		"--comment", comment,
		account,
	); err != nil {
		return err
	}
	start, err := nextSubordinateRangeStart("/etc/subuid", "/etc/subgid")
	if err != nil {
		return err
	}
	span := fmt.Sprintf("%d-%d", start, start+subordinateRangeSize-1)
	_, err = executor.run(commandTimeout, "usermod",
		"--add-subuids", span,
		"--add-subgids", span,
		account,
	)
	return err
}

const (
	// subordinateRangeSize is the conventional 16-bit range a rootless engine
	// expects; shadow allocates the same span for ordinary users.
	subordinateRangeSize = 65536
	// subordinateRangeFloor is where allocation starts on a machine whose
	// files name no range yet, matching shadow's SUB_UID_MIN default.
	subordinateRangeFloor = 100000
)

// nextSubordinateRangeStart reads the machine's own allocation files and
// answers the first identifier above every range they already name.
//
// The files are the authority, not a counter of this product: whoever
// allocated before — shadow for an ordinary user, an administrator by hand —
// their ranges are what a new one must not overlap.
func nextSubordinateRangeStart(paths ...string) (uint64, error) {
	var start uint64 = subordinateRangeFloor
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, fmt.Errorf("read %s: %w", path, err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Split(strings.TrimSpace(line), ":")
			if len(fields) != 3 {
				continue
			}
			first, firstErr := strconv.ParseUint(fields[1], 10, 64)
			count, countErr := strconv.ParseUint(fields[2], 10, 64)
			if firstErr != nil || countErr != nil {
				continue
			}
			if end := first + count; end > start {
				start = end
			}
		}
	}
	return start, nil
}

// EnableLinger keeps that account's systemd user manager running without a
// session, which is what carries an approved state across a reboot.
//
// loginctl answers before logind has created the account's runtime directory,
// and everything that runs as the account next — the engine, the user unit
// manager — needs that directory to exist. Returning early would hand the
// caller a linger that is enabled and unusable, so this waits, bounded, for
// the state it announced; a machine that never produces it is named instead
// of retried forever.
func (executor SystemExecutor) EnableLinger(account string) error {
	if _, err := executor.run(commandTimeout, "loginctl", "enable-linger", account); err != nil {
		return err
	}
	entry, err := user.Lookup(account)
	if err != nil {
		return fmt.Errorf("the account %s does not exist on this machine", account)
	}
	runtimeDirectory := "/run/user/" + entry.Uid
	deadline := time.Now().Add(lingerReadyTimeout)
	for {
		if info, statErr := os.Stat(runtimeDirectory); statErr == nil && info.IsDir() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("linger is enabled for %s but %s never appeared within %s",
				account, runtimeDirectory, lingerReadyTimeout)
		}
		time.Sleep(lingerReadyPollInterval)
	}
}

// ReadUnitFile reads the sheet, and reports its absence as an answer.
func (executor SystemExecutor) ReadUnitFile(path string) ([]byte, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

// WriteUnitFile replaces the sheet atomically and root-owned.
//
// The temporary file is synchronised before the rename and the directory after
// it, the same discipline the anti-replay state is written with: a machine that
// loses power at any instant comes back holding either the previous sheet or the
// new one, never a truncated file describing half a service.
func (executor SystemExecutor) WriteUnitFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, unitDirectoryMode); err != nil {
		return fmt.Errorf("create the Quadlet directory: %w", err)
	}
	temporaryPath := path + ".tmp"
	if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear the previous temporary sheet: %w", err)
	}
	temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, unitFileMode)
	if err != nil {
		return fmt.Errorf("create the temporary sheet: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("write the temporary sheet: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("synchronise the temporary sheet: %w", err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("close the temporary sheet: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("replace the Quadlet sheet: %w", err)
	}
	return syncDirectory(directory)
}

// RemoveUnitFile removes the sheet and is content with it being absent.
func (executor SystemExecutor) RemoveUnitFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// EnsureEntrypointDirectories creates the three root-owned directories the
// entrypoint's sheet mounts read-only.
//
// The mode is the one the sheets already use: writable by root and readable by
// everyone, which is what a rootless container needs in order to read a bind
// mount as its own account while never being able to write it. The list is a
// constant of this package and no caller supplies a path.
func (executor SystemExecutor) EnsureEntrypointDirectories() error {
	for _, directory := range []string{
		entrypointRoot,
		entrypointFragmentDirectory,
		entrypointCertificateDirectory,
	} {
		if err := os.MkdirAll(directory, unitDirectoryMode); err != nil {
			return fmt.Errorf("create %s: %w", directory, err)
		}
	}
	return nil
}

// ListRouteFragments names the fragments the entrypoint currently serves.
//
// An absent directory is an answer and not a failure: a machine that never held
// an entrypoint publishes no route. Only the file names travel back, sorted so
// that a refusal names the same routes in the same order on every run, and no
// content of a fragment ever leaves this function.
func (executor SystemExecutor) ListRouteFragments() ([]string, error) {
	entries, err := os.ReadDir(entrypointFragmentDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fragments := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), routeFragmentSuffix) {
			continue
		}
		fragments = append(fragments, entry.Name())
	}
	sort.Strings(fragments)
	return fragments, nil
}

// HostPortsPolicy reads the policy file, and reports its absence as an answer.
func (executor SystemExecutor) HostPortsPolicy() ([]byte, bool, error) {
	return executor.ReadUnitFile(hostPortsPolicyPath)
}

// WriteHostPortsPolicy persists the policy and applies it immediately.
//
// The two halves are one effect on purpose. A file under /etc/sysctl.d alone
// would only take effect at the next boot, so a machine that had just approved
// an entrypoint would hold a policy it was not yet running under; applying alone
// would not survive a reboot, and the palier's own proof requires that a restart
// brings everything back without an action. The application is `sysctl --system`
// with no argument derived from anything: it re-reads the machine's own files,
// which is what makes the running kernel agree with what is on disk rather than
// with what this process believed.
func (executor SystemExecutor) WriteHostPortsPolicy(content []byte) error {
	if err := executor.WriteUnitFile(hostPortsPolicyPath, content); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, "sysctl", "--system")
	return err
}

// RemoveHostPortsPolicy removes the policy file and puts this machine back under
// whatever remains, in three steps whose order is the whole of the argument.
func (executor SystemExecutor) RemoveHostPortsPolicy() error {
	if err := executor.RemoveUnitFile(hostPortsPolicyPath); err != nil {
		return err
	}
	// `sysctl` has no "forget this setting", so removing the file alone would
	// leave the relaxation running until the next reboot: the setting is put back
	// to the kernel's own default by name.
	if _, err := executor.run(commandTimeout, "sysctl", "--write",
		"net.ipv4.ip_unprivileged_port_start="+strconv.Itoa(defaultUnprivilegedPortStart)); err != nil {
		return err
	}
	// And the machine's remaining files are read last rather than first, so that
	// another administrator's policy, if this machine carries one, re-asserts
	// itself over that default instead of being overwritten by it. What this
	// product takes away is exactly what this product put there.
	_, err := executor.run(commandTimeout, "sysctl", "--system")
	return err
}

// defaultUnprivilegedPortStart is the value a Linux kernel carries when nothing
// has raised it, and the one a removed entrypoint puts back.
const defaultUnprivilegedPortStart = 1024

// ReloadUserUnits makes the account's own systemd read its sheets again.
func (executor SystemExecutor) ReloadUserUnits(account string) error {
	_, err := executor.runAs(account, commandTimeout, "systemctl", "--user", "daemon-reload")
	return err
}

// StartService starts the service Quadlet generated from the sheet.
func (executor SystemExecutor) StartService(account, service string) error {
	_, err := executor.runAs(account, commandTimeout, "systemctl", "--user", "start", service)
	return err
}

// StopService stops it.
func (executor SystemExecutor) StopService(account, service string) error {
	_, err := executor.runAs(account, commandTimeout, "systemctl", "--user", "stop", service)
	return err
}

// ServiceActive reports whether the service runs right now.
//
// A non-zero exit is the documented way systemd answers "not active", so the
// answer is read from what it printed rather than from its status. Anything it
// did not print as a state — an unreachable manager, a runuser that failed — is
// an error and never a quiet "no", because a machine that cannot be asked has
// not answered.
func (executor SystemExecutor) ServiceActive(account, service string) (bool, error) {
	if _, err := user.Lookup(account); err != nil {
		return false, nil
	}
	output, err := executor.runAs(account, commandTimeout, "systemctl", "--user", "is-active", service)
	state := strings.TrimSpace(output)
	if state == "active" {
		return true, nil
	}
	if _, known := inactiveStates[state]; known {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return false, fmt.Errorf("systemd answered %q for %s", state, service)
}

// inactiveStates is the closed list of answers systemd gives for a service that
// is not running, including the one it gives for a service it has never heard
// of. A state outside this list is not read as "not running".
var inactiveStates = map[string]struct{}{
	"inactive":     {},
	"failed":       {},
	"deactivating": {},
	"activating":   {},
	"reloading":    {},
	"unknown":      {},
}

// PullImage fetches exactly the pinned reference.
func (executor SystemExecutor) PullImage(account, reference string) error {
	_, err := executor.runAs(account, pullTimeout, "podman", "pull", reference)
	return err
}

// RemoveImage leaves no image behind, and does not object to it being gone.
func (executor SystemExecutor) RemoveImage(account, reference string) error {
	if _, err := user.Lookup(account); err != nil {
		return nil
	}
	_, err := executor.runAs(account, commandTimeout, "podman", "rmi", "--ignore", reference)
	return err
}

// ContainerImage reports the reference the running container was created from,
// and an empty string when there is no such container.
func (executor SystemExecutor) ContainerImage(account, container string) (string, error) {
	if _, err := user.Lookup(account); err != nil {
		return "", nil
	}
	output, err := executor.runAs(account, commandTimeout,
		"podman", "container", "inspect", "--format", "{{.ImageName}}", container)
	if err != nil {
		// An absent container is an answer; an engine that could not be asked is
		// not, and is never reported as an absence. The engine names the absence
		// on its error stream, which runAs carries inside the error, so the
		// error text is what holds the answer — proven in the LAB when reading
		// it from standard output alone turned every absence into a failure.
		if strings.Contains(strings.ToLower(err.Error()), "no such container") {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// ProbeAnswers performs the local verification, bounded in attempts and in time.
//
// The address is the loopback constant of the contract and never a value from a
// plan, and the request is refused any redirect: what is being proven is that
// this machine answers on this port, not that something somewhere does.
//
// What is asserted about the answer is deliberately the least that still
// distinguishes the approved service from anything else listening: the status,
// always, and the media type where the profile asks for one. The body is read
// only far enough to be discarded — no profile of these paliers describes its
// content, so no verification here may claim anything about it.
func (executor SystemExecutor) ProbeAnswers(port int, expectedContentType string) error {
	client := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	address := "http://" + net.JoinHostPort(loopbackAddress, strconv.Itoa(port)) + "/"
	var last error
	for attempt := 0; attempt < probeAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(probeInterval)
		}
		response, err := client.Get(address)
		if err != nil {
			last = err
			continue
		}
		contentType := response.Header.Get("Content-Type")
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			last = fmt.Errorf("the service answered %d", response.StatusCode)
			continue
		}
		if expectedContentType != "" && !strings.HasPrefix(contentType, expectedContentType) {
			last = fmt.Errorf("the service answered 200 with content type %q rather than %q",
				contentType, expectedContentType)
			continue
		}
		return nil
	}
	if last == nil {
		last = errors.New("the service never answered")
	}
	return last
}

// EntrypointAnswers performs the local verification of the public entrypoint,
// bounded in attempts and in time, and proves the one invariant that depends on
// no route at all.
//
// Two constats, both from this machine and both about a name nobody declared:
//
//  1. the secure port answers, and answers the entry's own generic refusal. The
//     Host of the request is the loopback address, which no fragment can ever
//     declare — the plan validation refuses a route host that is not a name — so
//     an answer that was not a refusal would mean a default router exists, which
//     is exactly what this contract forbids;
//  2. the clear port answers a permanent redirection towards https, and nothing
//     else. A redirect that is followed proves nothing, so it is read rather
//     than followed.
//
// Certificate verification is skipped because there is nothing to verify: this
// runs before any name is declared, so the certificate the entry presents is its
// own, and what is being proven is what the entry does, not what it presents.
func (executor SystemExecutor) EntrypointAnswers() error {
	secure := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// #nosec G402 -- the entry presents its own certificate here: this
			// verification runs before any name is declared, and what it proves is
			// the entry's conduct rather than a chain of trust. The palier's proof
			// of TLS is taken from outside the machine against a pinned authority.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	clear := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	secureAddress := "https://" + net.JoinHostPort(loopbackAddress, strconv.Itoa(entrypointSecurePort)) + "/"
	clearAddress := "http://" + net.JoinHostPort(loopbackAddress, strconv.Itoa(entrypointClearPort)) + "/"

	var last error
	for attempt := 0; attempt < probeAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(probeInterval)
		}
		if err := refusesUndeclaredNames(secure, secureAddress); err != nil {
			last = err
			continue
		}
		if err := redirectsToTheSecurePort(clear, clearAddress); err != nil {
			last = err
			continue
		}
		return nil
	}
	if last == nil {
		last = errors.New("the entrypoint never answered")
	}
	return last
}

// refusesUndeclaredNames is the first half of the entry's invariant.
func refusesUndeclaredNames(client *http.Client, address string) error {
	response, err := client.Get(address)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		return fmt.Errorf(
			"the entrypoint answered %d to a name no route declares, rather than its generic refusal",
			response.StatusCode,
		)
	}
	return nil
}

// redirectsToTheSecurePort is the second half.
func redirectsToTheSecurePort(client *http.Client, address string) error {
	response, err := client.Get(address)
	if err != nil {
		return err
	}
	location := response.Header.Get("Location")
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode != http.StatusPermanentRedirect && response.StatusCode != http.StatusMovedPermanently {
		return fmt.Errorf("the clear port answered %d rather than a permanent redirection", response.StatusCode)
	}
	if !strings.HasPrefix(location, "https://") {
		return fmt.Errorf("the clear port redirected somewhere that is not https")
	}
	return nil
}

// RouteAnswers performs the local verification of one published route, bounded
// in attempts and in time.
//
// The declared name travels twice — once as the TLS server name, so the entry
// selects the router the way a real client makes it select one, and once as the
// Host header — while the connection itself is made to this machine's loopback
// and nowhere else. What is required of the answer is the status and the two
// isolation headers of the profile, which are the two the palier's proof
// constats from outside; the body is read only far enough to be discarded,
// because no plan describes it.
//
// The retry window is what absorbs the entry's own file watch: the fragment is
// on disk before this runs, and the entry picks it up shortly after.
func (executor SystemExecutor) RouteAnswers(routeHost string) error {
	return servesDeclaredName(routeHost, func(response *http.Response) error {
		opener := response.Header.Get("Cross-Origin-Opener-Policy")
		embedder := response.Header.Get("Cross-Origin-Embedder-Policy")
		if opener != isolationOpenerPolicy || embedder != isolationEmbedderPolicy {
			return fmt.Errorf(
				"the answer carried the isolation headers %q and %q rather than %q and %q",
				opener, embedder, isolationOpenerPolicy, isolationEmbedderPolicy)
		}
		return nil
	})
}

// LinkRouteAnswers performs the local verification of one name the passage
// carries, through the very request a client makes and therefore through the
// tunnel itself.
//
// It asks of the answer the status alone. The two isolation headers are the
// public profile's and a link route declares none, so requiring them here would
// refuse every correct publication; and what a vault answers a plain request
// with is described by no plan of this palier, so nothing beyond the status is
// claimed. What the status proves is the whole chain the contract cares about:
// the entry took the fragment, the junction let the approved port through, and
// the service on the other machine answered.
func (executor SystemExecutor) LinkRouteAnswers(routeHost string) error {
	return servesDeclaredName(routeHost, func(*http.Response) error { return nil })
}

// servesDeclaredName is the one bounded request both verifications above make,
// and the one place either of them reaches the network.
//
// The declared name travels twice — once as the TLS server name, so the entry
// selects the router the way a real client makes it select one, and once as the
// Host header — while the connection itself is made to this machine's loopback
// and nowhere else. The status is required of every answer here, because a name
// that is not served is not a published route whichever kind it is; what a kind
// requires beyond it is the one argument this function takes. The body is read
// only far enough to be discarded, because no plan describes it.
func servesDeclaredName(routeHost string, required func(*http.Response) error) error {
	client := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// #nosec G402 -- see EntrypointAnswers: the certificate of a declared
			// name is signed by an authority this palier's proof creates, not by
			// anything this Auxiliary could hold. What is proven here is that the
			// fragment took effect and that the backend is reached.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: routeHost},
		},
	}
	address := "https://" + net.JoinHostPort(loopbackAddress, strconv.Itoa(entrypointSecurePort)) + "/"
	var last error
	for attempt := 0; attempt < probeAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(probeInterval)
		}
		request, err := http.NewRequest(http.MethodGet, address, nil)
		if err != nil {
			return err
		}
		request.Host = routeHost
		response, err := client.Do(request)
		if err != nil {
			last = err
			continue
		}
		status := response.StatusCode
		failed := required(response)
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if status != http.StatusOK {
			last = fmt.Errorf("the entrypoint answered %d for this name", status)
			continue
		}
		if failed != nil {
			last = failed
			continue
		}
		return nil
	}
	if last == nil {
		last = errors.New("the entrypoint never served this name")
	}
	return last
}

// LinkPublicKey reports the public half of this machine's own passage key.
//
// It is derived from the private half rather than kept beside it, so the two can
// never drift apart and this machine holds exactly one file it must protect. The
// private bytes exist inside this function and nowhere else: they are read, used
// to compute the public half, and never returned, logged or carried into any
// value a caller can reach.
//
// An absent key is an answer and not a failure. A key that is there and is not a
// key is a failure and never a quiet absence, because a machine that cannot say
// what it holds has not answered.
func (executor SystemExecutor) LinkPublicKey() (string, bool, error) {
	encoded, err := os.ReadFile(linkPrivateKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(private) != plan.PeerPublicKeyBytes {
		return "", false, fmt.Errorf("%s does not hold one passage key", linkPrivateKeyPath)
	}
	public, err := publicKeyOf(private)
	if err != nil {
		return "", false, err
	}
	return public, true, nil
}

// GenerateLinkKey generates this machine's own passage key and returns only its
// public half.
//
// Three decisions are carried here and each of them is owed an explanation:
//
//   - the key is generated with the standard library's own X25519 rather than by
//     shelling out to `wg`, because it is one call over an algorithm the standard
//     library already implements and because a passage would otherwise refuse to
//     be prepared on a machine that has the WireGuard tools uninstalled — which
//     the kernel does not require;
//   - the scalar is clamped before it is written, so the file holds exactly the
//     bytes `wg genkey` would have written. The kernel clamps again on load and
//     the public half is computed from the clamped scalar either way, so this
//     changes no value; it removes the question of whether two implementations
//     wrote the same key differently;
//   - the file is created exclusively. A key that already exists is never
//     replaced, whatever a caller asks: replacing a key is a withdrawal followed
//     by a preparation, two plans a human reads, and the refusal is here as well
//     as in the flow above so that no future caller can arrange to skip it.
func (executor SystemExecutor) GenerateLinkKey() (string, error) {
	if err := os.MkdirAll(linkRoot, linkKeyDirectoryMode); err != nil {
		return "", fmt.Errorf("create the passage's root-owned directory: %w", err)
	}
	// The directory carries the same group as the key it holds, because a file
	// a reader may open inside a directory that reader cannot enter is a file
	// nobody reads: the first machine proof failed exactly there, networkd
	// refusing the key with search permission denied on this directory.
	if group, err := user.LookupGroup(networkAccount); err == nil {
		gid, atoiErr := strconv.Atoi(group.Gid)
		if atoiErr != nil {
			return "", fmt.Errorf("read the %s group: %w", networkAccount, atoiErr)
		}
		if err := os.Chown(linkRoot, 0, gid); err != nil {
			return "", fmt.Errorf("give the passage's directory to root and %s: %w", networkAccount, err)
		}
		if err := os.Chmod(linkRoot, linkKeyDirectoryMode); err != nil {
			return "", fmt.Errorf("hold the passage's directory at %#o: %w", linkKeyDirectoryMode, err)
		}
	}
	private := make([]byte, plan.PeerPublicKeyBytes)
	if _, err := rand.Read(private); err != nil {
		return "", fmt.Errorf("draw this machine's own passage key: %w", err)
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	public, err := publicKeyOf(private)
	if err != nil {
		return "", err
	}

	mode := os.FileMode(linkKeyStrictMode)
	group, groupErr := user.LookupGroup(networkAccount)
	if groupErr == nil {
		mode = linkKeyFileMode
	}
	handle, err := os.OpenFile(linkPrivateKeyPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return "", fmt.Errorf("create this machine's own passage key: %w", err)
	}
	if _, err := handle.Write([]byte(base64.StdEncoding.EncodeToString(private) + "\n")); err != nil {
		handle.Close()
		os.Remove(linkPrivateKeyPath)
		return "", fmt.Errorf("write this machine's own passage key: %w", err)
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		os.Remove(linkPrivateKeyPath)
		return "", fmt.Errorf("synchronise this machine's own passage key: %w", err)
	}
	if err := handle.Close(); err != nil {
		os.Remove(linkPrivateKeyPath)
		return "", fmt.Errorf("close this machine's own passage key: %w", err)
	}
	// The mode requested at creation is subject to the process umask, so it is
	// stated again rather than assumed, and the group is set only where it exists.
	if err := os.Chmod(linkPrivateKeyPath, mode); err != nil {
		os.Remove(linkPrivateKeyPath)
		return "", fmt.Errorf("hold this machine's own passage key at %#o: %w", mode, err)
	}
	if groupErr == nil {
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			os.Remove(linkPrivateKeyPath)
			return "", fmt.Errorf("read the %s group: %w", networkAccount, err)
		}
		if err := os.Chown(linkPrivateKeyPath, 0, gid); err != nil {
			os.Remove(linkPrivateKeyPath)
			return "", fmt.Errorf("give this machine's own passage key to root and %s: %w", networkAccount, err)
		}
	}
	if err := syncDirectory(linkRoot); err != nil {
		return "", err
	}
	return public, nil
}

// publicKeyOf computes the public half of one X25519 scalar.
//
// It takes the private bytes and returns a string, and that asymmetry is the
// point: nothing in this package can go the other way, and the one value that
// leaves here is the one the contract lets travel.
func publicKeyOf(private []byte) (string, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return "", fmt.Errorf("read this machine's own passage key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// RemoveLinkKey takes the private key away, and does not object to it being
// gone.
func (executor SystemExecutor) RemoveLinkKey() error {
	if err := os.Remove(linkPrivateKeyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(linkRoot)
}

// LinkInterfaceActive reports whether the closed interface of the passage exists
// on this machine and is up.
//
// Both facts are read from the kernel's own files rather than from a tool's
// summary of them: an absent directory is an absent interface, and the flags
// file is what the kernel itself says about the one that is there.
func (executor SystemExecutor) LinkInterfaceActive() (bool, error) {
	flags, err := os.ReadFile("/sys/class/net/" + LinkInterfaceName + "/flags")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(flags)), "0x"), 16, 64)
	if err != nil {
		return false, fmt.Errorf("read the state of %s: %w", LinkInterfaceName, err)
	}
	return value&interfaceUpFlag != 0, nil
}

// RemoveLinkInterface takes the interface away, and does not object to it being
// gone.
//
// Removing the two files that describe it is not enough: a network manager that
// has forgotten a description does not take down the device it already created,
// so a withdrawal that only removed files would leave a tunnel standing that no
// plan describes any more.
func (executor SystemExecutor) RemoveLinkInterface() error {
	if _, err := os.Stat("/sys/class/net/" + LinkInterfaceName); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_, err := executor.run(commandTimeout, "ip", "link", "delete", LinkInterfaceName)
	return err
}

// LinkRules reads the bounding table this machine holds on disk, and reports its
// absence as an answer.
func (executor SystemExecutor) LinkRules() ([]byte, bool, error) {
	return executor.ReadUnitFile(linkRulesPath)
}

// WriteLinkRules persists the bounding table and loads it into the kernel.
//
// The two halves are one effect for the reason the host ports policy is: a file
// alone would only bound the passage at the next boot, so a machine that had
// just joined a peer would be carrying a passage it had not yet bounded, and a
// table loaded alone would be gone at that boot. The file is loaded by its own
// path rather than by re-reading anything else, and what it contains makes
// loading it twice mean the same as loading it once.
func (executor SystemExecutor) WriteLinkRules(content []byte) error {
	if err := executor.WriteUnitFile(linkRulesPath, content); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, nftProgram, "--file", linkRulesPath)
	return err
}

// RemoveLinkRules takes the bounding table out of the kernel and then off the
// disk, and names exactly one table while doing it.
//
// The table is added before it is deleted, which is the idiom the file itself
// opens with and is here for the same reason: adding is what makes the deletion
// succeed whether or not this machine was holding the table, and an added table
// with no chain in it filters nothing at all, so the two calls together have no
// instant in which this machine behaves differently than it would have. Every
// other table this machine carries — an administrator's own firewall above all —
// is never named and therefore never touched.
func (executor SystemExecutor) RemoveLinkRules() error {
	if _, err := executor.run(commandTimeout, nftProgram,
		"add", "table", linkTableFamily, linkTableName); err != nil {
		return err
	}
	if _, err := executor.run(commandTimeout, nftProgram,
		"delete", "table", linkTableFamily, linkTableName); err != nil {
		return err
	}
	return executor.RemoveUnitFile(linkRulesPath)
}

// LinkLoopbackPolicy reads the one host relaxation a junction declares.
func (executor SystemExecutor) LinkLoopbackPolicy() ([]byte, bool, error) {
	return executor.ReadUnitFile(linkLoopbackPolicyPath)
}

// WriteLinkLoopbackPolicy persists that relaxation and applies it immediately.
//
// It applies exactly the file it just wrote rather than re-reading everything
// this machine holds under /etc/sysctl.d, which is where it departs from the
// entrypoint's own policy: the setting names an interface, so it must fail
// loudly on a machine where that interface is not there, and an unrelated file
// somebody else owns has no business deciding whether a junction succeeded. The
// same command is what the boot unit runs, so a machine coming back from a
// reboot passes through this exact state by this exact path.
func (executor SystemExecutor) WriteLinkLoopbackPolicy(content []byte) error {
	if err := executor.WriteUnitFile(linkLoopbackPolicyPath, content); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, sysctlProgram, "--quiet", "--load", linkLoopbackPolicyPath)
	return err
}

// RemoveLinkLoopbackPolicy removes the file and puts the kernel back to the
// value it carries when nothing has raised it.
//
// The setting is put back by name because sysctl has no "forget this line", and
// unknown keys are ignored because the interface the key names may already be
// gone by the time a passage is dismantled — an absent interface is an answer
// here and not a failure. Nothing else of this machine's policy is re-read: what
// this product takes away is exactly what this product put there.
func (executor SystemExecutor) RemoveLinkLoopbackPolicy() error {
	if err := executor.RemoveUnitFile(linkLoopbackPolicyPath); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, sysctlProgram, "--ignore", "--write",
		linkRouteLocalnetKey+"="+strconv.Itoa(defaultRouteLocalnet))
	return err
}

// defaultRouteLocalnet is the value a Linux interface carries when nothing has
// raised it, and the one a dismantled junction puts back.
const defaultRouteLocalnet = 0

// EnableLinkRulesAtBoot makes the oneshot unit run at the next boot, and not
// now.
//
// The manager is made to read the file first, because it was written moments
// ago. What is deliberately not done is starting the unit: the junction has
// already applied both files itself, and running them again would be a second
// application of a state this machine already holds.
func (executor SystemExecutor) EnableLinkRulesAtBoot() error {
	if _, err := executor.run(commandTimeout, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, "systemctl", "enable", linkRulesUnitName)
	return err
}

// DisableLinkRulesAtBoot takes that away, while the unit file is still there.
//
// The order is not a detail: a manager asked to disable a unit whose file has
// already been removed cannot read the [Install] section that says what to
// remove, so the enablement is undone first and the file goes afterwards.
func (executor SystemExecutor) DisableLinkRulesAtBoot() error {
	if _, err := executor.run(commandTimeout, "systemctl", "disable", linkRulesUnitName); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, "systemctl", "daemon-reload")
	return err
}

// EnableNetworkManagement makes systemd-networkd run now and after a reboot.
//
// It is one command rather than two because the two halves are one effect, for
// the reason the host ports policy is: enabling without starting would leave a
// machine that has approved a passage holding no interface until it reboots, and
// starting without enabling would lose the passage at the next boot — which the
// palier's proof requires to survive.
//
// What it does not do is take anything away from whatever already configures
// this machine's real interfaces. networkd manages exactly the devices its own
// [Match] sections name, and the only file this product writes matches one
// interface by its name.
func (executor SystemExecutor) EnableNetworkManagement() error {
	_, err := executor.run(commandTimeout, "systemctl", "enable", "--now", "systemd-networkd")
	return err
}

// ReloadNetworkConfiguration makes the network manager read the passage's two
// files again.
//
// The reload is what creates the interface from a description that did not exist
// before. The reconfiguration that follows is what makes an *edited* description
// take effect on an interface that is already there — a peer attached or
// detached above all — and it is skipped while there is no such interface,
// because reconfiguring a device that does not exist is an error rather than an
// answer.
func (executor SystemExecutor) ReloadNetworkConfiguration() error {
	if _, err := executor.run(commandTimeout, "networkctl", "reload"); err != nil {
		return err
	}
	if _, err := os.Stat("/sys/class/net/" + LinkInterfaceName); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_, err := executor.run(commandTimeout, "networkctl", "reconfigure", LinkInterfaceName)
	return err
}

const (
	// serviceDataMode is how the one durable write path of this product is held:
	// the service's own account, and nobody else at all. It is narrower than the
	// sheets deliberately — a sheet describes a service and may be read, the data
	// of a vault may not.
	serviceDataMode = 0o700
	// serviceArchiveDirectoryMode and serviceArchiveFileMode hold the backups
	// under root alone. The account whose data they archive is not among the
	// identities that may read them: a container escape reaching that account must
	// not reach the history of the data it escaped from.
	serviceArchiveDirectoryMode = 0o700
	serviceArchiveFileMode      = 0o600

	// serviceSecretDirectoryMode and serviceSecretFileMode hold the values this
	// machine generates under the service's own account and nobody else.
	//
	// The owner is the account rather than root, and it is a necessity rather than
	// a relaxation: the sheet reads them back through EnvironmentFile= and the
	// systemd that reads that line is the account's own user manager, so a value
	// root alone could open would be a service that never starts. What the mode
	// buys is everything else on the machine — no other account, and no other
	// container, can enter the directory or open a value.
	serviceSecretDirectoryMode = 0o700
	serviceSecretFileMode      = 0o600

	// serviceSecretRandomBytes is how much of the kernel's randomness one
	// generated value is, and serviceSecretHexBytes is what it takes to write it.
	// Thirty-two bytes is the length this product already draws for the key of its
	// private passage, and hexadecimal is the alphabet that cannot carry a
	// newline, a quote or anything a shell reads.
	serviceSecretRandomBytes = 32
	serviceSecretHexBytes    = 2 * serviceSecretRandomBytes

	// archiveTimeout bounds the two effects that walk a whole tree. They are
	// longer than an ordinary command because they are proportional to the data,
	// and bounded all the same because an Auxiliary may not hang holding the
	// anti-replay lock of its machine.
	archiveTimeout = 900 * time.Second

	// restoringSuffix and replacedSuffix are the two temporary names a restore
	// passes through, so that the data directory is replaced by a rename rather
	// than emptied in place: a machine cut in the middle comes back holding either
	// the previous tree or the restored one, and never half of each.
	restoringSuffix = ".restoring"
	replacedSuffix  = ".replaced"
)

// AccountIdentifier reports the numeric identifier one account holds here.
func (executor SystemExecutor) AccountIdentifier(account string) (int, error) {
	entry, err := user.Lookup(account)
	if err != nil {
		return 0, fmt.Errorf("the account %s does not exist on this machine", account)
	}
	identifier, err := strconv.Atoi(entry.Uid)
	if err != nil {
		return 0, fmt.Errorf("the account %s carries an identifier this machine cannot read: %w", account, err)
	}
	return identifier, nil
}

// ServiceDataPresent reports whether the durable data directory is there, and
// reports its absence as an answer.
//
// A path that exists and is not a directory is not an answer but a machine this
// operation does not run on: it is named rather than replaced, because replacing
// it would destroy something no plan describes.
func (executor SystemExecutor) ServiceDataPresent(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("%s exists and is not a directory: this machine is not touched", path)
	}
	return true, nil
}

// EnsureServiceData creates the directories a data-bearing placement owns, with
// the two owners the seam's contract fixes.
//
// The data side is walked in the order it was given, parents first, so that a
// third door's durable root exists before the volume subtrees under it: a
// MkdirAll that created a parent on the way would leave that parent with a mode
// and an owner nobody stated.
func (executor SystemExecutor) EnsureServiceData(
	account string,
	dataDirectories []string,
	snapshotDirectory string,
) error {
	entry, err := user.Lookup(account)
	if err != nil {
		return fmt.Errorf("the account %s does not exist on this machine", account)
	}
	identifier, err := strconv.Atoi(entry.Uid)
	if err != nil {
		return fmt.Errorf("the account %s carries an identifier this machine cannot read: %w", account, err)
	}
	group, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return fmt.Errorf("the account %s carries a group this machine cannot read: %w", account, err)
	}
	for _, dataDirectory := range dataDirectories {
		if err := os.MkdirAll(dataDirectory, serviceDataMode); err != nil {
			return fmt.Errorf("create the service data directory: %w", err)
		}
		// The mode and the owner are set rather than assumed, because MkdirAll leaves
		// an existing directory exactly as it found it: a data directory the engine
		// had created before this seam existed is put back under its account here
		// rather than left as a service that cannot write.
		if err := os.Chmod(dataDirectory, serviceDataMode); err != nil {
			return fmt.Errorf("hold the service data directory closed: %w", err)
		}
		if err := os.Chown(dataDirectory, identifier, group); err != nil {
			return fmt.Errorf("give the service data directory to its own account: %w", err)
		}
	}
	if err := os.MkdirAll(snapshotDirectory, serviceArchiveDirectoryMode); err != nil {
		return fmt.Errorf("create the service archive directory: %w", err)
	}
	if err := os.Chmod(snapshotDirectory, serviceArchiveDirectoryMode); err != nil {
		return fmt.Errorf("hold the service archive directory closed: %w", err)
	}
	return nil
}

// ServiceSecretsPresent reports whether a value exists for every declared key and
// whether the environment file the sheet reads names exactly those keys.
//
// Nothing here carries a value out: the values are asked of the file system and
// answered by presence alone, and the environment file is read for the names to
// the left of its separators and never for what is to the right of them. A path
// that exists and is not an ordinary file is answered as absent rather than as a
// failure — what the caller does with that answer is reapply the approved plan,
// and the write below names the case if it really cannot proceed.
func (executor SystemExecutor) ServiceSecretsPresent(
	directory, environmentFile string,
	keys []string,
) (bool, error) {
	for _, key := range keys {
		held, err := regularFilePresent(filepath.Join(directory, key))
		if err != nil || !held {
			return false, err
		}
	}
	content, err := os.ReadFile(environmentFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return declaresExactly(content, keys), nil
}

// declaresExactly reports whether an environment file names one list of keys, in
// that order and with nothing else. Only the name of each line travels out of
// this function; what follows the separator is never looked at.
func declaresExactly(content []byte, keys []string) bool {
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(content) == 0 {
		lines = nil
	}
	if len(lines) != len(keys) {
		return false
	}
	for index, line := range lines {
		name, _, separated := strings.Cut(line, "=")
		if !separated || name != keys[index] {
			return false
		}
	}
	return true
}

func regularFilePresent(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

// EnsureServiceSecrets generates what this machine does not hold, keeps what it
// does, and rewrites the environment file the sheet reads.
//
// Three decisions are carried here and each of them is owed an explanation:
//
//   - a value is thirty-two bytes of the kernel's own randomness rendered as
//     lower-case hexadecimal. The alphabet is the point as much as the length: a
//     value that can only be those sixty-four characters cannot carry a newline
//     into the environment file below, cannot end an environment line early and
//     cannot mean anything to a shell — so a generated value is inert wherever it
//     is read;
//   - the file is created exclusively, exactly as this machine's own passage key
//     is. A value that already exists is never replaced, whatever a revision says
//     and whatever a caller asks: no plan of this product describes the
//     destruction of a secret, so nothing here performs one, and a redeployment
//     therefore finds the values the first deployment generated;
//   - a value this machine did not write is refused rather than used. A file
//     under this directory holding anything but the exact shape above is not
//     something this Auxiliary generated, and writing it into an environment file
//     line by line would let whatever put it there decide what the container's
//     environment says. The refusal names the key and never the content.
func (executor SystemExecutor) EnsureServiceSecrets(
	account, directory, environmentFile string,
	keys []string,
) error {
	entry, err := user.Lookup(account)
	if err != nil {
		return fmt.Errorf("the account %s does not exist on this machine", account)
	}
	identifier, err := strconv.Atoi(entry.Uid)
	if err != nil {
		return fmt.Errorf("the account %s carries an identifier this machine cannot read: %w", account, err)
	}
	group, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return fmt.Errorf("the account %s carries a group this machine cannot read: %w", account, err)
	}
	if err := os.MkdirAll(directory, serviceSecretDirectoryMode); err != nil {
		return fmt.Errorf("create the service secrets directory: %w", err)
	}
	if err := os.Chmod(directory, serviceSecretDirectoryMode); err != nil {
		return fmt.Errorf("hold the service secrets directory closed: %w", err)
	}
	if err := os.Chown(directory, identifier, group); err != nil {
		return fmt.Errorf("give the service secrets directory to its own account: %w", err)
	}

	lines := make([]byte, 0, len(keys)*(serviceSecretHexBytes+len("KEY=\n")))
	for _, key := range keys {
		value, err := executor.ensureServiceSecret(filepath.Join(directory, key), identifier, group)
		if err != nil {
			return fmt.Errorf("hold the generated value of %s: %w", key, err)
		}
		lines = append(lines, (key + "=" + value + "\n")...)
	}
	return writeAccountFile(environmentFile, lines, identifier, group, serviceSecretFileMode)
}

// ensureServiceSecret returns the value one key holds on this machine, generating
// it exactly once and never replacing it.
func (executor SystemExecutor) ensureServiceSecret(path string, identifier, group int) (string, error) {
	handle, err := os.OpenFile(path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, serviceSecretFileMode)
	if errors.Is(err, os.ErrExist) {
		return readServiceSecret(path)
	}
	if err != nil {
		return "", fmt.Errorf("create the generated value: %w", err)
	}
	drawn := make([]byte, serviceSecretRandomBytes)
	if _, err := rand.Read(drawn); err != nil {
		handle.Close()
		os.Remove(path)
		return "", fmt.Errorf("draw the generated value: %w", err)
	}
	value := hex.EncodeToString(drawn)
	if _, err := handle.Write([]byte(value + "\n")); err != nil {
		handle.Close()
		os.Remove(path)
		return "", fmt.Errorf("write the generated value: %w", err)
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		os.Remove(path)
		return "", fmt.Errorf("synchronise the generated value: %w", err)
	}
	if err := handle.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("close the generated value: %w", err)
	}
	// The mode requested at creation is subject to the process umask, so it is
	// stated again rather than assumed.
	if err := os.Chmod(path, serviceSecretFileMode); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("hold the generated value closed: %w", err)
	}
	if err := os.Chown(path, identifier, group); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("give the generated value to its own account: %w", err)
	}
	return value, nil
}

// readServiceSecret reads back one value this machine already held, and refuses
// anything that is not the exact shape this machine writes.
func readServiceSecret(path string) (string, error) {
	held, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the generated value: %w", err)
	}
	value := strings.TrimSuffix(string(held), "\n")
	if len(value) != serviceSecretHexBytes {
		return "", errors.New("this machine holds a value it did not generate for this key")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("this machine holds a value it did not generate for this key")
	}
	return value, nil
}

// writeAccountFile replaces one file the service's own account reads, atomically
// and under that account.
//
// It is the discipline WriteUnitFile follows over another owner, and the owner is
// the whole difference: what is written here is read back by the account's own
// systemd, from a file inside that account's own home, so root-owning it would
// claim a protection the directory above it cannot back.
func writeAccountFile(path string, content []byte, identifier, group int, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporaryPath := path + ".tmp"
	if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear the previous temporary file: %w", err)
	}
	temporary, err := os.OpenFile(temporaryPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return fmt.Errorf("create the temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("write the temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("synchronise the temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("close the temporary file: %w", err)
	}
	if err := os.Chmod(temporaryPath, mode); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("hold the temporary file closed: %w", err)
	}
	if err := os.Chown(temporaryPath, identifier, group); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("give the temporary file to its own account: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("replace the file: %w", err)
	}
	return syncDirectory(directory)
}

// ManagedUserServiceSlugs names the user services this machine holds a sheet for.
//
// The homes of the third door are read rather than a record of this product,
// because there is no such record: what this machine runs is what it holds sheets
// for. A directory whose name is not a well-formed slug of this door, and a home
// without the sheet its own service would be described by, are both answered as
// "not a user service of this machine" — the enumeration reports what is running,
// not what once was.
func (executor SystemExecutor) ManagedUserServiceSlugs() ([]string, error) {
	entries, err := os.ReadDir(userServiceHomeRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	slugs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), UserServiceAccountPrefix) {
			continue
		}
		slug := strings.TrimPrefix(entry.Name(), UserServiceAccountPrefix)
		if servicedefinition.ValidateSlug(slug) != nil {
			continue
		}
		where := userServicePlacementOfSlug(slug)
		if _, err := os.Stat(where.unitPath()); err != nil {
			continue
		}
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs, nil
}

// ServiceArchives names the ordinary slots this machine holds, sorted, and never
// the reserved one.
//
// An absent directory is an answer and not a failure: a machine that never held
// this profile holds no archive. Only the slots travel back — never a path, never
// a size and never a byte of content.
func (executor SystemExecutor) ServiceArchives(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	slots := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), archiveSuffix) {
			continue
		}
		slot := strings.TrimSuffix(entry.Name(), archiveSuffix)
		if slot == plan.ReservedSnapshotSlot {
			continue
		}
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	return slots, nil
}

// ServiceArchivePresent reports whether one named archive is there.
//
// It asks the filesystem for the entry rather than reading the file, unlike every
// other presence question of this package: the files those ask about are sheets a
// human could read on one screen, and an archive is proportional to the data of a
// service. Nothing here opens it, which is also the narrowest way to answer a
// question about a vault's backups.
func (executor SystemExecutor) ServiceArchivePresent(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s is a directory rather than an archive: this machine is not touched", path)
	}
	return true, nil
}

// ArchiveServiceData writes one named archive and refuses to replace one.
func (executor SystemExecutor) ArchiveServiceData(dataDirectory, archivePath string) (Archive, error) {
	if _, err := os.Stat(archivePath); err == nil {
		return Archive{}, fmt.Errorf(
			"an archive already exists at %s: backups of this product are immutable, so nothing was written", archivePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Archive{}, err
	}
	return executor.writeArchive(dataDirectory, archivePath)
}

// writeArchive is what an archiving effect does once the question of replacement
// is settled: one fixed argument vector, into a temporary file beside the target,
// hashed and only then renamed into place.
//
// The temporary file is why an interrupted archiving never leaves a slot holding
// half a tree: what a machine comes back with is either the previous archive or
// the complete new one. The digest is taken over the bytes that were written and
// not over the tree they came from, because what a report names is the archive a
// human can be handed.
func (executor SystemExecutor) writeArchive(dataDirectory, archivePath string) (Archive, error) {
	temporaryPath, archive, err := executor.stageArchive(dataDirectory, archivePath)
	if err != nil {
		return Archive{}, err
	}
	if err := os.Rename(temporaryPath, archivePath); err != nil {
		os.Remove(temporaryPath)
		return Archive{}, fmt.Errorf("place the archive in its slot: %w", err)
	}
	if err := syncDirectory(filepath.Dir(archivePath)); err != nil {
		return Archive{}, err
	}
	return archive, nil
}

// stageArchive writes the data into a temporary file beside the slot it is meant
// for, and hashes it there.
//
// The temporary file is why an interrupted archiving never leaves a slot holding
// half a tree: what a machine comes back with is either the previous archive or
// the complete new one. The digest is taken over the bytes that were written and
// not over the tree they came from, because what a report names is the archive a
// human can be handed.
func (executor SystemExecutor) stageArchive(dataDirectory, archivePath string) (string, Archive, error) {
	if err := os.MkdirAll(filepath.Dir(archivePath), serviceArchiveDirectoryMode); err != nil {
		return "", Archive{}, fmt.Errorf("create the service archive directory: %w", err)
	}
	temporaryPath := archivePath + ".tmp"
	if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", Archive{}, fmt.Errorf("clear the previous temporary archive: %w", err)
	}
	if _, err := executor.run(archiveTimeout, "tar",
		"--create",
		"--gzip",
		"--file", temporaryPath,
		"--directory", dataDirectory,
		".",
	); err != nil {
		os.Remove(temporaryPath)
		return "", Archive{}, err
	}
	if err := os.Chmod(temporaryPath, serviceArchiveFileMode); err != nil {
		os.Remove(temporaryPath)
		return "", Archive{}, fmt.Errorf("hold the archive closed: %w", err)
	}
	digest, err := digestOfFile(temporaryPath)
	if err != nil {
		os.Remove(temporaryPath)
		return "", Archive{}, err
	}
	return temporaryPath, Archive{SHA256: digest, TakenAt: time.Now().UTC()}, nil
}

// digestOfFile is the one digest this package ever takes over a file it wrote.
//
// The bytes are streamed rather than read whole: an archive is proportional to
// the data of a service, and a report may not depend on it fitting in memory.
func digestOfFile(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read the archive back to hash it: %w", err)
	}
	defer handle.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, handle); err != nil {
		return "", fmt.Errorf("hash the archive: %w", err)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// ExchangeServiceData performs a return as one effect, in the one order that
// makes the reserved slot both the state a return preserves and a slot a return
// may name.
//
// The order is the whole of the correctness argument, so it is written once,
// here:
//
//  1. the named archive is *unpacked first*, into a fresh directory beside the
//     data. It is read before anything is written, which is what makes a return
//     naming the reserved slot a swap rather than a loss: written the other way
//     round, the reserved archive would be overwritten by the current state and
//     then unpacked back over it, and the return of a return would restore
//     exactly what it had just replaced;
//  2. the state being replaced is archived, into a temporary file beside the
//     reserved slot, and hashed there;
//  3. the two are put in place by rename — the data first, the reserved archive
//     second — so a machine cut at any instant comes back holding one complete
//     tree and either the previous reserved archive or the new one;
//  4. what was replaced is removed last.
//
// The replacement is a replacement and never a merge: unpacking over the tree
// that is there would leave a service holding rows from two different states with
// nothing saying which.
func (executor SystemExecutor) ExchangeServiceData(archivePath, dataDirectory, reservedPath string) (Archive, error) {
	restoring := dataDirectory + restoringSuffix
	replaced := dataDirectory + replacedSuffix
	for _, leftover := range []string{restoring, replaced} {
		if err := os.RemoveAll(leftover); err != nil {
			return Archive{}, fmt.Errorf("clear what a previous return left at %s: %w", leftover, err)
		}
	}
	if err := os.Mkdir(restoring, serviceDataMode); err != nil {
		return Archive{}, fmt.Errorf("create the directory the archive is unpacked into: %w", err)
	}
	if _, err := executor.run(archiveTimeout, "tar",
		"--extract",
		"--gzip",
		"--same-owner",
		"--preserve-permissions",
		"--file", archivePath,
		"--directory", restoring,
	); err != nil {
		os.RemoveAll(restoring)
		return Archive{}, err
	}
	// The unpacked tree carries the owners the archive recorded, which are the
	// service account's own: the archive was written by root from a tree that
	// account owns, and it is unpacked by root. What is set here is the one thing
	// the archive cannot carry — the directory the mount point itself is.
	if err := os.Chmod(restoring, serviceDataMode); err != nil {
		os.RemoveAll(restoring)
		return Archive{}, fmt.Errorf("hold the restored data closed: %w", err)
	}

	stagedPath, archive, err := executor.stageArchive(dataDirectory, reservedPath)
	if err != nil {
		os.RemoveAll(restoring)
		return Archive{}, err
	}

	if err := os.Rename(dataDirectory, replaced); err != nil && !errors.Is(err, os.ErrNotExist) {
		os.RemoveAll(restoring)
		os.Remove(stagedPath)
		return Archive{}, fmt.Errorf("set the replaced data aside: %w", err)
	}
	if err := os.Rename(restoring, dataDirectory); err != nil {
		os.Remove(stagedPath)
		return Archive{}, fmt.Errorf("put the returned data in place: %w", err)
	}
	if err := os.Rename(stagedPath, reservedPath); err != nil {
		os.Remove(stagedPath)
		return Archive{}, fmt.Errorf("place the archive of the replaced state in its slot: %w", err)
	}
	if err := os.RemoveAll(replaced); err != nil {
		return Archive{}, fmt.Errorf("remove the data the return replaced: %w", err)
	}
	if err := syncDirectory(filepath.Dir(reservedPath)); err != nil {
		return Archive{}, err
	}
	return archive, syncDirectory(filepath.Dir(dataDirectory))
}

// RemoveServiceArchive removes one named archive and is content with it being
// absent.
func (executor SystemExecutor) RemoveServiceArchive(path string) error {
	return executor.RemoveUnitFile(path)
}

// EgressRules reads the confinement table this machine holds on disk, and
// reports its absence as an answer.
func (executor SystemExecutor) EgressRules(path string) ([]byte, bool, error) {
	return executor.ReadUnitFile(path)
}

// WriteEgressRules persists the confinement table and loads it into the kernel,
// for the reason the passage's own bounds are written that way: a file alone
// would only confine the service at the next boot, and a table loaded alone would
// be gone at that boot. What the file contains makes loading it twice mean the
// same as loading it once.
func (executor SystemExecutor) WriteEgressRules(path string, content []byte) error {
	if err := executor.WriteUnitFile(path, content); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, nftProgram, "--file", path)
	return err
}

// RemoveEgressRules takes the confinement table out of the kernel and then off
// the disk, and names exactly one table while doing it.
//
// The table is added before it is deleted, which is the idiom the file itself
// opens with: adding is what makes the deletion succeed whether or not this
// machine was holding the table, and an added table with no chain in it filters
// nothing at all. Every other table this machine carries — the passage's own and
// an administrator's firewall above all — is never named and therefore never
// touched.
func (executor SystemExecutor) RemoveEgressRules(path string) error {
	if _, err := executor.run(commandTimeout, nftProgram,
		"add", "table", egressTableFamily, egressTableName); err != nil {
		return err
	}
	if _, err := executor.run(commandTimeout, nftProgram,
		"delete", "table", egressTableFamily, egressTableName); err != nil {
		return err
	}
	return executor.RemoveUnitFile(path)
}

// EnableEgressRulesAtBoot makes the oneshot unit run at the next boot, and not
// now: the deployment has already applied the table itself.
func (executor SystemExecutor) EnableEgressRulesAtBoot() error {
	if _, err := executor.run(commandTimeout, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, "systemctl", "enable", egressRulesUnitName)
	return err
}

// DisableEgressRulesAtBoot takes that away, while the unit file is still there:
// a manager asked to disable a unit whose file has already been removed cannot
// read the [Install] section that says what to remove.
func (executor SystemExecutor) DisableEgressRulesAtBoot() error {
	if _, err := executor.run(commandTimeout, "systemctl", "disable", egressRulesUnitName); err != nil {
		return err
	}
	_, err := executor.run(commandTimeout, "systemctl", "daemon-reload")
	return err
}

// run executes one fixed argument vector as root, with a replaced environment.
//
// The working directory is fixed rather than inherited: a forced SSH command
// starts wherever the caller's account lives, and what runs here must behave
// identically wherever the Auxiliary was launched from.
//
// Only standard output is returned. A program that answers on stdout while
// warning on stderr has still answered, and a caller comparing the answer to an
// expected value must not have that comparison falsified by a warning. The
// stderr text travels in the error instead, where a human reads it.
func (executor SystemExecutor) run(timeout time.Duration, name string, arguments ...string) (string, error) {
	execution, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(execution, name, arguments...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	var errorOutput strings.Builder
	command.Stderr = &errorOutput
	output, err := command.Output()
	if err != nil {
		return string(output), fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(errorOutput.String()))
	}
	return string(output), nil
}

// runAs executes one fixed argument vector as the probe account.
//
// The account is switched with runuser rather than with a shell, so the command
// is executed directly and no interpretation happens between here and the
// program. The environment is built here, not inherited: a rootless Podman and a
// user systemd need to find their own runtime directory and bus, and nothing
// else of the environment is passed on.
func (executor SystemExecutor) runAs(account string, timeout time.Duration, name string, arguments ...string) (string, error) {
	entry, err := user.Lookup(account)
	if err != nil {
		return "", fmt.Errorf("the account %s does not exist on this machine", account)
	}
	runtimeDirectory := "/run/user/" + entry.Uid
	execution, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(execution, "runuser",
		append([]string{"-u", account, "--", name}, arguments...)...)
	// The working directory is fixed for the same reason as in run, and it is
	// load-bearing here: a rootless engine re-executes itself inside the user
	// namespace and chdir()s to the inherited directory, which the probe
	// account has no right to read when the Auxiliary was launched from
	// root's home — the exact situation a forced SSH command produces.
	command.Dir = "/"
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + entry.HomeDir,
		"USER=" + account,
		"XDG_RUNTIME_DIR=" + runtimeDirectory,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtimeDirectory + "/bus",
	}
	var errorOutput strings.Builder
	command.Stderr = &errorOutput
	output, err := command.Output()
	if err != nil {
		return string(output), fmt.Errorf("%s failed for %s: %w: %s", name, account, err, strings.TrimSpace(errorOutput.String()))
	}
	return string(output), nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open the Quadlet directory: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("synchronise the Quadlet directory: %w", err)
	}
	return nil
}
