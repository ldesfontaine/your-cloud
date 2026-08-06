package auxiliary

import (
	"context"
	"crypto/tls"
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
		opener := response.Header.Get("Cross-Origin-Opener-Policy")
		embedder := response.Header.Get("Cross-Origin-Embedder-Policy")
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			last = fmt.Errorf("the entrypoint answered %d for this name", response.StatusCode)
			continue
		}
		if opener != isolationOpenerPolicy || embedder != isolationEmbedderPolicy {
			last = fmt.Errorf(
				"the answer carried the isolation headers %q and %q rather than %q and %q",
				opener, embedder, isolationOpenerPolicy, isolationEmbedderPolicy)
			continue
		}
		return nil
	}
	if last == nil {
		last = errors.New("the entrypoint never served this name")
	}
	return last
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
