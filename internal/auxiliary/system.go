package auxiliary

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
// home and no login shell.
func (executor SystemExecutor) CreateProbeAccount(account, home string) error {
	_, err := executor.run(commandTimeout, "useradd",
		"--system",
		"--user-group",
		"--home-dir", home,
		"--create-home",
		"--shell", "/usr/sbin/nologin",
		"--comment", "Your Cloud OCI validation probe",
		account,
	)
	return err
}

// EnableLinger keeps that account's systemd user manager running without a
// session, which is what carries an approved state across a reboot.
func (executor SystemExecutor) EnableLinger(account string) error {
	_, err := executor.run(commandTimeout, "loginctl", "enable-linger", account)
	return err
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
		// not, and is never reported as an absence.
		if strings.Contains(strings.ToLower(output), "no such container") {
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
func (executor SystemExecutor) ProbeAnswers(port int) error {
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
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return nil
		}
		last = fmt.Errorf("the probe answered %d", response.StatusCode)
	}
	if last == nil {
		last = errors.New("the probe never answered")
	}
	return last
}

// run executes one fixed argument vector as root, with a replaced environment.
func (executor SystemExecutor) run(timeout time.Duration, name string, arguments ...string) (string, error) {
	execution, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(execution, name, arguments...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s failed: %w", name, err)
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
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + entry.HomeDir,
		"USER=" + account,
		"XDG_RUNTIME_DIR=" + runtimeDirectory,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtimeDirectory + "/bus",
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s failed for %s: %w", name, account, err)
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
