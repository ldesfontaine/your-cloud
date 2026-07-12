package collect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	telemetryv1 "github.com/ldesfontaine/your-cloud/protocole/gen/go"
)

// State collecte uniquement la télémétrie V1 bornée et les unités choisies.
func State(ctx context.Context, machineID, daemonVersion string, sequence uint64, units []string) (*telemetryv1.MachineState, error) {
	version, err := osReleaseVersion()
	if err != nil {
		return nil, err
	}
	kernel, err := kernelRelease()
	if err != nil {
		return nil, err
	}
	bootID, err := readTrimmed("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return nil, fmt.Errorf("lire le boot_id: %w", err)
	}
	uptime, err := uptimeSeconds()
	if err != nil {
		return nil, err
	}
	load, err := loadOne()
	if err != nil {
		return nil, err
	}
	memTotal, memAvailable, err := memory()
	if err != nil {
		return nil, err
	}
	rootTotal, rootFree, err := diskRoot()
	if err != nil {
		return nil, err
	}
	unitStates, err := selectedUnits(ctx, units)
	if err != nil {
		return nil, err
	}
	_, rebootErr := os.Stat("/var/run/reboot-required")
	if rebootErr != nil && !os.IsNotExist(rebootErr) {
		return nil, fmt.Errorf("lire l'état de redémarrage: %w", rebootErr)
	}
	return &telemetryv1.MachineState{
		SchemaVersion: 1, MachineId: machineID, DaemonVersion: daemonVersion,
		Sequence: sequence, ObservedAtUnix: time.Now().UTC().Unix(), DebianVersion: version,
		KernelRelease: kernel, BootId: bootID, UptimeSeconds: uptime, Load_1: load,
		MemoryTotalBytes: memTotal, MemoryAvailableBytes: memAvailable,
		MemoryUsedBytes: memTotal - memAvailable, RootTotalBytes: rootTotal,
		RootFreeBytes: rootFree, RootUsedBytes: rootTotal - rootFree,
		SecurityRebootRequired: rebootErr == nil, Units: unitStates,
		BootedAtUnix: time.Now().UTC().Unix() - int64(uptime),
	}, nil
}

func readTrimmed(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data := make([]byte, limit+1)
	n, err := file.Read(data)
	if err != nil && n == 0 {
		return "", err
	}
	if int64(n) > limit {
		return "", fmt.Errorf("valeur trop longue dans %s", path)
	}
	return strings.TrimSpace(string(data[:n])), nil
}

func osReleaseVersion() (string, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("lire os-release: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && key == "VERSION_ID" {
			return strings.Trim(value, `"`), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("VERSION_ID absente de os-release")
}

func kernelRelease() (string, error) {
	var value syscall.Utsname
	if err := syscall.Uname(&value); err != nil {
		return "", fmt.Errorf("uname: %w", err)
	}
	bytes := make([]byte, 0, len(value.Release))
	for _, char := range value.Release {
		if char == 0 {
			break
		}
		bytes = append(bytes, byte(char))
	}
	return string(bytes), nil
}

func uptimeSeconds() (uint64, error) {
	value, err := readTrimmed("/proc/uptime", 128)
	if err != nil {
		return 0, fmt.Errorf("lire uptime: %w", err)
	}
	field := strings.Fields(value)
	if len(field) < 1 {
		return 0, fmt.Errorf("uptime invalide")
	}
	seconds, err := strconv.ParseFloat(field[0], 64)
	if err != nil || seconds < 0 {
		return 0, fmt.Errorf("uptime invalide")
	}
	return uint64(seconds), nil
}

func loadOne() (float64, error) {
	value, err := readTrimmed("/proc/loadavg", 128)
	if err != nil {
		return 0, fmt.Errorf("lire loadavg: %w", err)
	}
	field := strings.Fields(value)
	if len(field) < 1 {
		return 0, fmt.Errorf("loadavg invalide")
	}
	result, err := strconv.ParseFloat(field[0], 64)
	if err != nil {
		return 0, fmt.Errorf("loadavg invalide")
	}
	return result, nil
}

func memory() (uint64, uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("lire meminfo: %w", err)
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && (fields[0] == "MemTotal:" || fields[0] == "MemAvailable:") {
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil {
				return 0, 0, fmt.Errorf("meminfo invalide")
			}
			values[fields[0]] = value * 1024
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if values["MemTotal:"] == 0 || values["MemAvailable:"] > values["MemTotal:"] {
		return 0, 0, fmt.Errorf("meminfo incomplet")
	}
	return values["MemTotal:"], values["MemAvailable:"], nil
}

func diskRoot() (uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, 0, fmt.Errorf("statfs /: %w", err)
	}
	return stat.Blocks * uint64(stat.Bsize), stat.Bavail * uint64(stat.Bsize), nil
}

func selectedUnits(ctx context.Context, units []string) ([]*telemetryv1.UnitState, error) {
	names := append([]string(nil), units...)
	sort.Strings(names)
	result := make([]*telemetryv1.UnitState, 0, len(names))
	for _, name := range names {
		commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		output, err := exec.CommandContext(commandCtx, "systemctl", "show", "--property=ActiveState", "--value", "--", name).Output()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("observer l'unité %s: %w", name, err)
		}
		state := strings.TrimSpace(string(output))
		if state == "" || len(state) > 32 {
			return nil, fmt.Errorf("état systemd invalide pour %s", name)
		}
		result = append(result, &telemetryv1.UnitState{Name: name, ActiveState: state})
	}
	return result, nil
}
