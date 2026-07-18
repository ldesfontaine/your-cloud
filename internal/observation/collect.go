package observation

import (
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	uptimePath = "/proc/uptime"
	memoryPath = "/proc/meminfo"
	rootPath   = "/"
)

// FileSystemStats is the narrow result needed from statfs for the root mount.
type FileSystemStats struct {
	BlockSize       uint64
	TotalBlocks     uint64
	AvailableBlocks uint64
}

// Sources isolates the three local reads so their parsing can be tested without
// granting the collector arbitrary paths.
type Sources struct {
	ReadFile func(string) ([]byte, error)
	StatFS   func(string) (FileSystemStats, error)
}

// SystemSources returns production readers fixed to /proc and the root mount.
func SystemSources() Sources {
	return Sources{ReadFile: os.ReadFile, StatFS: systemStatFS}
}

// CollectHostHealth runs every approved collector independently.
func CollectHostHealth(sources Sources) HostHealth {
	return HostHealth{
		Uptime: collectUptime(sources.ReadFile),
		Memory: collectMemory(sources.ReadFile),
		RootFS: collectRootFS(sources.StatFS),
	}
}

func collectUptime(readFile func(string) ([]byte, error)) UptimeResult {
	data, err := readFile(uptimePath)
	if err != nil {
		return UptimeResult{Status: statusError, Error: errorRead}
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return UptimeResult{Status: statusError, Error: errorValue}
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 || seconds > math.MaxUint64 {
		return UptimeResult{Status: statusError, Error: errorValue}
	}
	value := uint64(seconds)
	return UptimeResult{Status: statusOK, UptimeSeconds: &value}
}

func collectMemory(readFile func(string) ([]byte, error)) MemoryResult {
	data, err := readFile(memoryPath)
	if err != nil {
		return MemoryResult{Status: statusError, Error: errorRead}
	}
	total, totalOK := memoryKilobytes(data, "MemTotal")
	available, availableOK := memoryKilobytes(data, "MemAvailable")
	if !totalOK || !availableOK || available > total || total > math.MaxUint64/1024 {
		return MemoryResult{Status: statusError, Error: errorValue}
	}
	total *= 1024
	available *= 1024
	return MemoryResult{Status: statusOK, TotalBytes: &total, AvailableBytes: &available}
}

func memoryKilobytes(data []byte, name string) (uint64, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != name+":" || fields[2] != "kB" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		return value, err == nil
	}
	return 0, false
}

func collectRootFS(statFS func(string) (FileSystemStats, error)) RootFSResult {
	stats, err := statFS(rootPath)
	if err != nil {
		return RootFSResult{Status: statusError, Error: errorRead}
	}
	total, totalOK := multiply(stats.BlockSize, stats.TotalBlocks)
	available, availableOK := multiply(stats.BlockSize, stats.AvailableBlocks)
	if !totalOK || !availableOK || available > total {
		return RootFSResult{Status: statusError, Error: errorValue}
	}
	return RootFSResult{Status: statusOK, TotalBytes: &total, AvailableBytes: &available}
}

func multiply(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func systemStatFS(path string) (FileSystemStats, error) {
	if path != rootPath {
		return FileSystemStats{}, errors.New("only the root filesystem is supported")
	}
	var raw syscall.Statfs_t
	if err := syscall.Statfs(path, &raw); err != nil {
		return FileSystemStats{}, err
	}
	return FileSystemStats{
		BlockSize:       uint64(raw.Bsize),
		TotalBlocks:     raw.Blocks,
		AvailableBlocks: raw.Bavail,
	}, nil
}
