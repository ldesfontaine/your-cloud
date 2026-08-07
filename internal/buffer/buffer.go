// Package buffer persists the bounded local delivery queue of one Daemon.
package buffer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	stateSchema     = 1
	stateFileName   = "observation-buffer.json"
	HardMaxBytes    = int64(16 * 1024 * 1024)
	HardMaxRecords  = 10_000
	HardMaxAge      = 24 * time.Hour
	minimumMaxBytes = int64(16 * 1024)
	defaultMaxBytes = int64(64 * 1024)
	defaultRecords  = 120
	defaultMaxAge   = time.Hour
)

// Limits can reduce, never enlarge, the measured safety ceilings.
type Limits struct {
	MaxBytes   int64
	MaxRecords int
	MaxAge     time.Duration
}

// DefaultLimits retain about one hour at the fixed 30-second cadence while
// leaving metadata headroom above the measured encoded observation size.
func DefaultLimits() Limits {
	return Limits{MaxBytes: defaultMaxBytes, MaxRecords: defaultRecords, MaxAge: defaultMaxAge}
}

// Stats is the bounded state exposed by the local diagnostic command.
type Stats struct {
	PendingRecords int    `json:"pending_records"`
	PendingBytes   int64  `json:"pending_bytes"`
	OldestObserved string `json:"oldest_observed_at,omitempty"`
	NextSequence   uint64 `json:"next_sequence"`
	GapCount       int    `json:"gap_count"`
	LastDelivered  string `json:"last_delivered_at,omitempty"`
	DeliveryState  string `json:"delivery_state"`
	LastTransition string `json:"last_delivery_transition_at,omitempty"`
}

// Inspection is the complete read-only diagnostic view.
type Inspection struct {
	Current *observation.Envelope `json:"current,omitempty"`
	Stats   Stats                 `json:"stats"`
}

// Buffer owns one atomically published state file.
type Buffer struct {
	mu     sync.Mutex
	dir    string
	path   string
	limits Limits
	state  state
	// writeState is replaced only by package tests to model a disk failure.
	writeState func(state) error
}

type state struct {
	Schema         int                    `json:"schema"`
	NextSequence   uint64                 `json:"next_sequence"`
	Current        *observation.Envelope  `json:"current,omitempty"`
	Pending        []observation.Envelope `json:"pending"`
	Gaps           []observation.Gap      `json:"gaps"`
	LastDelivered  string                 `json:"last_delivered_at,omitempty"`
	DeliveryState  string                 `json:"delivery_state"`
	LastTransition string                 `json:"last_delivery_transition_at,omitempty"`
}

// Open creates or validates the private state directory and resumes its queue.
func Open(directory string, limits Limits) (*Buffer, error) {
	return openAt(directory, limits, time.Now().UTC())
}

func openAt(directory string, limits Limits, now time.Time) (*Buffer, error) {
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("buffer directory must be an absolute canonical path")
	}
	if err := prepareDirectory(directory); err != nil {
		return nil, err
	}
	result := &Buffer{dir: directory, path: filepath.Join(directory, stateFileName), limits: limits}
	result.writeState = result.persistState
	loaded, err := readState(result.path)
	if errors.Is(err, os.ErrNotExist) {
		candidate := state{Schema: stateSchema, NextSequence: 1, Pending: []observation.Envelope{}, Gaps: []observation.Gap{}, DeliveryState: "unknown"}
		if err := result.commit(candidate); err != nil {
			return nil, err
		}
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	result.state = loaded
	if err := result.validateState(); err != nil {
		return nil, err
	}
	candidate := cloneState(result.state)
	if err := result.enforce(&candidate, now.UTC()); err != nil {
		return nil, err
	}
	if err := result.commit(candidate); err != nil {
		return nil, err
	}
	return result, nil
}

// Enqueue persists one new current state before making it available to send.
//
// external is what the machine's declared loopback targets did at the same
// instant, and it is empty on every machine whose own sheet names none: the
// queue of such a machine holds exactly the envelopes it held before `#107`.
func (buffer *Buffer) Enqueue(machineID string, health observation.HostHealth, external []observation.ExternalReading, now time.Time) (observation.Envelope, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()

	candidate := cloneState(buffer.state)
	envelope, err := observation.NewEnvelope(machineID, candidate.NextSequence, now, health, external)
	if err != nil {
		return observation.Envelope{}, err
	}
	storedEnvelope := cloneEnvelope(envelope)
	candidate.NextSequence++
	candidate.Current = &storedEnvelope
	candidate.Pending = append(candidate.Pending, storedEnvelope)
	if err := buffer.enforce(&candidate, now.UTC()); err != nil {
		return observation.Envelope{}, err
	}
	if err := buffer.commit(candidate); err != nil {
		return observation.Envelope{}, err
	}
	return cloneEnvelope(envelope), nil
}

// Peek returns the immutable oldest payload. Any pending gap is attached and
// persisted before the bytes can leave the machine.
func (buffer *Buffer) Peek() ([]byte, uint64, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if len(buffer.state.Pending) == 0 {
		return nil, 0, io.EOF
	}
	if len(buffer.state.Gaps) > 0 {
		candidate := cloneState(buffer.state)
		candidate.Pending[0].Gaps = append([]observation.Gap(nil), candidate.Gaps...)
		candidate.Gaps = []observation.Gap{}
		if err := buffer.commit(candidate); err != nil {
			return nil, 0, err
		}
	}
	encoded, err := buffer.state.Pending[0].Encode()
	if err != nil {
		return nil, 0, fmt.Errorf("encode pending observation: %w", err)
	}
	return encoded, buffer.state.Pending[0].Sequence, nil
}

// Acknowledge removes only the exact oldest sequence confirmed by the Relay.
func (buffer *Buffer) Acknowledge(sequence uint64, deliveredAt time.Time) error {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if len(buffer.state.Pending) == 0 || buffer.state.Pending[0].Sequence != sequence {
		return errors.New("acknowledgement does not match the oldest pending sequence")
	}
	candidate := cloneState(buffer.state)
	candidate.Pending = append([]observation.Envelope(nil), candidate.Pending[1:]...)
	candidate.LastDelivered = deliveredAt.UTC().Format(time.RFC3339Nano)
	return buffer.commit(candidate)
}

// Stats returns no collector data and performs no mutation.
func (buffer *Buffer) Stats() (Stats, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return statsFromState(buffer.state)
}

// SetDeliveryState persists only a real transition and accepts no free error.
func (buffer *Buffer) SetDeliveryState(value string, changedAt time.Time) error {
	if value != "available" && value != "unavailable" {
		return errors.New("delivery state must be available or unavailable")
	}
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.state.DeliveryState == value {
		return nil
	}
	candidate := cloneState(buffer.state)
	candidate.DeliveryState = value
	candidate.LastTransition = changedAt.UTC().Format(time.RFC3339Nano)
	return buffer.commit(candidate)
}

// Inspect reads and validates the local state without creating, enforcing,
// acknowledging or rewriting anything.
func Inspect(directory string, limits Limits) (Inspection, error) {
	if err := validateLimits(limits); err != nil {
		return Inspection{}, err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Inspection{}, errors.New("buffer directory must be an absolute canonical path")
	}
	loaded, err := readState(filepath.Join(directory, stateFileName))
	if err != nil {
		return Inspection{}, err
	}
	validator := &Buffer{limits: limits, state: loaded}
	if err := validator.validateState(); err != nil {
		return Inspection{}, err
	}
	stats, err := statsFromState(loaded)
	if err != nil {
		return Inspection{}, err
	}
	var current *observation.Envelope
	if loaded.Current != nil {
		copy := *loaded.Current
		current = &copy
	}
	return Inspection{Current: current, Stats: stats}, nil
}

func statsFromState(current state) (Stats, error) {
	var pendingBytes int64
	for _, pending := range current.Pending {
		encoded, err := pending.Encode()
		if err != nil {
			return Stats{}, fmt.Errorf("encode pending observation for statistics: %w", err)
		}
		pendingBytes += int64(len(encoded))
	}
	gapCount := len(current.Gaps)
	for _, pending := range current.Pending {
		gapCount += len(pending.Gaps)
	}
	result := Stats{
		PendingRecords: len(current.Pending),
		PendingBytes:   pendingBytes,
		NextSequence:   current.NextSequence,
		GapCount:       gapCount,
		LastDelivered:  current.LastDelivered,
		DeliveryState:  current.DeliveryState,
		LastTransition: current.LastTransition,
	}
	if len(current.Pending) > 0 {
		result.OldestObserved = current.Pending[0].ObservedAt
	}
	return result, nil
}

func (buffer *Buffer) enforce(candidate *state, now time.Time) error {
	for len(candidate.Pending) > 0 {
		oldestTime, err := time.Parse(time.RFC3339Nano, candidate.Pending[0].ObservedAt)
		if err != nil {
			return errors.New("pending observation has an invalid timestamp")
		}
		encoded, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		withinAge := !oldestTime.Before(now.Add(-buffer.limits.MaxAge))
		withinCount := len(candidate.Pending) <= buffer.limits.MaxRecords
		withinBytes := int64(len(encoded)) <= buffer.limits.MaxBytes
		if withinAge && withinCount && withinBytes {
			return nil
		}
		buffer.dropOldest(candidate)
	}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > buffer.limits.MaxBytes {
		return errors.New("buffer metadata exceeds its byte limit")
	}
	return nil
}

func (buffer *Buffer) dropOldest(candidate *state) {
	dropped := candidate.Pending[0]
	candidate.Pending = append([]observation.Envelope(nil), candidate.Pending[1:]...)
	for _, gap := range dropped.Gaps {
		buffer.addGap(candidate, gap)
	}
	buffer.addGap(candidate, observation.Gap{
		FirstSequence:   dropped.Sequence,
		LastSequence:    dropped.Sequence,
		DroppedCount:    1,
		FirstObservedAt: dropped.ObservedAt,
		LastObservedAt:  dropped.ObservedAt,
	})
}

func (buffer *Buffer) addGap(current *state, candidate observation.Gap) {
	current.Gaps = append(current.Gaps, candidate)
	sort.Slice(current.Gaps, func(left, right int) bool {
		return current.Gaps[left].FirstSequence < current.Gaps[right].FirstSequence
	})
	merged := make([]observation.Gap, 0, len(current.Gaps))
	for _, gap := range current.Gaps {
		if len(merged) == 0 || merged[len(merged)-1].LastSequence+1 < gap.FirstSequence {
			merged = append(merged, gap)
			continue
		}
		last := &merged[len(merged)-1]
		if gap.LastSequence > last.LastSequence {
			last.LastSequence = gap.LastSequence
			last.LastObservedAt = gap.LastObservedAt
		}
		last.DroppedCount = last.LastSequence - last.FirstSequence + 1
	}
	current.Gaps = merged
}

// commit makes a candidate visible only after its complete persistence.
func (buffer *Buffer) commit(candidate state) error {
	if err := buffer.writeState(candidate); err != nil {
		return err
	}
	buffer.state = candidate
	return nil
}

func (buffer *Buffer) persistState(candidate state) error {
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode buffer state: %w", err)
	}
	if int64(len(encoded)) > buffer.limits.MaxBytes {
		return errors.New("buffer state exceeds its byte limit")
	}
	temporary, err := os.CreateTemp(buffer.dir, ".observation-buffer-")
	if err != nil {
		return fmt.Errorf("create temporary buffer state: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, buffer.path); err != nil {
		return fmt.Errorf("publish buffer state: %w", err)
	}
	removeTemporary = false
	return syncDirectory(buffer.dir)
}

func cloneState(source state) state {
	result := source
	if source.Current != nil {
		current := cloneEnvelope(*source.Current)
		result.Current = &current
	}
	result.Pending = make([]observation.Envelope, len(source.Pending))
	for index, envelope := range source.Pending {
		result.Pending[index] = cloneEnvelope(envelope)
	}
	result.Gaps = append([]observation.Gap(nil), source.Gaps...)
	return result
}

func cloneEnvelope(source observation.Envelope) observation.Envelope {
	result := source
	result.Gaps = append([]observation.Gap(nil), source.Gaps...)
	result.External = append([]observation.ExternalReading(nil), source.External...)
	result.Health.Uptime.UptimeSeconds = cloneUint64(source.Health.Uptime.UptimeSeconds)
	result.Health.Memory.TotalBytes = cloneUint64(source.Health.Memory.TotalBytes)
	result.Health.Memory.AvailableBytes = cloneUint64(source.Health.Memory.AvailableBytes)
	result.Health.RootFS.TotalBytes = cloneUint64(source.Health.RootFS.TotalBytes)
	result.Health.RootFS.AvailableBytes = cloneUint64(source.Health.RootFS.AvailableBytes)
	return result
}

func cloneUint64(source *uint64) *uint64 {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}

func readState(path string) (state, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return state{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return state{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > HardMaxBytes {
		return state{}, errors.New("buffer state file has unsafe type, mode or size")
	}
	data, err := io.ReadAll(io.LimitReader(file, HardMaxBytes+1))
	if err != nil || int64(len(data)) > HardMaxBytes {
		return state{}, errors.New("buffer state cannot be read within its limit")
	}
	var loaded state
	if err := strictjson.Decode(data, &loaded); err != nil {
		return state{}, fmt.Errorf("decode buffer state: %w", err)
	}
	return loaded, nil
}

func (buffer *Buffer) validateState() error {
	if buffer.state.Schema != stateSchema || buffer.state.NextSequence == 0 {
		return errors.New("buffer state has an unsupported schema or sequence")
	}
	previous := uint64(0)
	for _, pending := range buffer.state.Pending {
		if err := pending.Validate(); err != nil {
			return fmt.Errorf("pending observation: %w", err)
		}
		if pending.Sequence <= previous || pending.Sequence >= buffer.state.NextSequence {
			return errors.New("pending observation sequences are not strictly ordered")
		}
		previous = pending.Sequence
	}
	if buffer.state.Current != nil {
		if err := buffer.state.Current.Validate(); err != nil {
			return fmt.Errorf("current observation: %w", err)
		}
		if buffer.state.Current.Sequence >= buffer.state.NextSequence {
			return errors.New("current observation sequence is outside the persisted range")
		}
	}
	for _, gap := range buffer.state.Gaps {
		if err := gap.Validate(); err != nil {
			return err
		}
	}
	if buffer.state.LastDelivered != "" {
		if _, err := time.Parse(time.RFC3339Nano, buffer.state.LastDelivered); err != nil {
			return errors.New("last_delivered_at is invalid")
		}
	}
	if buffer.state.DeliveryState != "unknown" && buffer.state.DeliveryState != "available" && buffer.state.DeliveryState != "unavailable" {
		return errors.New("delivery_state is invalid")
	}
	if buffer.state.LastTransition != "" {
		if _, err := time.Parse(time.RFC3339Nano, buffer.state.LastTransition); err != nil {
			return errors.New("last_delivery_transition_at is invalid")
		}
	}
	return nil
}

func validateLimits(limits Limits) error {
	if limits.MaxBytes < minimumMaxBytes || limits.MaxBytes > HardMaxBytes {
		return errors.New("buffer MaxBytes is outside the approved range")
	}
	if limits.MaxRecords < 1 || limits.MaxRecords > HardMaxRecords {
		return errors.New("buffer MaxRecords is outside the approved range")
	}
	if limits.MaxAge <= 0 || limits.MaxAge > HardMaxAge {
		return errors.New("buffer MaxAge is outside the approved range")
	}
	return nil
}

func prepareDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create buffer directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("buffer directory must be a private real directory")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
