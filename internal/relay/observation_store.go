package relay

import (
	"crypto/sha256"
	"encoding/hex"
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
	observationStoreSchema   = 1
	observationStoreFileName = "relay-observations.json"
	maxObservationStoreBytes = int64(1024 * 1024)
)

// ObservationStore durably keeps the latest accepted state for each machine.
type ObservationStore struct {
	mu    sync.Mutex
	dir   string
	path  string
	state observationStoreState
	// writeState is replaced only by package tests to model a disk failure.
	writeState func(observationStoreState) error
}

type observationStoreState struct {
	Schema   int                          `json:"schema"`
	Machines map[string]storedObservation `json:"machines"`
}

type storedObservation struct {
	Sequence   uint64               `json:"sequence"`
	SHA256     string               `json:"sha256"`
	ReceivedAt string               `json:"received_at"`
	Envelope   observation.Envelope `json:"envelope"`
	Gaps       []observation.Gap    `json:"gaps"`
}

// OpenObservationStore creates or validates one private Relay state file.
func OpenObservationStore(directory string) (*ObservationStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Relay store directory must be an absolute canonical path")
	}
	if err := prepareObservationStoreDirectory(directory); err != nil {
		return nil, err
	}
	store := &ObservationStore{dir: directory, path: filepath.Join(directory, observationStoreFileName)}
	store.writeState = store.persistState
	loaded, err := readObservationStore(store.path)
	if errors.Is(err, os.ErrNotExist) {
		candidate := observationStoreState{Schema: observationStoreSchema, Machines: make(map[string]storedObservation)}
		if err := store.commit(candidate); err != nil {
			return nil, err
		}
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	store.state = loaded
	if err := store.validate(); err != nil {
		return nil, err
	}
	return store, nil
}

// Save authenticates the body identity, enforces sequence continuity and
// persists before returning a successful acknowledgement.
func (store *ObservationStore) Save(authenticatedMachine string, encoded []byte, receivedAt time.Time) (observation.Envelope, bool, error) {
	envelope, err := observation.Decode(encoded)
	if err != nil {
		return observation.Envelope{}, false, err
	}
	if envelope.MachineID != authenticatedMachine {
		return observation.Envelope{}, false, errors.New("observation machine does not match the authenticated certificate")
	}
	digest := sha256.Sum256(encoded)
	digestText := hex.EncodeToString(digest[:])

	store.mu.Lock()
	defer store.mu.Unlock()
	current, found := store.state.Machines[authenticatedMachine]
	firstSkipped := uint64(1)
	if found {
		switch {
		case envelope.Sequence == current.Sequence && digestText == current.SHA256:
			return envelope, true, nil
		case envelope.Sequence == current.Sequence:
			return observation.Envelope{}, false, errors.New("observation sequence collides with different bytes")
		case envelope.Sequence < current.Sequence:
			return observation.Envelope{}, false, errors.New("observation sequence is older than the durable Relay state")
		}
		firstSkipped = current.Sequence + 1
	}
	if !gapsMatchSkippedRange(envelope.Gaps, firstSkipped, envelope.Sequence-1) {
		return observation.Envelope{}, false, errors.New("observation gaps do not exactly match the skipped sequence range")
	}

	receivedGaps := append([]observation.Gap(nil), envelope.Gaps...)
	if found {
		receivedGaps = append(receivedGaps, current.Gaps...)
	}
	candidate := cloneObservationStoreState(store.state)
	candidate.Machines[authenticatedMachine] = storedObservation{
		Sequence:   envelope.Sequence,
		SHA256:     digestText,
		ReceivedAt: receivedAt.UTC().Format(time.RFC3339Nano),
		Envelope:   cloneObservationEnvelope(envelope),
		Gaps:       mergeReceivedGaps(receivedGaps),
	}
	if err := store.commit(candidate); err != nil {
		return observation.Envelope{}, false, err
	}
	return envelope, false, nil
}

// Snapshot returns one machine's durable state for local proof and future
// authenticated readers; it opens no network route by itself.
func (store *ObservationStore) Snapshot(machineID string) (observation.Envelope, string, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, found := store.state.Machines[machineID]
	result := cloneObservationEnvelope(stored.Envelope)
	result.Gaps = append([]observation.Gap(nil), stored.Gaps...)
	return result, stored.ReceivedAt, found
}

func mergeReceivedGaps(gaps []observation.Gap) []observation.Gap {
	sort.Slice(gaps, func(left, right int) bool {
		return gaps[left].FirstSequence < gaps[right].FirstSequence
	})
	merged := make([]observation.Gap, 0, len(gaps))
	for _, gap := range gaps {
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
	return merged
}

func gapsMatchSkippedRange(gaps []observation.Gap, first, last uint64) bool {
	if first > last {
		return len(gaps) == 0
	}
	if len(gaps) == 0 {
		return false
	}
	next := first
	for index, gap := range gaps {
		if gap.FirstSequence != next || gap.LastSequence > last {
			return false
		}
		if gap.LastSequence == last {
			return index == len(gaps)-1
		}
		next = gap.LastSequence + 1
	}
	return false
}

func (store *ObservationStore) validate() error {
	if store.state.Schema != observationStoreSchema || store.state.Machines == nil || len(store.state.Machines) > 64 {
		return errors.New("Relay observation store has an unsupported schema or size")
	}
	for machineID, stored := range store.state.Machines {
		if stored.Envelope.MachineID != machineID || stored.Sequence != stored.Envelope.Sequence {
			return errors.New("Relay observation store identity or sequence is inconsistent")
		}
		if err := stored.Envelope.Validate(); err != nil {
			return fmt.Errorf("Relay observation store contains an invalid envelope: %w", err)
		}
		if len(stored.SHA256) != 64 {
			return errors.New("Relay observation store contains an invalid digest")
		}
		for _, gap := range stored.Gaps {
			if err := gap.Validate(); err != nil {
				return errors.New("Relay observation store contains an invalid retained gap")
			}
		}
		if _, err := time.Parse(time.RFC3339Nano, stored.ReceivedAt); err != nil {
			return errors.New("Relay observation store contains an invalid reception time")
		}
	}
	return nil
}

// commit makes a candidate visible only after its complete persistence.
func (store *ObservationStore) commit(candidate observationStoreState) error {
	if err := store.writeState(candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

func (store *ObservationStore) persistState(candidate observationStoreState) error {
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode Relay observation store: %w", err)
	}
	if int64(len(encoded)) > maxObservationStoreBytes {
		return errors.New("Relay observation store exceeds its maximum size")
	}
	temporary, err := os.CreateTemp(store.dir, ".relay-observations-")
	if err != nil {
		return err
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
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return err
	}
	removeTemporary = false
	directory, err := os.Open(store.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func cloneObservationStoreState(source observationStoreState) observationStoreState {
	result := source
	result.Machines = make(map[string]storedObservation, len(source.Machines))
	for machineID, stored := range source.Machines {
		result.Machines[machineID] = storedObservation{
			Sequence:   stored.Sequence,
			SHA256:     stored.SHA256,
			ReceivedAt: stored.ReceivedAt,
			Envelope:   cloneObservationEnvelope(stored.Envelope),
			Gaps:       append([]observation.Gap(nil), stored.Gaps...),
		}
	}
	return result
}

func cloneObservationEnvelope(source observation.Envelope) observation.Envelope {
	result := source
	result.Gaps = append([]observation.Gap(nil), source.Gaps...)
	result.Health.Uptime.UptimeSeconds = cloneObservationUint64(source.Health.Uptime.UptimeSeconds)
	result.Health.Memory.TotalBytes = cloneObservationUint64(source.Health.Memory.TotalBytes)
	result.Health.Memory.AvailableBytes = cloneObservationUint64(source.Health.Memory.AvailableBytes)
	result.Health.RootFS.TotalBytes = cloneObservationUint64(source.Health.RootFS.TotalBytes)
	result.Health.RootFS.AvailableBytes = cloneObservationUint64(source.Health.RootFS.AvailableBytes)
	return result
}

func cloneObservationUint64(source *uint64) *uint64 {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}

func readObservationStore(path string) (observationStoreState, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return observationStoreState{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return observationStoreState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxObservationStoreBytes {
		return observationStoreState{}, errors.New("Relay observation store has unsafe type, mode or size")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxObservationStoreBytes+1))
	if err != nil || int64(len(data)) > maxObservationStoreBytes {
		return observationStoreState{}, errors.New("Relay observation store cannot be read within its limit")
	}
	var loaded observationStoreState
	if err := strictjson.Decode(data, &loaded); err != nil {
		return observationStoreState{}, err
	}
	return loaded, nil
}

func prepareObservationStoreDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Relay observation store directory must be private and real")
	}
	return nil
}
