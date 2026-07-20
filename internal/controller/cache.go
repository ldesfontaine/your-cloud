package controller

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

const relayCacheFileName = "relay-cache.json"

type RelayCacheStore struct {
	mu               sync.Mutex
	directory        string
	path             string
	controllerID     string
	infrastructureID string
	state            *RelaySnapshot
	loadError        error
	writeState       func(RelaySnapshot) error
}

// OpenRelayCache keeps a syntactically invalid regular cache recoverable while
// still refusing unsafe file types, links and modes.
func OpenRelayCacheStore(directory, controllerID, infrastructureID string) (*RelayCacheStore, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return nil, err
	}
	store := &RelayCacheStore{
		directory:        directory,
		path:             filepath.Join(directory, relayCacheFileName),
		controllerID:     controllerID,
		infrastructureID: infrastructureID,
	}
	store.writeState = func(candidate RelaySnapshot) error {
		return persistRelayCache(directory, store.path, candidate)
	}
	data, err := readPrivateStateFile(store.path, maxRelaySnapshotBytes)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	state, err := DecodeRelaySnapshot(data, controllerID, infrastructureID)
	if err != nil {
		store.loadError = err
		return store, nil
	}
	store.state = &state
	return store, nil
}

func (store *RelayCacheStore) Snapshot() (*RelaySnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil {
		if store.loadError != nil {
			return nil, store.loadError
		}
		return nil, os.ErrNotExist
	}
	copy := cloneRelaySnapshot(*store.state)
	return &copy, nil
}

func (store *RelayCacheStore) Commit(candidate RelaySnapshot) error {
	if err := candidate.Validate(store.controllerID, store.infrastructureID); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state != nil {
		if err := allowsSnapshotTransition(*store.state, candidate); err != nil {
			return err
		}
	}
	if err := store.writeState(candidate); err != nil {
		return err
	}
	copy := cloneRelaySnapshot(candidate)
	store.state = &copy
	store.loadError = nil
	return nil
}

func persistRelayCache(directory, path string, candidate RelaySnapshot) error {
	encoded, err := json.Marshal(candidate)
	if err != nil || len(encoded) > maxRelaySnapshotBytes {
		return errors.New("Relay cache cannot be encoded within its bound")
	}
	temporary, err := os.CreateTemp(directory, ".relay-cache-")
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func cloneRelaySnapshot(snapshot RelaySnapshot) RelaySnapshot {
	result := snapshot
	result.Machines = make([]RelaySnapshotMachine, len(snapshot.Machines))
	for index, machine := range snapshot.Machines {
		result.Machines[index] = machine
		if machine.Observation == nil {
			continue
		}
		observationCopy := *machine.Observation
		observationCopy.Gaps = append([]observation.Gap(nil), machine.Observation.Gaps...)
		if machine.Observation.Gaps != nil && observationCopy.Gaps == nil {
			observationCopy.Gaps = make([]observation.Gap, 0)
		}
		result.Machines[index].Observation = &observationCopy
	}
	return result
}
