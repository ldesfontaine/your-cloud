// Package controller owns the bounded read-only Controller state and API.
package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	inventorySchema   = 1
	inventoryFileName = "inventory.json"
	maxInventoryBytes = int64(65_536)
	maxMachines       = 64
)

type Inventory struct {
	SchemaVersion       int                `json:"schema_version"`
	ControllerID        string             `json:"controller_id"`
	InfrastructureID    string             `json:"infrastructure_id"`
	InventoryRevision   uint64             `json:"inventory_revision"`
	InfrastructureLabel *string            `json:"infrastructure_label"`
	Machines            []InventoryMachine `json:"machines"`
}

type InventoryMachine struct {
	MachineID string `json:"machine_id"`
	Label     string `json:"label"`
}

type InfrastructureView struct {
	SchemaVersion     int     `json:"schema_version"`
	ControllerID      string  `json:"controller_id"`
	InfrastructureID  string  `json:"infrastructure_id"`
	Initialized       bool    `json:"initialized"`
	Label             *string `json:"label"`
	InventoryRevision uint64  `json:"inventory_revision"`
}

type MachineMutationView struct {
	SchemaVersion     int    `json:"schema_version"`
	InventoryRevision uint64 `json:"inventory_revision"`
	MachineID         string `json:"machine_id"`
	Label             string `json:"label"`
}

type InventoryStore struct {
	mu         sync.Mutex
	directory  string
	path       string
	state      Inventory
	writeState func(Inventory) error
}

func CreateInventory(directory, controllerID, infrastructureID string) error {
	if err := identifier.ValidateUUIDv4(controllerID); err != nil {
		return fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(infrastructureID); err != nil {
		return fmt.Errorf("infrastructure_id: %w", err)
	}
	if err := validatePrivateStateDirectory(directory); err != nil {
		return err
	}
	path := filepath.Join(directory, inventoryFileName)
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("inventory authority already exists or cannot be inspected")
	}
	state := Inventory{
		SchemaVersion:     inventorySchema,
		ControllerID:      controllerID,
		InfrastructureID:  infrastructureID,
		InventoryRevision: 0,
		Machines:          make([]InventoryMachine, 0),
	}
	return persistInventory(directory, path, state)
}

func OpenInventoryStore(directory string) (*InventoryStore, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, inventoryFileName)
	state, err := readInventory(path)
	if err != nil {
		return nil, err
	}
	store := &InventoryStore{directory: directory, path: path, state: state}
	store.writeState = func(candidate Inventory) error {
		return persistInventory(directory, path, candidate)
	}
	return store, nil
}

func (store *InventoryStore) Snapshot() Inventory {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneInventory(store.state)
}

func (store *InventoryStore) Infrastructure() InfrastructureView {
	state := store.Snapshot()
	return InfrastructureView{
		SchemaVersion:     1,
		ControllerID:      state.ControllerID,
		InfrastructureID:  state.InfrastructureID,
		Initialized:       state.InfrastructureLabel != nil,
		Label:             cloneString(state.InfrastructureLabel),
		InventoryRevision: state.InventoryRevision,
	}
}

// PutInfrastructure performs the one-time idempotent label publication.
func (store *InventoryStore) PutInfrastructure(infrastructureID, rawLabel string) (InfrastructureView, bool, error) {
	canonical, err := CanonicalLabel(rawLabel)
	if err != nil {
		return InfrastructureView{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if infrastructureID != store.state.InfrastructureID {
		return InfrastructureView{}, false, errors.New("infrastructure identity conflicts with local authority")
	}
	if store.state.InfrastructureLabel != nil {
		if *store.state.InfrastructureLabel != canonical {
			return InfrastructureView{}, false, errors.New("infrastructure is already initialized differently")
		}
		return infrastructureView(store.state), false, nil
	}
	candidate := cloneInventory(store.state)
	if candidate.InventoryRevision == math.MaxUint64 {
		return InfrastructureView{}, false, errors.New("inventory revision is saturated")
	}
	candidate.InventoryRevision++
	candidate.InfrastructureLabel = &canonical
	if err := store.commit(candidate); err != nil {
		return InfrastructureView{}, false, err
	}
	return infrastructureView(store.state), true, nil
}

// PutMachine mutates only local business state; allowNew must come from a fresh
// authenticated Relay read performed by the caller during the same operation.
func (store *InventoryStore) PutMachine(machineID, rawLabel string, allowNew bool) (MachineMutationView, bool, error) {
	if err := machineid.Validate(machineID); err != nil {
		return MachineMutationView{}, false, err
	}
	canonical, err := CanonicalLabel(rawLabel)
	if err != nil {
		return MachineMutationView{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := sort.Search(len(store.state.Machines), func(index int) bool {
		return store.state.Machines[index].MachineID >= machineID
	})
	if index < len(store.state.Machines) && store.state.Machines[index].MachineID == machineID {
		if store.state.Machines[index].Label == canonical {
			return machineMutationView(store.state, store.state.Machines[index]), false, nil
		}
		if store.state.InventoryRevision == math.MaxUint64 {
			return MachineMutationView{}, false, errors.New("inventory revision is saturated")
		}
		candidate := cloneInventory(store.state)
		candidate.Machines[index].Label = canonical
		candidate.InventoryRevision++
		if err := store.commit(candidate); err != nil {
			return MachineMutationView{}, false, err
		}
		return machineMutationView(store.state, store.state.Machines[index]), true, nil
	}
	if !allowNew {
		return MachineMutationView{}, false, errors.New("machine is not active in a fresh Relay snapshot")
	}
	if len(store.state.Machines) >= maxMachines || store.state.InventoryRevision == math.MaxUint64 {
		return MachineMutationView{}, false, errors.New("inventory capacity or revision is exhausted")
	}
	candidate := cloneInventory(store.state)
	candidate.Machines = append(candidate.Machines, InventoryMachine{})
	copy(candidate.Machines[index+1:], candidate.Machines[index:])
	candidate.Machines[index] = InventoryMachine{MachineID: machineID, Label: canonical}
	candidate.InventoryRevision++
	if err := store.commit(candidate); err != nil {
		return MachineMutationView{}, false, err
	}
	return machineMutationView(store.state, store.state.Machines[index]), true, nil
}

func (store *InventoryStore) commit(candidate Inventory) error {
	if err := validateInventory(candidate); err != nil {
		return err
	}
	if err := store.writeState(candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

func readInventory(path string) (Inventory, error) {
	data, err := readPrivateStateFile(path, maxInventoryBytes)
	if err != nil {
		return Inventory{}, err
	}
	var state Inventory
	if err := strictjson.Decode(data, &state); err != nil {
		return Inventory{}, fmt.Errorf("decode inventory authority: %w", err)
	}
	if err := validateInventory(state); err != nil {
		return Inventory{}, err
	}
	return state, nil
}

func validateInventory(state Inventory) error {
	if state.SchemaVersion != inventorySchema {
		return errors.New("unsupported inventory schema_version")
	}
	if err := identifier.ValidateUUIDv4(state.ControllerID); err != nil {
		return fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(state.InfrastructureID); err != nil {
		return fmt.Errorf("infrastructure_id: %w", err)
	}
	if state.InfrastructureLabel != nil {
		canonical, err := CanonicalLabel(*state.InfrastructureLabel)
		if err != nil || canonical != *state.InfrastructureLabel {
			return errors.New("infrastructure label is not canonical")
		}
	}
	if state.Machines == nil || len(state.Machines) > maxMachines {
		return errors.New("inventory machines must be a present bounded array")
	}
	previous := ""
	for _, machine := range state.Machines {
		if err := machineid.Validate(machine.MachineID); err != nil {
			return err
		}
		if machine.MachineID <= previous {
			return errors.New("inventory machines must be unique and sorted")
		}
		canonical, err := CanonicalLabel(machine.Label)
		if err != nil || canonical != machine.Label {
			return errors.New("machine label is not canonical")
		}
		previous = machine.MachineID
	}
	return nil
}

func persistInventory(directory, path string, candidate Inventory) error {
	if err := validateInventory(candidate); err != nil {
		return err
	}
	encoded, err := json.Marshal(candidate)
	if err != nil || int64(len(encoded)) > maxInventoryBytes {
		return errors.New("inventory cannot be encoded within its bound")
	}
	temporary, err := os.CreateTemp(directory, ".inventory-")
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

func validatePrivateStateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("Controller state directory must be absolute and canonical")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("Controller state directory must be a real private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("Controller state directory must belong to the service account")
	}
	return nil
}

func readPrivateStateFile(path string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("Controller state file must be regular and private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("Controller state file ownership metadata is unavailable, foreign or linked")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, errors.New("Controller state file is empty, unreadable or too large")
	}
	return data, nil
}

func cloneInventory(state Inventory) Inventory {
	result := state
	result.InfrastructureLabel = cloneString(state.InfrastructureLabel)
	result.Machines = make([]InventoryMachine, len(state.Machines))
	copy(result.Machines, state.Machines)
	return result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func infrastructureView(state Inventory) InfrastructureView {
	return InfrastructureView{
		SchemaVersion:     1,
		ControllerID:      state.ControllerID,
		InfrastructureID:  state.InfrastructureID,
		Initialized:       state.InfrastructureLabel != nil,
		Label:             cloneString(state.InfrastructureLabel),
		InventoryRevision: state.InventoryRevision,
	}
}

func machineMutationView(state Inventory, machine InventoryMachine) MachineMutationView {
	return MachineMutationView{
		SchemaVersion:     1,
		InventoryRevision: state.InventoryRevision,
		MachineID:         machine.MachineID,
		Label:             machine.Label,
	}
}
