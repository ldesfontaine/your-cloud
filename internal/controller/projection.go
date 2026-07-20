package controller

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

const maxConsoleResponseBytes = 128 * 1024

type RelayStatus string

const (
	RelayAvailable      RelayStatus = "available"
	RelayUnavailable    RelayStatus = "unavailable"
	RelayClockUntrusted RelayStatus = "clock_untrusted"
)

type MachinesView struct {
	SchemaVersion     int                `json:"schema_version"`
	ControllerID      string             `json:"controller_id"`
	InfrastructureID  string             `json:"infrastructure_id"`
	InventoryRevision uint64             `json:"inventory_revision"`
	RelayStatus       RelayStatus        `json:"relay_status"`
	RelaySnapshotAt   *string            `json:"relay_snapshot_at"`
	Machines          []ProjectedMachine `json:"machines"`
}

type ProjectedMachine struct {
	MachineID         string                `json:"machine_id"`
	Label             string                `json:"label"`
	EnrollmentStatus  *string               `json:"enrollment_status"`
	ObservationStatus *string               `json:"observation_status"`
	Observation       *ProjectedObservation `json:"observation"`
}

type ProjectedObservation struct {
	Profile             string                 `json:"profile"`
	Sequence            uint64                 `json:"sequence"`
	ObservedAt          string                 `json:"observed_at"`
	ReceivedAt          string                 `json:"received_at"`
	ObservedTimeWarning bool                   `json:"observed_time_warning"`
	Continuity          string                 `json:"continuity"`
	GapSummary          *GapSummary            `json:"gap_summary"`
	Health              observation.HostHealth `json:"health"`
}

type GapSummary struct {
	RangeCount    uint64 `json:"range_count"`
	DroppedCount  uint64 `json:"dropped_count"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
}

// ProjectMachines exposes only inventory machines and never the raw Relay set.
// ageIncrement is monotonic time elapsed since the validated network response.
func ProjectMachines(inventory Inventory, cache *RelaySnapshot, status RelayStatus, ageIncrement time.Duration) (MachinesView, error) {
	if err := validateInventory(inventory); err != nil {
		return MachinesView{}, err
	}
	if status != RelayAvailable && status != RelayUnavailable && status != RelayClockUntrusted {
		return MachinesView{}, errors.New("unsupported Relay status")
	}
	if ageIncrement < 0 {
		return MachinesView{}, errors.New("monotonic cache age cannot be negative")
	}
	view := MachinesView{
		SchemaVersion:     1,
		ControllerID:      inventory.ControllerID,
		InfrastructureID:  inventory.InfrastructureID,
		InventoryRevision: inventory.InventoryRevision,
		RelayStatus:       status,
		Machines:          make([]ProjectedMachine, 0, len(inventory.Machines)),
	}
	cacheByID := make(map[string]RelaySnapshotMachine)
	var snapshotAt time.Time
	if cache != nil {
		if err := cache.Validate(inventory.ControllerID, inventory.InfrastructureID); err != nil {
			return MachinesView{}, err
		}
		parsed, err := parseCanonicalUTC(cache.SnapshotAt)
		if err != nil {
			return MachinesView{}, err
		}
		snapshotAt = parsed
		view.RelaySnapshotAt = cloneString(&cache.SnapshotAt)
		for _, machine := range cache.Machines {
			cacheByID[machine.MachineID] = machine
		}
	}
	for _, expected := range inventory.Machines {
		machine := ProjectedMachine{MachineID: expected.MachineID, Label: expected.Label}
		cached, found := cacheByID[expected.MachineID]
		if !found {
			view.Machines = append(view.Machines, machine)
			continue
		}
		machine.EnrollmentStatus = stringPointer(cached.EnrollmentStatus)
		if status != RelayAvailable {
			machine.ObservationStatus = stringPointer("untrusted")
		} else if cached.Observation == nil {
			machine.ObservationStatus = stringPointer("absent")
		} else {
			receivedAt, err := parseCanonicalUTC(cached.Observation.ReceivedAt)
			if err != nil || receivedAt.After(snapshotAt) {
				return MachinesView{}, errors.New("cached observation age is invalid")
			}
			age := snapshotAt.Sub(receivedAt) + ageIncrement
			if age <= 90*time.Second {
				machine.ObservationStatus = stringPointer("recent")
			} else {
				machine.ObservationStatus = stringPointer("old")
			}
		}
		if cached.Observation != nil {
			projected, err := projectObservation(cached.Observation)
			if err != nil {
				return MachinesView{}, err
			}
			machine.Observation = projected
		}
		view.Machines = append(view.Machines, machine)
	}
	return view, nil
}

func EncodeMachinesView(view MachinesView) ([]byte, error) {
	encoded, err := json.Marshal(view)
	if err != nil || len(encoded) > maxConsoleResponseBytes {
		return nil, errors.New("Console projection exceeds its response bound")
	}
	return encoded, nil
}

func projectObservation(source *RelaySnapshotObservation) (*ProjectedObservation, error) {
	observedAt, err := parseCanonicalUTC(source.ObservedAt)
	if err != nil {
		return nil, err
	}
	receivedAt, err := parseCanonicalUTC(source.ReceivedAt)
	if err != nil {
		return nil, err
	}
	difference := observedAt.Sub(receivedAt)
	if difference < 0 {
		difference = -difference
	}
	projected := &ProjectedObservation{
		Profile:             source.Profile,
		Sequence:            source.Sequence,
		ObservedAt:          source.ObservedAt,
		ReceivedAt:          source.ReceivedAt,
		ObservedTimeWarning: difference > 30*time.Second,
		Continuity:          "complete",
		Health:              source.Health,
	}
	if len(source.Gaps) == 0 {
		return projected, nil
	}
	summary := &GapSummary{
		RangeCount:    uint64(len(source.Gaps)),
		FirstSequence: source.Gaps[0].FirstSequence,
		LastSequence:  source.Gaps[len(source.Gaps)-1].LastSequence,
	}
	for _, gap := range source.Gaps {
		if math.MaxUint64-summary.DroppedCount < gap.DroppedCount {
			return nil, errors.New("gap summary overflows")
		}
		summary.DroppedCount += gap.DroppedCount
	}
	projected.Continuity = "gapped"
	projected.GapSummary = summary
	return projected, nil
}

func stringPointer(value string) *string {
	return &value
}
