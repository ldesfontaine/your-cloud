package controller

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	maxRelaySnapshotBytes = 2 * 1024 * 1024
	maxRelaySnapshotGaps  = 8_192
)

type RelaySnapshot struct {
	SchemaVersion    int                    `json:"schema_version"`
	InfrastructureID string                 `json:"infrastructure_id"`
	ControllerID     string                 `json:"controller_id"`
	SnapshotAt       string                 `json:"snapshot_at"`
	Machines         []RelaySnapshotMachine `json:"machines"`
}

type RelaySnapshotMachine struct {
	MachineID        string                    `json:"machine_id"`
	EnrollmentStatus string                    `json:"enrollment_status"`
	Observation      *RelaySnapshotObservation `json:"observation"`
}

type RelaySnapshotObservation struct {
	SchemaVersion int                    `json:"schema_version"`
	MachineID     string                 `json:"machine_id"`
	DaemonVersion string                 `json:"daemon_version"`
	Profile       string                 `json:"profile"`
	Sequence      uint64                 `json:"sequence"`
	ObservedAt    string                 `json:"observed_at"`
	ReceivedAt    string                 `json:"received_at"`
	Gaps          []observation.Gap      `json:"gaps"`
	Health        observation.HostHealth `json:"health"`
}

func DecodeRelaySnapshot(data []byte, controllerID, infrastructureID string) (RelaySnapshot, error) {
	if len(data) == 0 || len(data) > maxRelaySnapshotBytes {
		return RelaySnapshot{}, errors.New("Relay snapshot size is outside its bound")
	}
	var snapshot RelaySnapshot
	if err := strictjson.Decode(data, &snapshot); err != nil {
		return RelaySnapshot{}, fmt.Errorf("decode Relay snapshot: %w", err)
	}
	if err := snapshot.Validate(controllerID, infrastructureID); err != nil {
		return RelaySnapshot{}, err
	}
	return snapshot, nil
}

func (snapshot RelaySnapshot) Validate(controllerID, infrastructureID string) error {
	if snapshot.SchemaVersion != 1 {
		return errors.New("unsupported Relay snapshot schema_version")
	}
	if err := identifier.ValidateUUIDv4(snapshot.ControllerID); err != nil || snapshot.ControllerID != controllerID {
		return errors.New("Relay snapshot controller_id is invalid or crossed")
	}
	if err := identifier.ValidateUUIDv4(snapshot.InfrastructureID); err != nil || snapshot.InfrastructureID != infrastructureID {
		return errors.New("Relay snapshot infrastructure_id is invalid or crossed")
	}
	snapshotAt, err := parseCanonicalUTC(snapshot.SnapshotAt)
	if err != nil {
		return errors.New("Relay snapshot timestamp is not canonical UTC")
	}
	if snapshot.Machines == nil || len(snapshot.Machines) > maxMachines {
		return errors.New("Relay snapshot machines must be a present bounded array")
	}
	previousMachine := ""
	totalGaps := 0
	for index := range snapshot.Machines {
		machine := snapshot.Machines[index]
		if err := machineid.Validate(machine.MachineID); err != nil || machine.MachineID <= previousMachine {
			return errors.New("Relay snapshot machines are invalid, duplicated or unsorted")
		}
		if machine.EnrollmentStatus != "active" && machine.EnrollmentStatus != "revoked" {
			return errors.New("Relay snapshot enrollment status is invalid")
		}
		if machine.Observation != nil {
			if err := validateSnapshotObservation(machine.MachineID, snapshotAt, machine.Observation); err != nil {
				return fmt.Errorf("Relay snapshot machine %q: %w", machine.MachineID, err)
			}
			totalGaps += len(machine.Observation.Gaps)
			if totalGaps > maxRelaySnapshotGaps {
				return errors.New("Relay snapshot contains too many gaps")
			}
		}
		previousMachine = machine.MachineID
	}
	return nil
}

func validateSnapshotObservation(machineID string, snapshotAt time.Time, candidate *RelaySnapshotObservation) error {
	if candidate.SchemaVersion != observation.SchemaVersion || candidate.MachineID != machineID {
		return errors.New("observation identity or schema is invalid")
	}
	if candidate.Gaps == nil {
		return errors.New("observation gaps must be a present array")
	}
	envelope := observation.Envelope{
		SchemaVersion: candidate.SchemaVersion,
		MachineID:     candidate.MachineID,
		DaemonVersion: candidate.DaemonVersion,
		Profile:       candidate.Profile,
		Sequence:      candidate.Sequence,
		ObservedAt:    candidate.ObservedAt,
		Health:        candidate.Health,
		Gaps:          candidate.Gaps,
	}
	if err := envelope.Validate(); err != nil {
		return err
	}
	if _, err := parseCanonicalUTC(candidate.ObservedAt); err != nil {
		return errors.New("observed_at is not canonical UTC")
	}
	receivedAt, err := parseCanonicalUTC(candidate.ReceivedAt)
	if err != nil || receivedAt.After(snapshotAt) {
		return errors.New("received_at is invalid or later than snapshot_at")
	}
	for index, gap := range candidate.Gaps {
		if _, err := parseCanonicalUTC(gap.FirstObservedAt); err != nil {
			return errors.New("gap first_observed_at is not canonical UTC")
		}
		if _, err := parseCanonicalUTC(gap.LastObservedAt); err != nil {
			return errors.New("gap last_observed_at is not canonical UTC")
		}
		if index > 0 && candidate.Gaps[index-1].LastSequence+1 >= gap.FirstSequence {
			return errors.New("Relay snapshot gaps must be merged and non-adjacent")
		}
	}
	return nil
}

func parseCanonicalUTC(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("timestamp must use Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp must use canonical RFC3339Nano UTC")
	}
	return parsed, nil
}

func allowsSnapshotTransition(current, candidate RelaySnapshot) error {
	if current.ControllerID != candidate.ControllerID || current.InfrastructureID != candidate.InfrastructureID {
		return errors.New("Relay cache identities are immutable")
	}
	currentAt, currentErr := parseCanonicalUTC(current.SnapshotAt)
	candidateAt, candidateErr := parseCanonicalUTC(candidate.SnapshotAt)
	if currentErr != nil || candidateErr != nil || candidateAt.Before(currentAt) {
		return errors.New("Relay cache snapshot time cannot regress")
	}
	currentByID := make(map[string]RelaySnapshotMachine, len(current.Machines))
	for _, machine := range current.Machines {
		currentByID[machine.MachineID] = machine
	}
	for _, next := range candidate.Machines {
		previous, existed := currentByID[next.MachineID]
		if !existed {
			continue
		}
		delete(currentByID, next.MachineID)
		if previous.EnrollmentStatus == "revoked" && next.EnrollmentStatus != "revoked" {
			return fmt.Errorf("machine %q cannot be reactivated", next.MachineID)
		}
		if previous.Observation == nil {
			continue
		}
		if next.Observation == nil {
			return fmt.Errorf("machine %q cannot lose its observation", next.MachineID)
		}
		switch {
		case next.Observation.Sequence < previous.Observation.Sequence:
			return fmt.Errorf("machine %q observation sequence regressed", next.MachineID)
		case next.Observation.Sequence == previous.Observation.Sequence && !reflect.DeepEqual(next.Observation, previous.Observation):
			return fmt.Errorf("machine %q reused a sequence with different content", next.MachineID)
		case next.Observation.Sequence > previous.Observation.Sequence && !gapsPreserved(previous.Observation.Gaps, next.Observation.Gaps):
			return fmt.Errorf("machine %q removed a known gap", next.MachineID)
		}
	}
	if len(currentByID) != 0 {
		missing := make([]string, 0, len(currentByID))
		for machineID := range currentByID {
			missing = append(missing, machineID)
		}
		sort.Strings(missing)
		return fmt.Errorf("Relay snapshot omitted known machine %q", missing[0])
	}
	return nil
}

func gapsPreserved(previous, next []observation.Gap) bool {
	index := 0
	for _, known := range previous {
		for index < len(next) && next[index].LastSequence < known.FirstSequence {
			index++
		}
		if index == len(next) || next[index].FirstSequence > known.FirstSequence || next[index].LastSequence < known.LastSequence {
			return false
		}
	}
	return true
}
