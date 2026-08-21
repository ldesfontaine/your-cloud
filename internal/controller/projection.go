package controller

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

const maxAppResponseBytes = 128 * 1024

// observationFreshnessLimit is the one ageing limit this product announces.
//
// A reading is presented as current up to and including this age and as old
// beyond it, and the same limit governs every dated constat the App shows:
// the machines projected from the Relay cache and the external elements read by
// an adapter. A second threshold would put two meanings of "old" on the same
// screen, and the human would have to know which one a line is speaking.
const observationFreshnessLimit = 90 * time.Second

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
	// CommandPosition is what the App needs in order to sign the exact
	// successor of this machine's sequence, and it is two read-only fields
	// rather than one number because the second is what keeps the first
	// honest.
	CommandPosition ProjectedCommandPosition `json:"command_position"`
}

// ProjectedCommandPosition is the position this Controller can attest, and
// whether it is certain.
//
// `LastReportedSequence` is the highest position a machine itself *reported* as
// consumed — never one this Controller assumed, and never one it merely sent.
// Zero means this Controller can attest nothing, which is not the same as a
// machine that has consumed nothing, and the App says so.
//
// `Certain` is false as soon as a dispatch of that machine was launched and not
// reported: the machine may have consumed or not, and the product says that
// rather than guessing. The reprise then costs at most one wasted human
// approval — the human approves at the position this Controller knows, and if
// the machine has already gone past it, it refuses by naming its own position
// in its own sentence, which the App shows without rewriting
// (docs/architecture/TRAJET-DE-COMMANDE.md).
type ProjectedCommandPosition struct {
	LastReportedSequence uint64 `json:"last_reported_sequence"`
	Certain              bool   `json:"certain"`
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
			if age <= observationFreshnessLimit {
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

// ExternalElementsView is the declared inventory as the App reads it.
//
// It carries no capability field. The four things the product cannot do to an
// external element — update it, restore it, delete it, guarantee its state — are
// properties of what an external element is, identical for every line, and there
// is no state in which they differ. Projecting them would suggest a Controller
// could one day answer otherwise, and an App that read them instead of
// knowing them would offer a management action the day a compromised Controller
// said yes. The App announces those four absences from the context of this
// route, as it does for every other user-facing sentence.
type ExternalElementsView struct {
	SchemaVersion    int                        `json:"schema_version"`
	ControllerID     string                     `json:"controller_id"`
	InfrastructureID string                     `json:"infrastructure_id"`
	ExternalRevision uint64                     `json:"external_revision"`
	Elements         []ProjectedExternalElement `json:"elements"`
}

// ProjectedExternalElement holds the declaration, the reading and the age of the
// reading as three separate facts.
//
// `state` is the contract's own vocabulary and never a fourth value in disguise;
// `observation_status` is the independent ageing dimension, in the same three
// words the machines already use. A verified reading past the announced limit
// keeps saying `verified` and stops saying `recent`, which is exactly "the state
// is no longer presented as current" without inventing a state for it.
type ProjectedExternalElement struct {
	ElementID         string  `json:"element_id"`
	MachineID         string  `json:"machine_id"`
	Label             string  `json:"label"`
	Kind              string  `json:"kind"`
	ProbePort         int     `json:"probe_port"`
	DeclaredAt        string  `json:"declared_at"`
	State             string  `json:"state"`
	Reason            *string `json:"reason"`
	ObservedAt        *string `json:"observed_at"`
	ObservationStatus string  `json:"observation_status"`
}

// ProjectExternalElements renders the declared inventory at one instant.
//
// It infers nothing. A declaration nobody has read is `declared` and `absent`,
// not "probably fine"; a reading whose date this Controller cannot place before
// now is `old`, because an age that cannot be computed is never a reason to call
// something current.
func ProjectExternalElements(inventory ExternalInventory, now time.Time) (ExternalElementsView, error) {
	if err := validateExternalInventory(inventory); err != nil {
		return ExternalElementsView{}, err
	}
	view := ExternalElementsView{
		SchemaVersion:    1,
		ControllerID:     inventory.ControllerID,
		InfrastructureID: inventory.InfrastructureID,
		ExternalRevision: inventory.ExternalRevision,
		Elements:         make([]ProjectedExternalElement, 0, len(inventory.Elements)),
	}
	for _, element := range inventory.Elements {
		projected, err := projectExternalElement(element, now)
		if err != nil {
			return ExternalElementsView{}, err
		}
		view.Elements = append(view.Elements, projected)
	}
	return view, nil
}

// projectExternalElement is the one place a declaration becomes something the
// App reads, so a single declaration and a listing can never disagree about
// the same element.
func projectExternalElement(element ExternalElement, now time.Time) (ProjectedExternalElement, error) {
	projected := ProjectedExternalElement{
		ElementID:         element.ElementID,
		MachineID:         element.MachineID,
		Label:             element.Label,
		Kind:              element.Kind,
		ProbePort:         element.ProbePort,
		DeclaredAt:        element.DeclaredAt,
		State:             ExternalStateDeclared,
		ObservationStatus: "absent",
	}
	if element.Observation == nil {
		return projected, nil
	}
	observedAt, err := parseCanonicalUTC(element.Observation.ObservedAt)
	if err != nil {
		return ProjectedExternalElement{}, err
	}
	projected.State = element.Observation.State
	projected.ObservedAt = cloneString(&element.Observation.ObservedAt)
	if element.Observation.Reason != "" {
		projected.Reason = cloneString(&element.Observation.Reason)
	}
	projected.ObservationStatus = "old"
	if !now.Before(observedAt) && now.Sub(observedAt) <= observationFreshnessLimit {
		projected.ObservationStatus = "recent"
	}
	return projected, nil
}

func EncodeExternalElementsView(view ExternalElementsView) ([]byte, error) {
	encoded, err := json.Marshal(view)
	if err != nil || len(encoded) > maxAppResponseBytes {
		return nil, errors.New("external projection exceeds its response bound")
	}
	return encoded, nil
}

func EncodeMachinesView(view MachinesView) ([]byte, error) {
	encoded, err := json.Marshal(view)
	if err != nil || len(encoded) > maxAppResponseBytes {
		return nil, errors.New("App projection exceeds its response bound")
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
