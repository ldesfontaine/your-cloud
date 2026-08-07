package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	externalSchema        = 1
	externalFileName      = "external-elements.json"
	maxExternalStateBytes = int64(128 * 1024)
	maxExternalElements   = 128
	maxExternalLabelBytes = 64
)

// The closed vocabulary of a declaration. A kind says what the human is talking
// about and nothing else: there is no field for an image, a version, a digest or
// a command, because the product installs none of these and claiming to know
// them would be exactly the lie this inventory exists to avoid.
const (
	ExternalKindService = "external_service"
	ExternalKindPassage = "external_passage"
)

// The closed vocabulary of a reading. `declared` is not a reading — it is the
// absence of one, and it is projected rather than stored, so that no writer can
// ever store "nobody looked" as if it were a result.
const (
	ExternalStateDeclared     = "declared"
	ExternalStateVerified     = "verified"
	ExternalStateContradicted = "contradicted"
	ExternalStateUnverifiable = "unverifiable"
)

// The closed reasons an unverifiable reading may carry. They are the three
// sentences the contract names, held apart because "nothing is listening" and
// "the machine cannot be reached" are different facts and the App renders them
// as such. A reading that cannot name one of these is not unverifiable — it is
// a reading nobody wrote correctly, and it is refused.
const (
	ExternalReasonNothingListening   = "nothing_listening"
	ExternalReasonResponseTooLarge   = "response_too_large"
	ExternalReasonMachineUnreachable = "machine_unreachable"
)

// ExternalInventory is the second inventory of the Controller: the things a
// human declared, held apart from the machines the product manages.
//
// It is a separate document in a separate file, and its revision is its own. The
// managed inventory's revision is what a Console caches its machines against; a
// declaration must not disturb it, and a corrupt external document must not take
// the managed inventory down with it. Two inventories that refuse each other do
// not share one decode.
type ExternalInventory struct {
	SchemaVersion    int               `json:"schema_version"`
	ControllerID     string            `json:"controller_id"`
	InfrastructureID string            `json:"infrastructure_id"`
	ExternalRevision uint64            `json:"external_revision"`
	Elements         []ExternalElement `json:"elements"`
}

// ExternalElement is one declaration and the last reading taken against it.
//
// Five of its fields are the human's closed declaration. `element_id` and
// `declared_at` are not: the Controller mints them, because a request that could
// name its own identifier could aim a withdrawal at a declaration it never made,
// and a request that could name its own date could make a stale reading look
// fresh.
type ExternalElement struct {
	ElementID   string               `json:"element_id"`
	MachineID   string               `json:"machine_id"`
	Label       string               `json:"label"`
	Kind        string               `json:"kind"`
	ProbePort   int                  `json:"probe_port"`
	DeclaredAt  string               `json:"declared_at"`
	Observation *ExternalObservation `json:"observation"`
}

// ExternalObservation is what a reading concluded and when. The date is not
// decoration: it is the fact the App displays, and past the announced limit it
// is what stops a verified state from being presented as current.
type ExternalObservation struct {
	State      string `json:"state"`
	Reason     string `json:"reason"`
	ObservedAt string `json:"observed_at"`
}

// ExternalDeclaration carries the four values a human chooses. The machine is
// the point of view the reading will be taken from, not a property of the thing:
// declaring an element places nothing, installs nothing and attributes nothing.
type ExternalDeclaration struct {
	MachineID string
	Label     string
	Kind      string
	ProbePort int
}

// ExternalStore holds the declared inventory durably, beside the managed one.
//
// Durable rather than in memory, for the same reason the managed inventory is:
// these are lines a human typed, and an inventory that emptied itself on restart
// would make the App say "nothing is declared" about things that are. The last
// reading is stored with its declaration for the same reason — a dated constat
// that ages honestly beats forgetting that anyone ever looked.
type ExternalStore struct {
	mu               sync.Mutex
	directory        string
	path             string
	controllerID     string
	infrastructureID string
	random           io.Reader
	state            ExternalInventory
	writeState       func(ExternalInventory) error
}

// OpenExternalStore accepts a missing file as an empty inventory, because an
// installation created before this palier has none and no migration should be
// required to keep serving. A file that exists and does not decode is refused
// instead: a declaration is business state a human maintains by hand, and
// fabricating an empty inventory would silently drop it. Availability is reduced
// on purpose, exactly as the managed inventory reduces it.
func OpenExternalStore(directory, controllerID, infrastructureID string) (*ExternalStore, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return nil, err
	}
	if err := identifier.ValidateUUIDv4(controllerID); err != nil {
		return nil, fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(infrastructureID); err != nil {
		return nil, fmt.Errorf("infrastructure_id: %w", err)
	}
	path := filepath.Join(directory, externalFileName)
	store := &ExternalStore{
		directory:        directory,
		path:             path,
		controllerID:     controllerID,
		infrastructureID: infrastructureID,
		random:           rand.Reader,
		state: ExternalInventory{
			SchemaVersion:    externalSchema,
			ControllerID:     controllerID,
			InfrastructureID: infrastructureID,
			Elements:         make([]ExternalElement, 0),
		},
	}
	store.writeState = func(candidate ExternalInventory) error {
		return persistExternalInventory(directory, path, candidate)
	}
	data, err := readPrivateStateFile(path, maxExternalStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state ExternalInventory
	if err := strictjson.Decode(data, &state); err != nil {
		return nil, fmt.Errorf("decode external inventory: %w", err)
	}
	if err := validateExternalInventory(state); err != nil {
		return nil, err
	}
	if state.ControllerID != controllerID || state.InfrastructureID != infrastructureID {
		return nil, errors.New("external inventory belongs to another installation")
	}
	store.state = state
	return store, nil
}

func (store *ExternalStore) Snapshot() ExternalInventory {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneExternalInventory(store.state)
}

// Declare records one declaration and produces no plan.
//
// machineAttached is the caller's proof that the named machine is in the managed
// inventory. It is a parameter rather than a lookup because this store cannot
// see the managed inventory and must not be able to talk itself into believing a
// machine exists: there is one way in, and it carries the proof.
func (store *ExternalStore) Declare(declaration ExternalDeclaration, machineAttached bool, now time.Time) (ExternalElement, uint64, error) {
	if err := machineid.Validate(declaration.MachineID); err != nil {
		return ExternalElement{}, 0, err
	}
	if _, err := CanonicalExternalLabel(declaration.Label); err != nil {
		return ExternalElement{}, 0, err
	}
	if declaration.Kind != ExternalKindService && declaration.Kind != ExternalKindPassage {
		return ExternalElement{}, 0, errors.New("external kind is outside its closed list")
	}
	if declaration.ProbePort < 1 || declaration.ProbePort > 65535 {
		return ExternalElement{}, 0, errors.New("probe_port is outside 1..65535")
	}
	if !machineAttached {
		return ExternalElement{}, 0, errors.New("declared machine is not in the managed inventory")
	}
	declaredAt := now.UTC().Format(time.RFC3339Nano)
	if _, err := parseCanonicalUTC(declaredAt); err != nil {
		return ExternalElement{}, 0, errors.New("declaration time is not canonical UTC")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := externalSearch(store.state.Elements, declaration.MachineID, declaration.ProbePort)
	if index < len(store.state.Elements) &&
		store.state.Elements[index].MachineID == declaration.MachineID &&
		store.state.Elements[index].ProbePort == declaration.ProbePort {
		return ExternalElement{}, 0, errors.New("this machine and probe_port are already declared")
	}
	if len(store.state.Elements) >= maxExternalElements || store.state.ExternalRevision == math.MaxUint64 {
		return ExternalElement{}, 0, errors.New("external inventory capacity or revision is exhausted")
	}
	elementID, err := store.mintElementID()
	if err != nil {
		return ExternalElement{}, 0, err
	}
	element := ExternalElement{
		ElementID:  elementID,
		MachineID:  declaration.MachineID,
		Label:      declaration.Label,
		Kind:       declaration.Kind,
		ProbePort:  declaration.ProbePort,
		DeclaredAt: declaredAt,
	}
	candidate := cloneExternalInventory(store.state)
	candidate.Elements = append(candidate.Elements, ExternalElement{})
	copy(candidate.Elements[index+1:], candidate.Elements[index:])
	candidate.Elements[index] = element
	candidate.ExternalRevision++
	if err := store.commit(candidate); err != nil {
		return ExternalElement{}, 0, err
	}
	return element, candidate.ExternalRevision, nil
}

// Withdraw removes the declaration and nothing else. The thing the human named
// keeps existing, and saying so is the Console's sentence from the context of
// this route, never a text this Controller sends.
func (store *ExternalStore) Withdraw(elementID string) (ExternalElement, uint64, error) {
	if !canonicalRawURLBytes(elementID, 16) {
		return ExternalElement{}, 0, errors.New("element_id is malformed")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for index, element := range store.state.Elements {
		if element.ElementID != elementID {
			continue
		}
		if store.state.ExternalRevision == math.MaxUint64 {
			return ExternalElement{}, 0, errors.New("external revision is saturated")
		}
		candidate := cloneExternalInventory(store.state)
		candidate.Elements = append(candidate.Elements[:index], candidate.Elements[index+1:]...)
		candidate.ExternalRevision++
		if err := store.commit(candidate); err != nil {
			return ExternalElement{}, 0, err
		}
		return element, candidate.ExternalRevision, nil
	}
	return ExternalElement{}, 0, errExternalElementUnknown
}

var errExternalElementUnknown = errors.New("no declaration carries this element_id")

// RecordObservation stores what an adapter reported, and is the seam the
// read-only adapter of the next palier writes through.
//
// It is a method and not a route on purpose. The adapter reads a loopback port
// on the enrolled machine, so how its reading reaches this Controller is that
// palier's decision; opening an HTTP write path for a caller that does not exist
// yet would freeze the answer and add an authority with nobody behind it. What
// this palier fixes is the shape of the result and the rules it must satisfy.
func (store *ExternalStore) RecordObservation(elementID string, observed ExternalObservation) (ExternalElement, error) {
	if !canonicalRawURLBytes(elementID, 16) {
		return ExternalElement{}, errors.New("element_id is malformed")
	}
	if err := validateExternalObservation(observed); err != nil {
		return ExternalElement{}, err
	}
	observedAt, err := parseCanonicalUTC(observed.ObservedAt)
	if err != nil {
		return ExternalElement{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for index, element := range store.state.Elements {
		if element.ElementID != elementID {
			continue
		}
		// A reading older than the one already held is refused, for the reason the
		// Relay cache refuses a regressing snapshot: a state that can move
		// backwards in time is a state someone can rewrite by replaying an old
		// success over a fresh contradiction.
		if element.Observation != nil {
			previous, err := parseCanonicalUTC(element.Observation.ObservedAt)
			if err != nil || observedAt.Before(previous) {
				return ExternalElement{}, errors.New("external observation time cannot regress")
			}
		}
		if store.state.ExternalRevision == math.MaxUint64 {
			return ExternalElement{}, errors.New("external revision is saturated")
		}
		candidate := cloneExternalInventory(store.state)
		recorded := observed
		candidate.Elements[index].Observation = &recorded
		candidate.ExternalRevision++
		if err := store.commit(candidate); err != nil {
			return ExternalElement{}, err
		}
		return cloneExternalElement(candidate.Elements[index]), nil
	}
	return ExternalElement{}, errExternalElementUnknown
}

func (store *ExternalStore) commit(candidate ExternalInventory) error {
	if err := validateExternalInventory(candidate); err != nil {
		return err
	}
	// The identities of this document are immutable, as the Relay cache's are: no
	// mutation of the declared inventory may rename the installation it belongs to.
	if candidate.ControllerID != store.controllerID || candidate.InfrastructureID != store.infrastructureID {
		return errors.New("external inventory identities are immutable")
	}
	if err := store.writeState(candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

func (store *ExternalStore) mintElementID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(store.random, raw); err != nil {
		return "", errors.New("external element identifier cannot be minted")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// CanonicalExternalLabel holds the label to the contract's own bound: 1 to 64
// printable ASCII characters, returned exactly as written.
//
// It is deliberately not the managed label profile. A managed label names a
// thing the product owns, so it is normalised and held to a positive list of
// Unicode categories. This one is the human's own words about a thing the
// product does not own; the contract closes it on bytes rather than on taste,
// and the App does not silently improve what someone wrote. Everything the label
// could otherwise mean is neutralised where it is displayed, not here: it is
// bounded, escaped and never executed, and a label that looks like markup is
// stored and rendered as the inert text it is.
func CanonicalExternalLabel(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxExternalLabelBytes {
		return "", errors.New("external label length is outside 1..64")
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < 0x20 || raw[index] > 0x7e {
			return "", errors.New("external label carries a byte outside printable ASCII")
		}
	}
	return raw, nil
}

func validateExternalInventory(state ExternalInventory) error {
	if state.SchemaVersion != externalSchema {
		return errors.New("unsupported external inventory schema_version")
	}
	if err := identifier.ValidateUUIDv4(state.ControllerID); err != nil {
		return fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(state.InfrastructureID); err != nil {
		return fmt.Errorf("infrastructure_id: %w", err)
	}
	if state.Elements == nil || len(state.Elements) > maxExternalElements {
		return errors.New("external elements must be a present bounded array")
	}
	seen := make(map[string]struct{}, len(state.Elements))
	previousMachine := ""
	previousPort := 0
	for index, element := range state.Elements {
		if !canonicalRawURLBytes(element.ElementID, 16) {
			return errors.New("element_id is malformed")
		}
		if _, duplicated := seen[element.ElementID]; duplicated {
			return errors.New("element_id is duplicated")
		}
		seen[element.ElementID] = struct{}{}
		if err := machineid.Validate(element.MachineID); err != nil {
			return err
		}
		if canonical, err := CanonicalExternalLabel(element.Label); err != nil || canonical != element.Label {
			return errors.New("external label is not canonical")
		}
		if element.Kind != ExternalKindService && element.Kind != ExternalKindPassage {
			return errors.New("external kind is outside its closed list")
		}
		if element.ProbePort < 1 || element.ProbePort > 65535 {
			return errors.New("probe_port is outside 1..65535")
		}
		if _, err := parseCanonicalUTC(element.DeclaredAt); err != nil {
			return errors.New("declared_at is not canonical UTC")
		}
		if element.Observation != nil {
			if err := validateExternalObservation(*element.Observation); err != nil {
				return err
			}
		}
		// Sorted on the pair that must be unique, so that the uniqueness of a
		// machine's probe port is a property of the document rather than a check
		// somebody has to remember to run.
		if index > 0 && !externalKeyLess(previousMachine, previousPort, element.MachineID, element.ProbePort) {
			return errors.New("external elements must be unique and sorted by machine and port")
		}
		previousMachine, previousPort = element.MachineID, element.ProbePort
	}
	return nil
}

func validateExternalObservation(observed ExternalObservation) error {
	switch observed.State {
	case ExternalStateVerified, ExternalStateContradicted:
		if observed.Reason != "" {
			return errors.New("only an unverifiable reading carries a reason")
		}
	case ExternalStateUnverifiable:
		switch observed.Reason {
		case ExternalReasonNothingListening, ExternalReasonResponseTooLarge, ExternalReasonMachineUnreachable:
		default:
			return errors.New("an unverifiable reading must name a reason of the closed list")
		}
	default:
		return errors.New("external observation state is outside its closed list")
	}
	if _, err := parseCanonicalUTC(observed.ObservedAt); err != nil {
		return errors.New("observed_at is not canonical UTC")
	}
	return nil
}

func externalKeyLess(leftMachine string, leftPort int, rightMachine string, rightPort int) bool {
	if leftMachine != rightMachine {
		return leftMachine < rightMachine
	}
	return leftPort < rightPort
}

func externalSearch(elements []ExternalElement, machineID string, probePort int) int {
	return sort.Search(len(elements), func(index int) bool {
		return !externalKeyLess(elements[index].MachineID, elements[index].ProbePort, machineID, probePort)
	})
}

func persistExternalInventory(directory, path string, candidate ExternalInventory) error {
	if err := validateExternalInventory(candidate); err != nil {
		return err
	}
	encoded, err := json.Marshal(candidate)
	if err != nil || int64(len(encoded)) > maxExternalStateBytes {
		return errors.New("external inventory cannot be encoded within its bound")
	}
	return writePrivateStateFile(directory, path, ".external-elements-", encoded)
}

func cloneExternalInventory(state ExternalInventory) ExternalInventory {
	result := state
	result.Elements = make([]ExternalElement, len(state.Elements))
	for index, element := range state.Elements {
		result.Elements[index] = cloneExternalElement(element)
	}
	return result
}

func cloneExternalElement(element ExternalElement) ExternalElement {
	result := element
	if element.Observation != nil {
		observed := *element.Observation
		result.Observation = &observed
	}
	return result
}
