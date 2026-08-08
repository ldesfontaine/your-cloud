package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	serviceDefinitionSchema   = 1
	serviceDefinitionFileName = "service-definitions.json"

	// maxServiceDefinitionStateBytes bounds the document on the disk. It is not
	// the bound that decides how many definitions may be frozen — the listing
	// does, below — it is the fail-closed bound of a file this Controller reads
	// at every start, and it sits above what the listing can ever hold so that
	// the file bound is never the thing a human runs into.
	maxServiceDefinitionStateBytes = int64(256 * 1024)

	// maxFrozenServiceDefinitions bounds how many revisions this inventory holds,
	// all slugs taken together. Nothing is ever erased here, so a bound is the
	// only thing standing between an inventory that grows and a Controller whose
	// state file grows without end; it is the bound of the declared inventory,
	// contestable at the first real need proved and never an approvable value.
	maxFrozenServiceDefinitions = 128
)

// errServiceDefinitionRefused marks the one family of failures that is the
// caller's document rather than this Controller's state: bytes that are not a
// definition of the contract, or a digest that does not name them. The route
// answers it with the existing `400 invalid_request`, and everything else with
// the existing `409 state_conflict`, so this palier adds no error code.
var errServiceDefinitionRefused = errors.New("the submitted definition is outside the contract")

// ServiceDefinitionInventory is the third durable document of the Controller:
// the definitions a human wrote and this Controller froze.
//
// It is a separate document in a separate file with a revision of its own, for
// the reason the declared inventory is: freezing a definition must not disturb
// the revision a Console caches its machines against, and a corrupt document
// here must not take the managed inventory down with it.
//
// Nothing in it describes an effect. There is no machine, no account, no host
// path, no port of a host and no operation: a definition is an inventory of
// infrastructure the product does not act on until a plan a human signs pins one
// by its digest.
type ServiceDefinitionInventory struct {
	SchemaVersion      int                       `json:"schema_version"`
	ControllerID       string                    `json:"controller_id"`
	InfrastructureID   string                    `json:"infrastructure_id"`
	DefinitionRevision uint64                    `json:"definition_revision"`
	Definitions        []FrozenServiceDefinition `json:"definitions"`
}

// FrozenServiceDefinition is one revision, held as the exact canonical bytes it
// was frozen as and the digest those bytes hash to.
//
// The document travels and rests as a string rather than as a nested object, so
// that the bytes a human approved, the bytes a plan pins and the bytes an
// Auxiliary later receives are one thing rather than three encodings that happen
// to agree. `slug` is not a second truth beside the document: every commit
// requires it to be the slug the document itself declares, so the field is a key
// this inventory sorts and groups on and never something it could say alone.
//
// `frozen_at` is minted by this Controller and is not a field of any request. A
// submission that could name its own date could make one revision look like the
// successor of another it preceded, and which revision is the latest under a
// slug is exactly what a human reads this date for.
type FrozenServiceDefinition struct {
	Slug     string `json:"slug"`
	Digest   string `json:"definition_sha256"`
	Document string `json:"definition_document"`
	FrozenAt string `json:"frozen_at"`
}

// ServiceDefinitionsView is what the Console receives when it reads the frozen
// definitions: every one of them, as its exact canonical bytes and its digest.
type ServiceDefinitionsView struct {
	SchemaVersion      int                      `json:"schema_version"`
	ControllerID       string                   `json:"controller_id"`
	InfrastructureID   string                   `json:"infrastructure_id"`
	DefinitionRevision uint64                   `json:"definition_revision"`
	Definitions        []ServiceDefinitionEntry `json:"definitions"`
}

// ServiceDefinitionEntry is one frozen definition as the Console reads it. It is
// the same shape whether it arrives alone as the answer to a freeze or inside a
// listing, so that what a human sees after freezing and what they see afterwards
// are the same object.
type ServiceDefinitionEntry struct {
	Slug               string `json:"slug"`
	DefinitionDocument string `json:"definition_document"`
	DefinitionSHA256   string `json:"definition_sha256"`
	FrozenAt           string `json:"frozen_at"`
}

// ServiceDefinitionStore holds the frozen definitions durably.
//
// Durable rather than in memory, and for a stronger reason than the declared
// inventory has: a plan pins a definition by its digest, so a definition this
// Controller forgot across a restart would be a plan nobody could ever build
// again and an instance nobody could read the revision of. Nothing here is ever
// replaced or removed — a revision is a new freeze that coexists with all the
// previous ones — so the only write this store performs is an insertion.
type ServiceDefinitionStore struct {
	mu               sync.Mutex
	controllerID     string
	infrastructureID string
	state            ServiceDefinitionInventory
	writeState       func(ServiceDefinitionInventory) error
}

// OpenServiceDefinitionStore accepts a missing file as an empty inventory,
// because an installation created before this palier has none and no migration
// should be required to keep serving. A file that exists and does not decode, or
// that holds a definition whose bytes are not the definition its digest names, is
// refused instead: these are documents plans pin, and fabricating an empty
// inventory would silently drop what a human froze. Availability is reduced on
// purpose, exactly as the two inventories before it reduce it.
func OpenServiceDefinitionStore(directory, controllerID, infrastructureID string) (*ServiceDefinitionStore, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return nil, err
	}
	if err := identifier.ValidateUUIDv4(controllerID); err != nil {
		return nil, fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(infrastructureID); err != nil {
		return nil, fmt.Errorf("infrastructure_id: %w", err)
	}
	path := filepath.Join(directory, serviceDefinitionFileName)
	store := &ServiceDefinitionStore{
		controllerID:     controllerID,
		infrastructureID: infrastructureID,
		state: ServiceDefinitionInventory{
			SchemaVersion:    serviceDefinitionSchema,
			ControllerID:     controllerID,
			InfrastructureID: infrastructureID,
			Definitions:      make([]FrozenServiceDefinition, 0),
		},
	}
	store.writeState = func(candidate ServiceDefinitionInventory) error {
		return persistServiceDefinitions(directory, path, candidate)
	}
	data, err := readPrivateStateFile(path, maxServiceDefinitionStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state ServiceDefinitionInventory
	if err := strictjson.Decode(data, &state); err != nil {
		return nil, fmt.Errorf("decode frozen service definitions: %w", err)
	}
	if err := validateServiceDefinitionInventory(state); err != nil {
		return nil, err
	}
	if state.ControllerID != controllerID || state.InfrastructureID != infrastructureID {
		return nil, errors.New("frozen service definitions belong to another installation")
	}
	store.state = state
	return store, nil
}

func (store *ServiceDefinitionStore) Snapshot() ServiceDefinitionInventory {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneServiceDefinitionInventory(store.state)
}

// Freeze validates, canonises, hashes and freezes one definition, and does
// nothing else at all.
//
// It creates no resource, produces no plan and contacts no machine — it cannot,
// having been given neither a machine nor anything to reach one with. The whole
// of its effect is one insertion into one file.
//
// Freezing the same bytes twice is the same revision and never a second one. The
// digest is the identity of a definition everywhere else in this product — a plan
// pins it, an Auxiliary re-derives it, an instance shows it — so two entries
// under one digest would be one revision the inventory counts twice, and the
// second freeze would move a revision counter while nothing changed. A repeated
// freeze is therefore reported as the definition already held, with the
// inventory's revision left exactly where it was; the caller learns which of the
// two happened from the returned flag, and nothing is erased in either case.
//
// The received bytes are held against the announced digest before anything else,
// by the one function that does that on both sides of the product. What is frozen
// afterwards is this Controller's own canonical spelling of the parsed
// definition, never the bytes as they arrived: a transport that reindented the
// document freezes the same revision as one that did not, which is exactly what
// makes the idempotence above a property of the definition rather than of the
// transport.
func (store *ServiceDefinitionStore) Freeze(
	document []byte, announcedSHA256 string, now time.Time,
) (FrozenServiceDefinition, uint64, bool, error) {
	parsed, err := servicedefinition.Verify(document, announcedSHA256)
	if err != nil {
		return FrozenServiceDefinition{}, 0, false, fmt.Errorf("%w: %w", errServiceDefinitionRefused, err)
	}
	canonical, err := parsed.Encode()
	if err != nil {
		return FrozenServiceDefinition{}, 0, false, fmt.Errorf("%w: %w", errServiceDefinitionRefused, err)
	}
	// The digest kept is the one rebuilt from the parsed fields, not the string the
	// caller wrote. The two are equal by the time this line runs — the verification
	// above refuses the submission otherwise — and taking it from the fields anyway
	// is what keeps the name of a revision a value this Controller computes rather
	// than a value it was handed and checked.
	digest, err := parsed.SHA256()
	if err != nil {
		return FrozenServiceDefinition{}, 0, false, fmt.Errorf("%w: %w", errServiceDefinitionRefused, err)
	}
	frozenAt := now.UTC().Format(time.RFC3339Nano)
	if _, err := parseCanonicalUTC(frozenAt); err != nil {
		return FrozenServiceDefinition{}, 0, false, errors.New("freeze time is not canonical UTC")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	index := serviceDefinitionSearch(store.state.Definitions, parsed.Slug, digest)
	if index < len(store.state.Definitions) &&
		store.state.Definitions[index].Slug == parsed.Slug &&
		store.state.Definitions[index].Digest == digest {
		held := store.state.Definitions[index]
		// A digest already held under other bytes is refused rather than
		// overwritten. It cannot happen while SHA-256 holds, and that is precisely
		// why the branch exists: the day it did happen, the one thing this store
		// must not do is replace bytes a plan may already pin.
		if held.Document != string(canonical) {
			return FrozenServiceDefinition{}, 0, false,
				errors.New("another definition is already frozen under this digest")
		}
		return held, store.state.DefinitionRevision, false, nil
	}
	if len(store.state.Definitions) >= maxFrozenServiceDefinitions ||
		store.state.DefinitionRevision == math.MaxUint64 {
		return FrozenServiceDefinition{}, 0, false,
			errors.New("frozen service definition capacity or revision is exhausted")
	}
	frozen := FrozenServiceDefinition{
		Slug:     parsed.Slug,
		Digest:   digest,
		Document: string(canonical),
		FrozenAt: frozenAt,
	}
	candidate := cloneServiceDefinitionInventory(store.state)
	candidate.Definitions = append(candidate.Definitions, FrozenServiceDefinition{})
	copy(candidate.Definitions[index+1:], candidate.Definitions[index:])
	candidate.Definitions[index] = frozen
	candidate.DefinitionRevision++
	if err := store.commit(candidate); err != nil {
		return FrozenServiceDefinition{}, 0, false, err
	}
	return frozen, candidate.DefinitionRevision, true, nil
}

func (store *ServiceDefinitionStore) commit(candidate ServiceDefinitionInventory) error {
	if err := validateServiceDefinitionInventory(candidate); err != nil {
		return err
	}
	// The identities of this document are immutable, as the two inventories before
	// it are: no freeze may rename the installation the definitions belong to.
	if candidate.ControllerID != store.controllerID || candidate.InfrastructureID != store.infrastructureID {
		return errors.New("frozen service definition identities are immutable")
	}
	// A freeze that would make the listing unencodable is refused here, at the
	// freeze. The contract requires the reading to omit no definition, so the
	// alternative — accepting the freeze and truncating the listing afterwards —
	// is the one behaviour this route may never have: a definition a human froze
	// and can no longer read is worse than a freeze that was refused out loud.
	if _, err := EncodeServiceDefinitionsView(serviceDefinitionsView(candidate)); err != nil {
		return err
	}
	if err := store.writeState(candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

// ProjectServiceDefinitions renders the frozen definitions for the Console.
//
// It projects nothing and computes nothing: the bytes and the digest of a
// revision are what was frozen, and this reading hands them over unchanged. The
// validation in front of it is what makes that sentence true rather than hopeful
// — a document that no longer hashes to the digest beside it is refused as a
// reading, and never served as one.
func ProjectServiceDefinitions(inventory ServiceDefinitionInventory) (ServiceDefinitionsView, error) {
	if err := validateServiceDefinitionInventory(inventory); err != nil {
		return ServiceDefinitionsView{}, err
	}
	return serviceDefinitionsView(inventory), nil
}

// serviceDefinitionsView is the one place a frozen definition becomes something
// the Console reads, so that a single freeze and a listing can never disagree
// about the same revision. It assumes a validated inventory, which is why it is
// private: the exported reading above validates, and the commit path has already
// validated the candidate it hands over.
func serviceDefinitionsView(inventory ServiceDefinitionInventory) ServiceDefinitionsView {
	view := ServiceDefinitionsView{
		SchemaVersion:      1,
		ControllerID:       inventory.ControllerID,
		InfrastructureID:   inventory.InfrastructureID,
		DefinitionRevision: inventory.DefinitionRevision,
		Definitions:        make([]ServiceDefinitionEntry, 0, len(inventory.Definitions)),
	}
	for _, definition := range inventory.Definitions {
		view.Definitions = append(view.Definitions, serviceDefinitionEntry(definition))
	}
	return view
}

func serviceDefinitionEntry(definition FrozenServiceDefinition) ServiceDefinitionEntry {
	return ServiceDefinitionEntry{
		Slug:               definition.Slug,
		DefinitionDocument: definition.Document,
		DefinitionSHA256:   definition.Digest,
		FrozenAt:           definition.FrozenAt,
	}
}

func EncodeServiceDefinitionsView(view ServiceDefinitionsView) ([]byte, error) {
	encoded, err := json.Marshal(view)
	if err != nil || len(encoded) > maxConsoleResponseBytes {
		return nil, errors.New("frozen service definitions exceed their response bound")
	}
	return encoded, nil
}

// validateServiceDefinitionInventory holds the whole document against the
// contract, entry by entry, at every read of the file and at every commit.
//
// Every entry is verified rather than trusted: the bytes are held against the
// digest beside them by the same function the Console and the Auxiliary use, and
// the bytes are required to be the canonical spelling of what they parse to. That
// is what makes "re-reading a digest returns exactly the bytes frozen under it" a
// property of the document rather than a promise of the code that wrote it, and
// it is what a Controller restarting on a file someone edited runs into before it
// serves a single definition.
func validateServiceDefinitionInventory(state ServiceDefinitionInventory) error {
	if state.SchemaVersion != serviceDefinitionSchema {
		return errors.New("unsupported frozen service definition schema_version")
	}
	if err := identifier.ValidateUUIDv4(state.ControllerID); err != nil {
		return fmt.Errorf("controller_id: %w", err)
	}
	if err := identifier.ValidateUUIDv4(state.InfrastructureID); err != nil {
		return fmt.Errorf("infrastructure_id: %w", err)
	}
	if state.Definitions == nil || len(state.Definitions) > maxFrozenServiceDefinitions {
		return errors.New("frozen service definitions must be a present bounded array")
	}
	previousSlug, previousDigest := "", ""
	for index, definition := range state.Definitions {
		parsed, err := servicedefinition.Verify([]byte(definition.Document), definition.Digest)
		if err != nil {
			return fmt.Errorf("frozen service definition %d: %w", index, err)
		}
		if parsed.Slug != definition.Slug {
			return errors.New("a frozen service definition is filed under a slug its document does not declare")
		}
		canonical, err := parsed.Encode()
		if err != nil || string(canonical) != definition.Document {
			return errors.New("a frozen service definition is not held as its canonical bytes")
		}
		if _, err := parseCanonicalUTC(definition.FrozenAt); err != nil {
			return errors.New("frozen_at is not canonical UTC")
		}
		// Sorted on the pair a revision is unique on, so that uniqueness is a
		// property of the document rather than a check somebody has to remember to
		// run. The slug leads because that is how the Console groups revisions; the
		// digest decides between the revisions of one slug, and no two entries may
		// share it — two entries under one digest would be one revision the
		// inventory counts twice.
		if index > 0 && !serviceDefinitionKeyLess(previousSlug, previousDigest, definition.Slug, definition.Digest) {
			return errors.New("frozen service definitions must be unique and sorted by slug and digest")
		}
		previousSlug, previousDigest = definition.Slug, definition.Digest
	}
	return nil
}

func serviceDefinitionKeyLess(leftSlug, leftDigest, rightSlug, rightDigest string) bool {
	if leftSlug != rightSlug {
		return leftSlug < rightSlug
	}
	return leftDigest < rightDigest
}

func serviceDefinitionSearch(definitions []FrozenServiceDefinition, slug, digest string) int {
	return sort.Search(len(definitions), func(index int) bool {
		return !serviceDefinitionKeyLess(definitions[index].Slug, definitions[index].Digest, slug, digest)
	})
}

func persistServiceDefinitions(directory, path string, candidate ServiceDefinitionInventory) error {
	if err := validateServiceDefinitionInventory(candidate); err != nil {
		return err
	}
	encoded, err := json.Marshal(candidate)
	if err != nil || int64(len(encoded)) > maxServiceDefinitionStateBytes {
		return errors.New("frozen service definitions cannot be encoded within their bound")
	}
	return writePrivateStateFile(directory, path, ".service-definitions-", encoded)
}

func cloneServiceDefinitionInventory(state ServiceDefinitionInventory) ServiceDefinitionInventory {
	result := state
	result.Definitions = make([]FrozenServiceDefinition, len(state.Definitions))
	copy(result.Definitions, state.Definitions)
	return result
}
