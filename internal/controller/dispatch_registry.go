package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/ldesfontaine/your-cloud/internal/identifier"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// The dispatch registry answers one question the Controller alone must answer:
// have these signed bytes already been launched once? It is not a copy of a
// machine's anti-replay state — that one lives beside the effects and stays
// the authority — but without this registry a Controller restarting between
// reception and launch would legitimately relaunch the same human intention.
// An approval is a one-shot authority on the Controller too
// (docs/architecture/TRAJET-DE-COMMANDE.md).
//
// The registry is indexed by the digest of the signed approval's exact bytes,
// never by the sequence number: replaying the same bytes is refused, while
// re-approving the same number after a launch that reached nothing stays
// possible — and that is exactly what a human must be able to do when the
// machine consumed nothing.
const (
	dispatchRegistrySchema = 1

	// maxDispatchMachineSentenceBytes bounds what a machine's own refusal may
	// leave in this document, and it is the same bound the launch reads off
	// the error channel (#126) so the two cannot drift: what is read is what
	// can be stored. It is derived from a measurement of the sentences the
	// Auxiliary can actually write — the widest literal refusal in
	// `internal/approval` and `internal/auxiliary` is 103 bytes, and a wrapped
	// chain carrying one system error that names a path under the product's
	// own layout measures under 400 — taken to the power of two above. The
	// sentence is kept verbatim and never paraphrased, so this is a bound on
	// what is read, never a licence to rewrite what was read.
	maxDispatchMachineSentenceBytes = 512

	// maxDispatchObservationBytes bounds the Controller's own account of its
	// own attempt. This one the product writes itself, from a closed set of
	// sentences, and the widest of them measures 94 bytes; the bound sits at
	// the power of two above with room for the launch refusals #126 adds.
	maxDispatchObservationBytes = 256

	// maxDispatchRecordsPerMachine bounds the history one machine keeps.
	//
	// It is derived from a measurement of the product's own proofs rather than
	// from a round number: a machine holds one command at a time, and the
	// busiest single machine of the `v0.1.1` proof crosses about thirty
	// dispatches in one run (`play-removal` alone drives eleven, `play-refusals`
	// eight, `play-lifecycle` seven). A history that dropped half of what one
	// proof produced would be a history `#128` could not read back. Thirty-two
	// is the power of two above that measurement.
	//
	// Records past the bound leave the registry oldest-first, and never a
	// non-terminal one — an open dispatch cannot be forgotten. The named limit
	// is that a machine which crosses the bound loses its oldest dispatches
	// from the history the Console reads; the effects stay on the machine, and
	// an instance whose last reported dispatch has left the history is shown
	// with its revision unknown rather than with an invented one. Raising this
	// number is a measurement away and changes no format.
	maxDispatchRecordsPerMachine = 32

	// maxDispatchStateBytes bounds the whole registry file, and it is derived
	// from the two bounds above rather than chosen: 64 machines — the
	// inventory's own bound — × 32 records × a record measured at 2 220 bytes
	// in its worst case (685 bytes of identifiers, digests, states and stamps,
	// plus the two free-text fields at their bound, each doubled because JSON
	// escapes the quote and the backslash), plus the head, comes to 4 546 707
	// bytes. This is the power of two above, so a legitimate history that the
	// trimming keeps can never be refused by the file's own bound. The test
	// suite builds that maximal registry and encodes it rather than trusting
	// this arithmetic.
	maxDispatchStateBytes = int64(8 * 1024 * 1024)
)

// Dispatch states, stored in English like every stored word of this package;
// the Console renders them as the contract's sentences. Their meaning is the
// contract's table, and the honest default matters most: a record found
// `in_flight` at startup becomes `launched_unreported`, because after a cut
// the Controller cannot tell "nothing left" from "something left" and says
// the weaker of the two.
const (
	// DispatchInFlight: the record is durably written; the rest is happening.
	DispatchInFlight = "in_flight"
	// DispatchNotLaunched: the connection failed before the first byte of the
	// wrapper, and the Controller observed it. No effect exists anywhere.
	DispatchNotLaunched = "not_launched"
	// DispatchMachineRefused: the machine answered a refusal and no report;
	// it changed nothing, and its sentence is kept verbatim.
	DispatchMachineRefused = "machine_refused"
	// DispatchReported: a valid report was read; it carries the outcome.
	DispatchReported = "reported"
	// DispatchLaunchedUnreported: everything else. Never retried, never
	// resolved by anything but a human.
	DispatchLaunchedUnreported = "launched_unreported"
)

var canonicalDispatchDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DispatchRecord is one launch of one signed approval, and nothing else. The
// machine's own sentence, when one exists, is stored exactly as received —
// bounded upstream — and never paraphrased.
type DispatchRecord struct {
	ApprovalSHA256 string `json:"approval_sha256"`
	MachineID      string `json:"machine_id"`
	Operation      string `json:"operation"`
	ApprovalEpoch  uint64 `json:"approval_epoch"`
	Sequence       uint64 `json:"sequence"`
	PlanSHA256     string `json:"plan_sha256"`
	RollbackSHA256 string `json:"rollback_sha256"`
	State          string `json:"state"`
	// AcceptedAtUnix is the instant the record was durably written, before
	// any connection; the terminal instant is zero while the record is open.
	AcceptedAtUnix uint64 `json:"accepted_at_unix"`
	FinishedAtUnix uint64 `json:"finished_at_unix"`
	// MachineSentence is what the machine wrote on its error channel when it
	// refused, verbatim and bounded; empty otherwise.
	MachineSentence string `json:"machine_sentence"`
	// ControllerObservation is what this Controller saw when the machine said
	// nothing — a connection that failed, a channel that closed. The two are
	// kept apart deliberately: one is a sentence the product did not write and
	// never rewrites, the other is the product's own account of its own
	// attempt, and a reader must be able to tell which is which.
	ControllerObservation string `json:"controller_observation"`
	// ReportedChanged and ReportedOutcome are filled by a valid report only
	// (#127); they stay empty until one is ingested.
	ReportedChanged bool   `json:"reported_changed"`
	ReportedOutcome string `json:"reported_outcome"`
}

func (record *DispatchRecord) terminal() bool {
	return record.State != DispatchInFlight
}

// DispatchRegistry is the durable document: append-oriented, bounded, owned by
// the Controller's service account like every private state of this package.
type DispatchRegistry struct {
	SchemaVersion    int              `json:"schema_version"`
	ControllerID     string           `json:"controller_id"`
	InfrastructureID string           `json:"infrastructure_id"`
	Records          []DispatchRecord `json:"records"`
}

// DispatchRegistryStore serialises every mutation behind one mutex and never
// lets the in-memory state advance before the disk, the same discipline as
// the inventory it is modelled on.
type DispatchRegistryStore struct {
	mu         sync.Mutex
	directory  string
	path       string
	state      DispatchRegistry
	writeState func(DispatchRegistry) error
}

const dispatchRegistryFile = "dispatches.json"

// OpenDispatchRegistryStore reads the registry back and settles its honesty
// before the Controller serves anything: a record found `in_flight` belongs
// to a life that was cut between reception and its terminal state, and it
// becomes `launched_unreported` durably, here, first. This is the one store
// of the package that mutates at open, and the contract is why: after a cut
// the Controller cannot tell "nothing left" from "something left", and a
// state that waited for the first request to say so would have served
// reads that lied.
func OpenDispatchRegistryStore(directory, controllerID, infrastructureID string) (*DispatchRegistryStore, error) {
	if err := validatePrivateStateDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, dispatchRegistryFile)
	var state DispatchRegistry
	data, err := readPrivateStateFile(path, maxDispatchStateBytes)
	switch {
	case err == nil:
		if err := strictjson.Decode(data, &state); err != nil {
			return nil, fmt.Errorf("dispatch registry: %w", err)
		}
		if err := validateDispatchRegistry(state); err != nil {
			return nil, fmt.Errorf("dispatch registry: %w", err)
		}
		if state.ControllerID != controllerID || state.InfrastructureID != infrastructureID {
			return nil, errors.New("dispatch registry belongs to another installation")
		}
	case errors.Is(err, os.ErrNotExist):
		// A Controller that never launched anything holds no registry yet:
		// the empty document is written durably before anything is served,
		// the same upgrade path the external and definition inventories
		// follow. A file that exists but cannot be read stays an error — an
		// unreadable registry hides spent authorities and inventing an empty
		// one would invent that nothing was ever launched.
		state = DispatchRegistry{
			SchemaVersion:    dispatchRegistrySchema,
			ControllerID:     controllerID,
			InfrastructureID: infrastructureID,
			Records:          []DispatchRecord{},
		}
		if err := persistDispatchRegistry(directory, path, state); err != nil {
			return nil, fmt.Errorf("dispatch registry: %w", err)
		}
	default:
		return nil, fmt.Errorf("dispatch registry: %w", err)
	}
	requalified := false
	for index := range state.Records {
		if state.Records[index].State == DispatchInFlight {
			state.Records[index].State = DispatchLaunchedUnreported
			requalified = true
		}
	}
	if requalified {
		if err := persistDispatchRegistry(directory, path, state); err != nil {
			return nil, fmt.Errorf("dispatch registry: %w", err)
		}
	}
	return newDispatchRegistryStore(directory, path, state), nil
}

func newDispatchRegistryStore(directory, path string, state DispatchRegistry) *DispatchRegistryStore {
	store := &DispatchRegistryStore{
		directory: directory,
		path:      path,
		state:     state,
	}
	store.writeState = func(candidate DispatchRegistry) error {
		return persistDispatchRegistry(store.directory, store.path, candidate)
	}
	return store
}

// Snapshot returns a clone; the registry's records never leave by reference.
func (store *DispatchRegistryStore) Snapshot() DispatchRegistry {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneDispatchRegistry(store.state)
}

// AlreadySpent answers the registry's one question for a submission: do these
// exact signed bytes already hold a record?
//
// Every state counts, `not_launched` included. That is the contract's own
// reading and it took re-reading to get right: a host key that changed leaves
// a dispatch `non lancé`, "la séquence est dépensée, aucun effet n'a eu lieu,
// et la reprise appartient à l'humain — jamais à une réparation". An approval
// is a one-shot authority, and it is spent by being submitted rather than by
// reaching a machine. What a human may honestly do after a launch that
// reached nothing is approve the same *position* again — a new envelope, new
// bytes, a new record — which is exactly what indexing by digest rather than
// by sequence number leaves open.
func (store *DispatchRegistryStore) AlreadySpent(approvalSHA256 string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for index := range store.state.Records {
		if store.state.Records[index].ApprovalSHA256 == approvalSHA256 {
			return true
		}
	}
	return false
}

// HighestReportedSequence is what this Controller can attest about a
// machine's position: the highest sequence a valid report named as consumed.
// Zero means it can attest nothing — and a Controller that knows nothing
// refuses nothing, because the machine stays the authority.
func (store *DispatchRegistryStore) HighestReportedSequence(machineID string) uint64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	var highest uint64
	for index := range store.state.Records {
		record := &store.state.Records[index]
		if record.MachineID == machineID && record.State == DispatchReported && record.Sequence > highest {
			highest = record.Sequence
		}
	}
	return highest
}

// Accept durably writes a new record in `in_flight`, before any connection
// exists to fail. The write is the point of consumption on the Controller:
// everything before it happened to a request, everything after it happens to
// an authority already spent here.
func (store *DispatchRegistryStore) Accept(record DispatchRecord) error {
	if record.State != DispatchInFlight {
		return errors.New("a dispatch record is accepted in_flight or not at all")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	candidate := cloneDispatchRegistry(store.state)
	candidate.Records = append(candidate.Records, record)
	candidate.Records = boundDispatchRecords(candidate.Records)
	return store.commit(candidate)
}

// Conclude moves one open record to a terminal state. It refuses to touch a
// record that is already terminal: a dispatch has one conclusion, and a
// second one would be a rewrite of history.
//
// The machine's sentence and this Controller's own observation are separate
// arguments because they are separate kinds of statement, and at most one of
// them exists for any conclusion. `reported` is reachable here so the record
// can carry what a report established; the report's own fields are filled by
// the ingestion that validates it (#127), never by the launch.
func (store *DispatchRegistryStore) Conclude(
	approvalSHA256, state, machineSentence, controllerObservation string, finishedAtUnix uint64,
) error {
	switch state {
	case DispatchNotLaunched, DispatchMachineRefused, DispatchLaunchedUnreported, DispatchReported:
	default:
		return fmt.Errorf("a dispatch does not conclude into %q", state)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	candidate := cloneDispatchRegistry(store.state)
	for index := range candidate.Records {
		record := &candidate.Records[index]
		if record.ApprovalSHA256 != approvalSHA256 {
			continue
		}
		if record.terminal() {
			return errors.New("this dispatch already holds its conclusion")
		}
		record.State = state
		record.MachineSentence = machineSentence
		record.ControllerObservation = controllerObservation
		record.FinishedAtUnix = finishedAtUnix
		// The bound is held here too: a conclusion is what turns a record
		// terminal, so a history that were only trimmed on acceptance would
		// grow past its bound by exactly the records that just became
		// forgettable.
		candidate.Records = boundDispatchRecords(candidate.Records)
		return store.commit(candidate)
	}
	return errors.New("no open dispatch holds these signed bytes")
}

func (store *DispatchRegistryStore) commit(candidate DispatchRegistry) error {
	if err := validateDispatchRegistry(candidate); err != nil {
		return err
	}
	if err := store.writeState(candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

// boundDispatchRecords trims the oldest terminal records of each machine past
// the named bound. Non-terminal records are never trimmed: an open dispatch
// cannot be forgotten, whatever the history's size.
func boundDispatchRecords(records []DispatchRecord) []DispatchRecord {
	perMachine := make(map[string]int, len(records))
	kept := make([]DispatchRecord, 0, len(records))
	// Records are appended in order, so walking from the end keeps the most
	// recent ones and trims from the oldest side.
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		if record.terminal() {
			if perMachine[record.MachineID] >= maxDispatchRecordsPerMachine {
				continue
			}
			perMachine[record.MachineID]++
		}
		kept = append(kept, record)
	}
	sort.SliceStable(kept, func(left, right int) bool {
		return kept[left].AcceptedAtUnix < kept[right].AcceptedAtUnix
	})
	return kept
}

func persistDispatchRegistry(directory, path string, candidate DispatchRegistry) error {
	if err := validateDispatchRegistry(candidate); err != nil {
		return err
	}
	encoded, err := json.Marshal(candidate)
	if err != nil || int64(len(encoded)) > maxDispatchStateBytes {
		return errors.New("dispatch registry cannot be encoded within its bound")
	}
	return writePrivateStateFile(directory, path, ".dispatches-", encoded)
}

func validateDispatchRegistry(state DispatchRegistry) error {
	if state.SchemaVersion != dispatchRegistrySchema {
		return errors.New("unsupported schema version")
	}
	if identifier.ValidateUUIDv4(state.ControllerID) != nil ||
		identifier.ValidateUUIDv4(state.InfrastructureID) != nil {
		return errors.New("controller and infrastructure identifiers must be canonical UUIDv4")
	}
	if state.Records == nil {
		return errors.New("records must be present, even empty")
	}
	openDigests := make(map[string]bool, len(state.Records))
	for index := range state.Records {
		record := &state.Records[index]
		if !canonicalDispatchDigest.MatchString(record.ApprovalSHA256) ||
			!canonicalDispatchDigest.MatchString(record.PlanSHA256) ||
			!canonicalDispatchDigest.MatchString(record.RollbackSHA256) {
			return errors.New("a record's digests must be lower-case hexadecimal SHA-256")
		}
		if machineid.Validate(record.MachineID) != nil {
			return errors.New("a record's machine identifier is malformed")
		}
		if record.Operation == "" || record.ApprovalEpoch == 0 || record.Sequence == 0 {
			return errors.New("a record must name its operation, epoch and sequence")
		}
		// The two free-text fields are refused here rather than trimmed in the
		// rendering: a bound held at the drawing would be a document that grew
		// silently behind a view that looked bounded.
		if len(record.MachineSentence) > maxDispatchMachineSentenceBytes {
			return fmt.Errorf("a machine sentence must stay within %d bytes", maxDispatchMachineSentenceBytes)
		}
		if len(record.ControllerObservation) > maxDispatchObservationBytes {
			return fmt.Errorf("an observation must stay within %d bytes", maxDispatchObservationBytes)
		}
		// At most one of the two exists for any conclusion: one is a sentence
		// the product did not write, the other is its own account of its own
		// attempt, and a record carrying both would leave a reader unable to
		// tell which it is reading.
		if record.MachineSentence != "" && record.ControllerObservation != "" {
			return errors.New("a record carries the machine's sentence or this Controller's observation, never both")
		}
		switch record.State {
		case DispatchInFlight, DispatchNotLaunched, DispatchMachineRefused,
			DispatchReported, DispatchLaunchedUnreported:
		default:
			return fmt.Errorf("a record holds the unknown state %q", record.State)
		}
		if record.AcceptedAtUnix == 0 {
			return errors.New("a record must carry the instant it was accepted")
		}
		if record.State == DispatchInFlight {
			if record.FinishedAtUnix != 0 {
				return errors.New("an open record cannot carry a terminal instant")
			}
			// Two open records for the same bytes would be two launches of a
			// one-shot authority; the acceptance path refuses it and the
			// document refuses to hold it.
			if openDigests[record.ApprovalSHA256] {
				return errors.New("two open records hold the same signed bytes")
			}
			openDigests[record.ApprovalSHA256] = true
		}
	}
	return nil
}

func cloneDispatchRegistry(state DispatchRegistry) DispatchRegistry {
	result := state
	result.Records = append([]DispatchRecord(nil), state.Records...)
	return result
}
