package approval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ldesfontaine/your-cloud/internal/securefile"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// StateDirectory holds the only thing this Auxiliary remembers between runs.
//
// It is deliberately not a log. There is no history of actions, no plan, no
// output and no secret in it: the one fact it carries is which sequence has
// already been spent, because that fact cannot be recomputed by observing the
// machine. Everything else the Auxiliary knows, it re-reads.
const StateDirectory = "/var/lib/your-cloud-auxiliary"

const (
	stateFileName = "approval-state.json"
	lockFileName  = "approval-state.lock"

	// MaxStateBytes bounds the state before it is parsed.
	MaxStateBytes = 512
)

// State is the anti-replay position of one machine under one authority.
//
// It is bound to the infrastructure and the machine as well as to the epoch, so
// a state file moved onto another machine, or kept across a change of
// infrastructure, is refused rather than silently reused as a starting point.
type State struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	ApprovalEpoch    uint64 `json:"approval_epoch"`
	ConsumedSequence uint64 `json:"consumed_sequence"`
}

// StatePath is the fixed file the state lives in.
func StatePath(directory string) string { return filepath.Join(directory, stateFileName) }

// LockPath is the fixed file two concurrent Auxiliaries contend on.
func LockPath(directory string) string { return filepath.Join(directory, lockFileName) }

// Consume spends the envelope's sequence, or refuses it, and returns the state
// the machine is at afterwards.
//
// It is the single mutating operation of this palier and it happens *before*
// anything is performed. That ordering is the point: a run interrupted after
// consumption has spent its sequence and will never be replayed, which is why
// the architecture requires a fresh observation and a new signed plan rather
// than a retry.
//
// The whole read-decide-write happens while this process holds an exclusive
// lock on the state directory, and the write is a rename over a synchronised
// temporary file. A second Auxiliary running at the same instant does not wait
// for the first: it is refused, because two approvals arriving together are two
// approvals and only one of them can be the successor.
func Consume(directory string, anchor *Anchor, envelope *Envelope) (*State, error) {
	if err := anchor.Binds(envelope); err != nil {
		return nil, err
	}
	lock, err := acquire(directory)
	if err != nil {
		return nil, err
	}
	defer lock.release()

	current, err := readState(directory)
	if err != nil {
		return nil, err
	}
	next, err := successor(current, anchor, envelope)
	if err != nil {
		return nil, err
	}
	if err := writeState(directory, next); err != nil {
		return nil, err
	}
	return next, nil
}

// successor decides, from the persisted position and the anchor, whether this
// envelope is the one and only sequence the machine may accept next.
func successor(current *State, anchor *Anchor, envelope *Envelope) (*State, error) {
	next := &State{
		SchemaVersion:    SchemaVersion,
		InfrastructureID: anchor.InfrastructureID,
		MachineID:        anchor.MachineID,
		ApprovalEpoch:    envelope.ApprovalEpoch,
		ConsumedSequence: envelope.Sequence,
	}
	if current == nil {
		// Nothing was ever consumed on this machine. Only the first sequence of
		// the epoch may open the series; a plan that starts at any other number
		// is a plan whose predecessors this machine never saw.
		if envelope.Sequence != 1 {
			return nil, fmt.Errorf("approval sequence %d is not the first of a machine that consumed none", envelope.Sequence)
		}
		return next, nil
	}
	if current.InfrastructureID != anchor.InfrastructureID || current.MachineID != anchor.MachineID {
		return nil, errors.New("anti-replay state belongs to another infrastructure or machine")
	}
	switch {
	case envelope.ApprovalEpoch < current.ApprovalEpoch:
		// The anchor already refused this, since it names the active epoch. The
		// state refuses it a second time so that an anchor rolled back to an
		// older epoch does not resurrect the sequences spent under it.
		return nil, fmt.Errorf("approval epoch %d is older than the epoch %d this machine consumed under", envelope.ApprovalEpoch, current.ApprovalEpoch)
	case envelope.ApprovalEpoch > current.ApprovalEpoch:
		// A new epoch invalidates the previous one instead of coexisting with
		// it, so its series starts over at one.
		if envelope.Sequence != 1 {
			return nil, fmt.Errorf("approval sequence %d is not the first of the new epoch %d", envelope.Sequence, envelope.ApprovalEpoch)
		}
		return next, nil
	default:
		if envelope.Sequence != current.ConsumedSequence+1 {
			return nil, fmt.Errorf("approval sequence %d is not the exact successor of %d", envelope.Sequence, current.ConsumedSequence)
		}
		return next, nil
	}
}

// readState returns nil when nothing was ever consumed, and an error when
// something is there but cannot be read as a position.
//
// An unreadable state is never treated as an absent one: that confusion is
// exactly how an attacker who can corrupt a file would reopen a spent series.
func readState(directory string) (*State, error) {
	path := StatePath(directory)
	data, err := securefile.ReadRootOwned(path, MaxStateBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("anti-replay state: %w", err)
	}
	var state State
	if err := strictjson.Decode(data, &state); err != nil {
		return nil, fmt.Errorf("decode anti-replay state: %w", err)
	}
	if state.SchemaVersion != SchemaVersion {
		return nil, errors.New("anti-replay state schema version is unsupported")
	}
	if !canonicalUUIDv4.MatchString(state.InfrastructureID) || !canonicalMachine.MatchString(state.MachineID) {
		return nil, errors.New("anti-replay state names no canonical infrastructure and machine")
	}
	if state.ApprovalEpoch == 0 || state.ConsumedSequence == 0 {
		return nil, errors.New("anti-replay state must name a consumed epoch and sequence")
	}
	return &state, nil
}

// writeState replaces the position durably.
//
// The temporary file is synchronised before the rename and the directory is
// synchronised after it, so a machine that loses power at any instant comes
// back holding either the previous position or the new one — never a truncated
// file, and never an empty one that would reopen a spent sequence. This is what
// the LAB reboot proof exercises for real.
func writeState(directory string, state *State) error {
	document, err := encodeState(state)
	if err != nil {
		return err
	}
	path := StatePath(directory)
	temporaryPath := path + ".tmp"
	if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear previous anti-replay state: %w", err)
	}
	temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create anti-replay state: %w", err)
	}
	if _, err := temporary.Write(document); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("write anti-replay state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("synchronise anti-replay state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("close anti-replay state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("replace anti-replay state: %w", err)
	}
	return syncDirectory(directory)
}

func encodeState(state *State) ([]byte, error) {
	document := fmt.Sprintf(
		"{\"schema_version\":%d,\"infrastructure_id\":%q,\"machine_id\":%q,\"approval_epoch\":%d,\"consumed_sequence\":%d}\n",
		state.SchemaVersion,
		state.InfrastructureID,
		state.MachineID,
		state.ApprovalEpoch,
		state.ConsumedSequence,
	)
	if len(document) > MaxStateBytes {
		return nil, errors.New("anti-replay state does not fit its own bound")
	}
	return []byte(document), nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open anti-replay directory: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("synchronise anti-replay directory: %w", err)
	}
	return nil
}

// stateLock is the exclusive right to decide the next sequence.
type stateLock struct{ file *os.File }

// acquire takes the lock without waiting.
//
// Waiting would serialise two concurrent approvals and let the second one run
// as the successor of the first, which is precisely what a Controller replaying
// two envelopes at once would want. Refusing instead makes concurrency visible.
func acquire(directory string) (*stateLock, error) {
	if err := validateStateDirectory(directory); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(LockPath(directory), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open anti-replay lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another approval is already being consumed on this machine")
	}
	return &stateLock{file: file}, nil
}

func (lock *stateLock) release() {
	syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	lock.file.Close()
}

// validateStateDirectory requires the same root-owned, non-group-writable real
// directory the authority files are read from. A state a non-root account could
// replace would be no state at all.
func validateStateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("anti-replay directory must be absolute and canonical")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("anti-replay directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("anti-replay directory must be a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("anti-replay directory ownership is unavailable")
	}
	if stat.Uid != 0 {
		return errors.New("anti-replay directory must be owned by root")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("anti-replay directory must not be writable by group or others")
	}
	return nil
}
