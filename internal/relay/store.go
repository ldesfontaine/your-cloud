// Package relay receives bounded presence signals and renders their age.
package relay

import (
	"sort"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
)

// Store keeps only the last signal received for each allowed machine. It is
// intentionally in memory: v0.0.1 has no history, buffer, or durable storage.
type Store struct {
	mu              sync.RWMutex
	allowedMachines []string
	lastSignals     map[string]receivedSignal
}

type receivedSignal struct {
	signal     presence.Signal
	receivedAt time.Time
}

// MachineState is the Relay-owned view returned to an observer.
type MachineState struct {
	MachineID     string `json:"machine_id"`
	Status        string `json:"status"`
	DaemonVersion string `json:"daemon_version,omitempty"`
	SentAt        string `json:"sent_at,omitempty"`
	ReceivedAt    string `json:"received_at,omitempty"`
}

// NewStore fixes the exact machines represented by this Relay instance.
func NewStore(allowedMachines []string) *Store {
	machines := append([]string(nil), allowedMachines...)
	sort.Strings(machines)
	return &Store{
		allowedMachines: machines,
		lastSignals:     make(map[string]receivedSignal, len(machines)),
	}
}

// Record replaces one machine's last signal with the Relay reception time.
func (store *Store) Record(signal presence.Signal, receivedAt time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.lastSignals[signal.MachineID] = receivedSignal{signal: signal, receivedAt: receivedAt}
}

// Snapshot renders every allowed machine as absent, recent, or old. Client
// timestamps are returned for visibility but never participate in this choice.
func (store *Store) Snapshot(now time.Time) []MachineState {
	store.mu.RLock()
	defer store.mu.RUnlock()

	states := make([]MachineState, 0, len(store.allowedMachines))
	for _, machineID := range store.allowedMachines {
		received, ok := store.lastSignals[machineID]
		if !ok {
			states = append(states, MachineState{MachineID: machineID, Status: "absent"})
			continue
		}
		status := "recent"
		if now.Sub(received.receivedAt) >= presence.StaleAfter {
			status = "old"
		}
		states = append(states, MachineState{
			MachineID:     machineID,
			Status:        status,
			DaemonVersion: received.signal.DaemonVersion,
			SentAt:        received.signal.SentAt,
			ReceivedAt:    received.receivedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return states
}
