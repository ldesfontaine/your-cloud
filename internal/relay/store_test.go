package relay

import (
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
)

func TestStoreUsesRelayReceptionTimeForFreshness(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := NewStore([]string{"lab-coordinateur", "lab-machine-1"})
	store.Record(presence.Signal{
		MachineID:     "lab-machine-1",
		DaemonVersion: presence.Version,
		SentAt:        "2000-01-01T00:00:00Z",
	}, now)

	states := store.Snapshot(now.Add(presence.StaleAfter - time.Nanosecond))
	if states[0].MachineID != "lab-coordinateur" || states[0].Status != "absent" {
		t.Fatalf("unexpected absent state: %#v", states[0])
	}
	if states[1].MachineID != "lab-machine-1" || states[1].Status != "recent" {
		t.Fatalf("unexpected recent state: %#v", states[1])
	}

	states = store.Snapshot(now.Add(presence.StaleAfter))
	if states[1].Status != "old" {
		t.Fatalf("machine should be old at the boundary: %#v", states[1])
	}
	if states[0].Status != "absent" {
		t.Fatalf("unexpected absent state: %#v", states[0])
	}
}
