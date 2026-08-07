package controller

import (
	"errors"
	"math"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

// This file is where a machine's reading becomes a dated constat of the declared
// inventory, and it is the transport decision of `#107` written as code.
//
// `#106` left RecordObservation without a route on purpose: the adapter reads a
// loopback port on the enrolled machine, so how its reading reaches the
// Controller was this palier's to decide. It is decided here, and the decision is
// that it reaches it the way every other fact about a machine already does —
// Daemon, Relay, Controller — rather than through a second reporting path.
//
// Nothing about the authorities of that chain moves. The Daemon still knows only
// its Relay and learns which ports to read from its own root-provisioned sheet,
// never from an answer; the Relay still carries no order in either direction; the
// Controller still reads, and is still the only one of the three that holds the
// declared inventory. What the Controller adds here is the join the chain cannot
// make for itself: the machine reports a port, and the machine and the port are
// exactly the pair a declaration is unique on.

// ExternalReasonPortIsManaged is the one extension `#107` makes to the closed
// reason list `#105` fixed, and it is named as an extension rather than slipped
// in.
//
// It exists because the collision `#106` could not decide is decided on the
// machine: a port a human declared external, whose listening socket is held by
// an account of this product, is a port this product itself published. Three
// answers were possible and two are refused. Refusing the reading outright would
// leave the element saying `declared` — which is exactly the silent presentation
// of a managed service as an external one that the refusal exists to prevent. A
// distinct fourth state would break the contract's own rule that there are three
// states and never a fourth in disguise. So the reading concludes what it
// honestly concluded — nothing about an external thing — and names why, in a word
// the App renders as its own sentence. The declaration is not removed either:
// withdrawing it is a human's act and never a Controller's.
const ExternalReasonPortIsManaged = "port_is_managed"

// AbsorbSnapshot applies to the declared inventory everything one Relay snapshot
// says about the loopback ports of the enrolled machines.
//
// It is called on the read path and writes durably, exactly as the Relay cache
// is: recording what a machine constated is not a human act, so it does not pass
// through the session's anti-replay gate, and it may not be gated on somebody
// being logged in either — a fact about a machine is a fact whoever is watching.
//
// It is idempotent. A snapshot the Controller has already absorbed changes
// nothing, bumps no revision and rewrites no file: a Console that refreshes
// twice must not make the inventory look like it moved.
func (store *ExternalStore) AbsorbSnapshot(snapshot *RelaySnapshot) error {
	if snapshot == nil {
		return nil
	}
	if _, err := parseCanonicalUTC(snapshot.SnapshotAt); err != nil {
		return errors.New("Relay snapshot timestamp is not canonical UTC")
	}
	observations := make(map[string]*RelaySnapshotObservation, len(snapshot.Machines))
	for _, machine := range snapshot.Machines {
		observations[machine.MachineID] = machine.Observation
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	candidate := cloneExternalInventory(store.state)
	changed := false
	for index := range candidate.Elements {
		element := candidate.Elements[index]
		concluded, ok := concludeExternalReading(element, observations, snapshot.SnapshotAt)
		if !ok {
			continue
		}
		if element.Observation != nil && *element.Observation == concluded {
			continue
		}
		if element.Observation != nil {
			previous, err := parseCanonicalUTC(element.Observation.ObservedAt)
			observed, observedErr := parseCanonicalUTC(concluded.ObservedAt)
			if err != nil || observedErr != nil || observed.Before(previous) {
				// A reading older than the one already held is dropped rather than
				// stored, for the reason the Relay cache refuses a regressing
				// snapshot: a state that can move backwards in time is a state
				// somebody can rewrite by replaying an old success over a fresh
				// contradiction.
				continue
			}
		}
		recorded := concluded
		candidate.Elements[index].Observation = &recorded
		changed = true
	}
	if !changed {
		return nil
	}
	if candidate.ExternalRevision == math.MaxUint64 {
		return errors.New("external revision is saturated")
	}
	candidate.ExternalRevision++
	return store.commit(candidate)
}

// concludeExternalReading turns what one machine reported into the contract's
// own vocabulary, and reports whether there is anything to record at all.
//
// It infers nothing. What a reading says is that something accepted a connection
// on this port at this instant — never that the something is the thing the human
// named — and the label stays the human's word about a thing the product does not
// own.
func concludeExternalReading(
	element ExternalElement,
	observations map[string]*RelaySnapshotObservation,
	snapshotAt string,
) (ExternalObservation, bool) {
	current, enrolled := observations[element.MachineID]
	if !enrolled || current == nil {
		// The machine this declaration looks from carries nothing at all in a
		// snapshot the Controller could read. An element nobody ever read stays
		// `declared`, because "not provisioned yet" is not "unreachable"; an element
		// that *was* read before is told plainly that the viewpoint it names has
		// stopped answering, rather than being left to age with no reason given.
		if element.Observation == nil {
			return ExternalObservation{}, false
		}
		if element.Observation.State == ExternalStateUnverifiable &&
			element.Observation.Reason == ExternalReasonMachineUnreachable {
			return ExternalObservation{}, false
		}
		return ExternalObservation{
			State:      ExternalStateUnverifiable,
			Reason:     ExternalReasonMachineUnreachable,
			ObservedAt: snapshotAt,
		}, true
	}
	outcome, named := readingForPort(current.External, element.ProbePort)
	if !named {
		// This machine's own sheet does not name that port, so nobody looked. The
		// last constat keeps its date and ages honestly; nothing is invented to fill
		// the silence.
		return ExternalObservation{}, false
	}
	concluded := ExternalObservation{ObservedAt: current.ObservedAt}
	switch outcome {
	case observation.ExternalAnswered:
		concluded.State = ExternalStateVerified
	case observation.ExternalTooLarge:
		concluded.State = ExternalStateUnverifiable
		concluded.Reason = ExternalReasonResponseTooLarge
	case observation.ExternalManaged:
		concluded.State = ExternalStateUnverifiable
		concluded.Reason = ExternalReasonPortIsManaged
	case observation.ExternalNoListener:
		// This is the whole of what `contradicted` means in this product, and it is
		// narrow on purpose: a port that a dated reading found answering accepts
		// nothing any more, so the machine contradicts what the declaration says is
		// there. It is never content matching — no profile describes the content of
		// an external thing, so nothing here could compare one — and it is never the
		// first answer about an element: nobody ever saw that port answer, so there
		// is nothing yet to contradict, and the reading says `unverifiable` with the
		// reason that names exactly what happened. Once established it holds until a
		// reading verifies the port again, so an element does not oscillate between
		// two words while nothing about it changes.
		if element.Observation != nil &&
			(element.Observation.State == ExternalStateVerified || element.Observation.State == ExternalStateContradicted) {
			concluded.State = ExternalStateContradicted
		} else {
			concluded.State = ExternalStateUnverifiable
			concluded.Reason = ExternalReasonNothingListening
		}
	default:
		return ExternalObservation{}, false
	}
	if err := validateExternalObservation(concluded); err != nil {
		return ExternalObservation{}, false
	}
	return concluded, true
}

func readingForPort(readings []observation.ExternalReading, port int) (string, bool) {
	for _, reading := range readings {
		if reading.ProbePort == port {
			return reading.Outcome, true
		}
	}
	return "", false
}
