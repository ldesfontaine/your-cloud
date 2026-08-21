// Package observation defines the bounded host-health wire message.
package observation

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// SchemaVersion identifies the only accepted host-health wire schema.
	SchemaVersion = 1
	// DaemonVersion is the exact producer version accepted by the Relay.
	DaemonVersion = "v0.2.0"
	// Profile identifies the fixed collector set.
	Profile = "host-health.v1"
	// CollectionInterval is the candidate cadence measured by the LAB proof.
	CollectionInterval = 30 * time.Second
	// MaxMessageBytes bounds an encoded observation before transport decoding.
	MaxMessageBytes = 4096
	// MaxExternalReadings bounds the declared-target section of one envelope.
	//
	// It is small on purpose. The section rides inside the same 4 KiB message the
	// three collectors already fit in, and a machine that could report a hundred
	// ports would be a machine whose envelope no longer fits — so the bound is
	// here, where the message is, rather than left to whoever provisions targets.
	MaxExternalReadings = 16
)

// The closed vocabulary of one external reading.
//
// Every one of them is a fact about a connection and never about a content:
// something accepted, nothing accepted, something accepted and would not stop
// talking within the bound, or the socket is held by an account of this product.
// There is no value here that says what answered, because a thing that answers
// proves that a thing answers and not that it is the thing a human named.
const (
	ExternalAnswered   = "answered"
	ExternalNoListener = "no_listener"
	ExternalTooLarge   = "response_too_large"
	ExternalManaged    = "managed_by_this_product"
)

const (
	statusOK    = "ok"
	statusError = "error"
	errorRead   = "source_unavailable"
	errorValue  = "source_invalid"
)

// Envelope is immutable once placed in the local delivery queue.
//
// `profile` names the fixed collector set of `health` and goes on naming exactly
// those three, because that is what it has always named. `external` is not a
// fourth collector and does not belong to that profile: it carries no value, no
// health and no content, only what a connection to a declared loopback port of
// this machine did. It is present only on a machine whose own root-provisioned
// sheet names targets, so an envelope from every machine proved before `#107` is
// byte for byte the envelope that palier proved.
type Envelope struct {
	SchemaVersion int               `json:"schema_version"`
	MachineID     string            `json:"machine_id"`
	DaemonVersion string            `json:"daemon_version"`
	Profile       string            `json:"profile"`
	Sequence      uint64            `json:"sequence"`
	ObservedAt    string            `json:"observed_at"`
	Health        HostHealth        `json:"health"`
	Gaps          []Gap             `json:"gaps,omitempty"`
	External      []ExternalReading `json:"external,omitempty"`
}

// ExternalReading is one bounded conclusion about one loopback port a
// root-provisioned sheet on that machine declared.
//
// Two fields and no third. There is no address, because the read is made on the
// machine's own loopback and nowhere else; no label, because the human's words
// live in the Controller's declared inventory and not on the wire; no body, no
// size, no status and no media type, because nothing about the answer is
// interpreted and a field that could carry a byte of a third party would be a
// field somebody would eventually read.
type ExternalReading struct {
	ProbePort int    `json:"probe_port"`
	Outcome   string `json:"outcome"`
}

// Gap makes one contiguous range of discarded observations explicit.
type Gap struct {
	FirstSequence   uint64 `json:"first_sequence"`
	LastSequence    uint64 `json:"last_sequence"`
	DroppedCount    uint64 `json:"dropped_count"`
	FirstObservedAt string `json:"first_observed_at"`
	LastObservedAt  string `json:"last_observed_at"`
}

// HostHealth contains exactly the three approved collectors.
type HostHealth struct {
	Uptime UptimeResult `json:"uptime"`
	Memory MemoryResult `json:"memory"`
	RootFS RootFSResult `json:"rootfs"`
}

// UptimeResult renders either one typed value or one bounded failure code.
type UptimeResult struct {
	Status        string  `json:"status"`
	UptimeSeconds *uint64 `json:"uptime_seconds,omitempty"`
	Error         string  `json:"error,omitempty"`
}

// MemoryResult contains only total and currently available bytes.
type MemoryResult struct {
	Status         string  `json:"status"`
	TotalBytes     *uint64 `json:"total_bytes,omitempty"`
	AvailableBytes *uint64 `json:"available_bytes,omitempty"`
	Error          string  `json:"error,omitempty"`
}

// RootFSResult contains only size and availability for the fixed root mount.
type RootFSResult struct {
	Status         string  `json:"status"`
	TotalBytes     *uint64 `json:"total_bytes,omitempty"`
	AvailableBytes *uint64 `json:"available_bytes,omitempty"`
	Error          string  `json:"error,omitempty"`
}

// NewEnvelope binds one collected state to its machine and persistent sequence.
//
// The declared-target section travels beside the health of the host rather than
// in a message of its own: a machine that has one thing to report has one
// message to send, and a second reporting path would be a second authority to
// enrol, to authenticate and to bound. An empty section is omitted rather than
// sent empty, so a machine that declares no target sends what it always sent.
func NewEnvelope(machineID string, sequence uint64, observedAt time.Time, health HostHealth, external []ExternalReading) (Envelope, error) {
	result := Envelope{
		SchemaVersion: SchemaVersion,
		MachineID:     machineID,
		DaemonVersion: DaemonVersion,
		Profile:       Profile,
		Sequence:      sequence,
		ObservedAt:    observedAt.UTC().Format(time.RFC3339Nano),
		Health:        health,
	}
	if len(external) != 0 {
		result.External = append([]ExternalReading(nil), external...)
	}
	if err := result.Validate(); err != nil {
		return Envelope{}, err
	}
	return result, nil
}

// Encode returns the exact immutable bytes placed in the local queue.
func (envelope Envelope) Encode() ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode observation: %w", err)
	}
	if len(encoded) > MaxMessageBytes {
		return nil, errors.New("observation exceeds the maximum encoded size")
	}
	return encoded, nil
}

// Decode rejects ambiguous JSON and validates the complete wire contract.
func Decode(data []byte) (Envelope, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return Envelope{}, errors.New("observation size is outside the allowed range")
	}
	var envelope Envelope
	if err := strictjson.Decode(data, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode observation: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// Validate enforces every fixed identifier and typed collector invariant.
func (envelope Envelope) Validate() error {
	if envelope.SchemaVersion != SchemaVersion {
		return errors.New("unsupported observation schema_version")
	}
	if err := machineid.Validate(envelope.MachineID); err != nil {
		return err
	}
	if envelope.DaemonVersion != DaemonVersion {
		return errors.New("unsupported daemon_version")
	}
	if envelope.Profile != Profile {
		return errors.New("unsupported observation profile")
	}
	if envelope.Sequence == 0 {
		return errors.New("observation sequence must be positive")
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.ObservedAt); err != nil {
		return errors.New("observed_at must be an RFC 3339 timestamp")
	}
	if err := validateUptime(envelope.Health.Uptime); err != nil {
		return fmt.Errorf("uptime collector: %w", err)
	}
	if err := validatePair(envelope.Health.Memory.Status, envelope.Health.Memory.TotalBytes, envelope.Health.Memory.AvailableBytes, envelope.Health.Memory.Error); err != nil {
		return fmt.Errorf("memory collector: %w", err)
	}
	if err := validatePair(envelope.Health.RootFS.Status, envelope.Health.RootFS.TotalBytes, envelope.Health.RootFS.AvailableBytes, envelope.Health.RootFS.Error); err != nil {
		return fmt.Errorf("rootfs collector: %w", err)
	}
	if err := validateExternalReadings(envelope.External); err != nil {
		return err
	}
	for index, gap := range envelope.Gaps {
		if err := gap.Validate(); err != nil {
			return fmt.Errorf("gap %d: %w", index, err)
		}
		if gap.LastSequence >= envelope.Sequence {
			return errors.New("observation gap must precede its sequence")
		}
		if index > 0 && envelope.Gaps[index-1].LastSequence >= gap.FirstSequence {
			return errors.New("observation gaps must be ordered and disjoint")
		}
	}
	return nil
}

// Validate rejects empty, reversed or arithmetically inconsistent gaps.
func (gap Gap) Validate() error {
	if gap.FirstSequence == 0 || gap.LastSequence < gap.FirstSequence {
		return errors.New("gap sequence range is invalid")
	}
	if gap.DroppedCount != gap.LastSequence-gap.FirstSequence+1 {
		return errors.New("gap dropped_count does not match its sequence range")
	}
	first, firstErr := time.Parse(time.RFC3339Nano, gap.FirstObservedAt)
	last, lastErr := time.Parse(time.RFC3339Nano, gap.LastObservedAt)
	if firstErr != nil || lastErr != nil || last.Before(first) {
		return errors.New("gap observation interval is invalid")
	}
	return nil
}

// validateExternalReadings keeps the declared-target section closed, bounded and
// ordered on the one value that identifies a target.
//
// Sorted and unique by port, so that a reader mapping a reading onto a
// declaration never has to choose between two answers about the same port, and
// so that the same machine in the same state produces the same bytes.
func validateExternalReadings(readings []ExternalReading) error {
	if len(readings) > MaxExternalReadings {
		return errors.New("observation carries more external readings than the bound")
	}
	previousPort := 0
	for _, reading := range readings {
		if reading.ProbePort < 1 || reading.ProbePort > 65535 {
			return errors.New("external reading probe_port is outside 1..65535")
		}
		if reading.ProbePort <= previousPort {
			return errors.New("external readings must be unique and sorted by probe_port")
		}
		switch reading.Outcome {
		case ExternalAnswered, ExternalNoListener, ExternalTooLarge, ExternalManaged:
		default:
			return errors.New("external reading outcome is outside its closed list")
		}
		previousPort = reading.ProbePort
	}
	return nil
}

func validateUptime(result UptimeResult) error {
	switch result.Status {
	case statusOK:
		if result.UptimeSeconds == nil || result.Error != "" {
			return errors.New("ok result must contain only uptime_seconds")
		}
	case statusError:
		if result.UptimeSeconds != nil || !validErrorCode(result.Error) {
			return errors.New("error result must contain one supported error code")
		}
	default:
		return errors.New("unsupported collector status")
	}
	return nil
}

func validatePair(status string, total, available *uint64, errorCode string) error {
	switch status {
	case statusOK:
		if total == nil || available == nil || errorCode != "" || *available > *total {
			return errors.New("ok result must contain a valid total and available pair")
		}
	case statusError:
		if total != nil || available != nil || !validErrorCode(errorCode) {
			return errors.New("error result must contain one supported error code")
		}
	default:
		return errors.New("unsupported collector status")
	}
	return nil
}

func validErrorCode(value string) bool {
	return value == errorRead || value == errorValue
}
