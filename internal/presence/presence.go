// Package presence defines the only message exchanged by v0.0.1.
package presence

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	// Version is the only Daemon version accepted by the v0.0.1 Relay.
	Version = "v0.0.1"
	// MaxBodyBytes bounds untrusted input before JSON decoding.
	MaxBodyBytes int64 = 512
	// SendInterval is the announced interval between two Daemon signals.
	SendInterval = time.Second
	// StaleAfter is the Relay-side age at which a machine becomes old.
	StaleAfter = 4 * time.Second
)

var machineIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

// AllowedMachineIDs returns the complete synthetic v0.0.1 topology. The VPS
// runs one Daemon beside the Relay; the other Daemon runs on the LAN machine.
func AllowedMachineIDs() []string {
	return []string{"lab-coordinateur", "lab-machine-1"}
}

// Signal travels from one Daemon to the Relay. SentAt is informative; the
// Relay uses its own reception time to decide whether a machine is recent.
type Signal struct {
	MachineID     string `json:"machine_id"`
	DaemonVersion string `json:"daemon_version"`
	SentAt        string `json:"sent_at"`
}

// DecodeSignal accepts exactly the three lower-case v0.0.1 fields once each.
// encoding/json otherwise accepts duplicate keys and case-insensitive struct
// matches, which would make the network boundary wider than the contract.
func DecodeSignal(reader io.Reader) (Signal, error) {
	decoder := json.NewDecoder(reader)
	if err := openSignalObject(decoder); err != nil {
		return Signal{}, err
	}

	var signal Signal
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		if err := decodeSignalField(decoder, &signal, seen); err != nil {
			return Signal{}, err
		}
	}
	if err := closeSignalObject(decoder); err != nil {
		return Signal{}, err
	}
	if len(seen) != 3 {
		return Signal{}, errors.New("presence is missing a required field")
	}
	return signal, nil
}

func openSignalObject(decoder *json.Decoder) error {
	start, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read presence object: %w", err)
	}
	if start != json.Delim('{') {
		return errors.New("presence must be one JSON object")
	}
	return nil
}

func decodeSignalField(decoder *json.Decoder, signal *Signal, seen map[string]struct{}) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read presence field: %w", err)
	}
	key, ok := token.(string)
	if !ok {
		return errors.New("presence field name is invalid")
	}
	if _, duplicate := seen[key]; duplicate {
		return fmt.Errorf("presence repeats field %q", key)
	}
	seen[key] = struct{}{}

	switch key {
	case "machine_id":
		err = decoder.Decode(&signal.MachineID)
	case "daemon_version":
		err = decoder.Decode(&signal.DaemonVersion)
	case "sent_at":
		err = decoder.Decode(&signal.SentAt)
	default:
		return fmt.Errorf("presence contains unknown field %q", key)
	}
	if err != nil {
		return fmt.Errorf("presence field %q is invalid: %w", key, err)
	}
	return nil
}

func closeSignalObject(decoder *json.Decoder) error {
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		if err != nil {
			return fmt.Errorf("close presence object: %w", err)
		}
		return errors.New("presence object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("read after presence object: %w", err)
		}
		return errors.New("presence must contain only one JSON object")
	}
	return nil
}

// ValidateMachineID rejects empty and syntactically unsafe identifiers before
// the Relay applies its exact LAB allowlist.
func ValidateMachineID(machineID string) error {
	if machineID == "" {
		return errors.New("machine_id is required")
	}
	if !machineIDPattern.MatchString(machineID) {
		return errors.New("machine_id is malformed")
	}
	return nil
}

// Validate checks the complete input contract at the Relay boundary.
func (signal Signal) Validate(allowedMachines map[string]struct{}) error {
	if err := ValidateMachineID(signal.MachineID); err != nil {
		return err
	}
	if _, allowed := allowedMachines[signal.MachineID]; !allowed {
		return errors.New("machine_id is not allowed")
	}
	if signal.DaemonVersion != Version {
		return fmt.Errorf("daemon_version must be %q", Version)
	}
	if signal.SentAt == "" {
		return errors.New("sent_at is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, signal.SentAt); err != nil {
		return errors.New("sent_at must be an RFC 3339 timestamp")
	}
	return nil
}
