// Package machineid validates the stable identifier carried across observation
// configuration, certificates and network messages.
package machineid

import (
	"errors"
	"regexp"
)

var pattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

// Validate rejects identifiers that cannot safely name a LAB machine.
func Validate(value string) error {
	if value == "" {
		return errors.New("machine_id is required")
	}
	if !pattern.MatchString(value) {
		return errors.New("machine_id is malformed")
	}
	return nil
}
