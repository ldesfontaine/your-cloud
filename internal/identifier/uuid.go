// Package identifier validates the fixed identifiers exchanged by v0.0.3.
package identifier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
)

var canonicalUUIDv4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidateUUIDv4 accepts only the canonical lower-case textual form.
func ValidateUUIDv4(value string) error {
	if !canonicalUUIDv4.MatchString(value) {
		return errors.New("identifier must be a canonical lower-case UUIDv4")
	}
	return nil
}

// NewUUIDv4 draws all non-version bits from the operating-system CSPRNG.
func NewUUIDv4() (string, error) {
	return UUIDv4From(rand.Reader)
}

// UUIDv4From exists so deterministic hostile tests can inject a bounded reader.
func UUIDv4From(source io.Reader) (string, error) {
	if source == nil {
		return "", errors.New("UUID randomness source is required")
	}
	var value [16]byte
	if _, err := io.ReadFull(source, value[:]); err != nil {
		return "", fmt.Errorf("generate UUIDv4: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}
