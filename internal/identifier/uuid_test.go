package identifier

import (
	"bytes"
	"testing"
)

func TestValidateUUIDv4(t *testing.T) {
	t.Parallel()
	valid := "11111111-1111-4111-8111-111111111111"
	if err := ValidateUUIDv4(valid); err != nil {
		t.Fatalf("valid UUID rejected: %v", err)
	}
	for _, hostile := range []string{
		"",
		"11111111-1111-1111-8111-111111111111",
		"11111111-1111-4111-7111-111111111111",
		"11111111-1111-4111-8111-11111111111A",
		"{11111111-1111-4111-8111-111111111111}",
	} {
		if err := ValidateUUIDv4(hostile); err == nil {
			t.Fatalf("hostile UUID accepted: %q", hostile)
		}
	}
}

func TestUUIDv4FromSetsCanonicalVersionAndVariant(t *testing.T) {
	value, err := UUIDv4From(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if value != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("unexpected UUIDv4 %q", value)
	}
	if _, err := UUIDv4From(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Fatal("short randomness was accepted")
	}
}
