package relay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validCandidate = `{"schema":1,"role":"relay-candidate"}`

func TestDecodeCandidateRejectsHostileDocuments(t *testing.T) {
	t.Parallel()
	tests := []string{
		``,
		`[]`,
		`{"schema":1}`,
		`{"schema":2,"role":"relay-candidate"}`,
		`{"schema":1,"role":"relay"}`,
		`{"schema":1,"role":"relay-candidate","extra":true}`,
		`{"schema":1,"schema":1,"role":"relay-candidate"}`,
		validCandidate + `{}`,
	}
	if manifest, err := decodeCandidate([]byte(validCandidate)); err != nil || manifest.Schema != 1 || manifest.Role != "relay-candidate" {
		t.Fatalf("valid candidate rejected: %#v %v", manifest, err)
	}
	for _, document := range tests {
		if manifest, err := decodeCandidate([]byte(document)); err == nil {
			t.Fatalf("hostile candidate accepted: %q as %#v", document, manifest)
		}
	}
}

func TestLoadCandidateChecksFilesystemAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require the isolated root LAB runner")
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	writeCandidate := func(content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	writeCandidate(validCandidate, 0o644)
	if err := LoadCandidate(path); err != nil {
		t.Fatalf("root candidate rejected: %v", err)
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := LoadCandidate(path); err == nil {
		t.Fatal("group-writable candidate accepted")
	}

	writeCandidate(validCandidate, 0o644)
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := LoadCandidate(path); err == nil {
		t.Fatal("non-root candidate accepted")
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if err := LoadCandidate(path); err == nil {
		t.Fatal("symbolic-link candidate accepted")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeCandidate(strings.Repeat("x", maxCandidateBytes+1), 0o644)
	if err := LoadCandidate(path); err == nil {
		t.Fatal("oversized candidate accepted")
	}

	writeCandidate(validCandidate, 0o644)
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := LoadCandidate(path); err == nil {
		t.Fatal("candidate in writable directory accepted")
	}
}
