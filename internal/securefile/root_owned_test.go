package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRootOwnedRejectsUnsafeAuthorityFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require the isolated root LAB runner")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "authority.json")
	write := func(content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	write("ok", 0o600)
	if data, err := ReadRootOwned(path, 8); err != nil || string(data) != "ok" {
		t.Fatalf("safe authority rejected: %q %v", data, err)
	}
	write("writable", 0o666)
	if _, err := ReadRootOwned(path, 8); err == nil {
		t.Fatal("group-writable authority accepted")
	}
	write(strings.Repeat("x", 9), 0o600)
	if _, err := ReadRootOwned(path, 8); err == nil {
		t.Fatal("oversized authority accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRootOwned(path, 8); err == nil {
		t.Fatal("symbolic-link authority accepted")
	}
}
