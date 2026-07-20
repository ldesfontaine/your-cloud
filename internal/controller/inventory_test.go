package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testControllerID     = "22222222-2222-4222-8222-222222222222"
	testInfrastructureID = "11111111-1111-4111-8111-111111111111"
)

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "controller")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestCanonicalLabelAcceptsNFCAndPositiveList(t *testing.T) {
	canonical, err := CanonicalLabel("Infra e\u0301te\u0301-1 Paris")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "Infra été-1 Paris" {
		t.Fatalf("unexpected canonical label %q", canonical)
	}
	for _, hostile := range []string{
		" leading", "trailing ", "two  spaces", "<script>", "a/b", "a\\b", "a\u202Eb", "a\u200Bb", "😀", "\u0301initial",
	} {
		if _, err := CanonicalLabel(hostile); err == nil {
			t.Fatalf("hostile label %q was accepted", hostile)
		}
	}
	if _, err := CanonicalLabel(strings.Repeat("é", 81)); err == nil {
		t.Fatal("81 scalar values were accepted")
	}
}

func TestInventoryCreationInitializationAndMachineMutation(t *testing.T) {
	directory := privateTestDirectory(t)
	if err := CreateInventory(directory, testControllerID, testInfrastructureID); err != nil {
		t.Fatal(err)
	}
	if err := CreateInventory(directory, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("existing authority was replaced")
	}
	store, err := OpenInventoryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if store.Infrastructure().Initialized {
		t.Fatal("new inventory is unexpectedly initialized")
	}
	view, changed, err := store.PutInfrastructure(testInfrastructureID, "Infrastructure e\u0301te\u0301")
	if err != nil || !changed || view.InventoryRevision != 1 || view.Label == nil || *view.Label != "Infrastructure été" {
		t.Fatalf("unexpected infrastructure mutation: %#v changed=%v err=%v", view, changed, err)
	}
	if _, changed, err := store.PutInfrastructure(testInfrastructureID, "Infrastructure été"); err != nil || changed {
		t.Fatalf("canonical replay must be idempotent: changed=%v err=%v", changed, err)
	}
	if _, _, err := store.PutMachine("lab-machine-1", "Serveur 1", false); err == nil {
		t.Fatal("new machine was attached without fresh Relay authority")
	}
	machine, changed, err := store.PutMachine("lab-machine-1", "Serveur 1", true)
	if err != nil || !changed || machine.InventoryRevision != 2 {
		t.Fatalf("unexpected machine mutation: %#v changed=%v err=%v", machine, changed, err)
	}
	if _, changed, err := store.PutMachine("lab-machine-1", "Serveur 1", false); err != nil || changed {
		t.Fatalf("machine replay must not require Relay: changed=%v err=%v", changed, err)
	}
	if _, changed, err := store.PutMachine("lab-machine-1", "Serveur principal", false); err != nil || !changed {
		t.Fatalf("machine rename must remain local: changed=%v err=%v", changed, err)
	}
}

func TestInventoryFailureKeepsPreviousAuthority(t *testing.T) {
	directory := privateTestDirectory(t)
	if err := CreateInventory(directory, testControllerID, testInfrastructureID); err != nil {
		t.Fatal(err)
	}
	store, err := OpenInventoryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	store.writeState = func(Inventory) error { return os.ErrPermission }
	if _, _, err := store.PutInfrastructure(testInfrastructureID, "Principale"); err == nil {
		t.Fatal("publication failure was accepted")
	}
	if store.Infrastructure().Initialized || store.Snapshot().InventoryRevision != 0 {
		t.Fatal("failed publication changed in-memory authority")
	}
}

func TestInventoryRejectsDangerousFileShapes(t *testing.T) {
	directory := privateTestDirectory(t)
	if err := CreateInventory(directory, testControllerID, testInfrastructureID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, inventoryFileName)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInventoryStore(directory); err == nil {
		t.Fatal("overly broad file mode was accepted")
	}
}

func TestPrivateStateReaderRejectsHardLinks(t *testing.T) {
	directory := privateTestDirectory(t)
	if err := CreateInventory(directory, testControllerID, testInfrastructureID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, inventoryFileName)
	if err := os.Link(path, filepath.Join(directory, "inventory-linked.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInventoryStore(directory); err == nil {
		t.Fatal("multiply linked state file was accepted")
	}
}

func TestPrivateStateReaderRejectsSymlink(t *testing.T) {
	directory := privateTestDirectory(t)
	if err := CreateInventory(directory, testControllerID, testInfrastructureID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, inventoryFileName)
	target := filepath.Join(directory, "inventory-real.json")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInventoryStore(directory); err == nil {
		t.Fatal("symlinked state file was accepted")
	}
}
