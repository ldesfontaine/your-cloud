package controller

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

const (
	// The reference vector of `#116`, byte for byte, with the digest that palier
	// pinned. It is spelled here rather than derived so that this Controller is
	// held against the same bytes the Console and the deterministic vectors of the
	// two implementations are held against: a freeze that agreed with an encoder
	// this test called would prove only that one encoder agrees with itself.
	definitionVectorDocument = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":8080,"volumes":["/srv/notes","/var/lib/lab-notes"],` +
		`"tmpfs":["/tmp"],"environment":["LAB_NOTES_TITLE=Your Cloud lab notes",` +
		`"LAB_NOTES_ORIGIN=https://{origin_host}/","LAB_NOTES_READ_ONLY=1"],` +
		`"secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}`
	definitionVectorSHA256 = "c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce"

	definitionMinimalDocument = `{"schema_version":1,"slug":"minimal",` +
		`"image_repository":"registry.lab.your-cloud.test/minimal",` +
		`"container_port":80,"volumes":[],"tmpfs":[],"environment":[],"secret_keys":[]}`
	definitionMinimalSHA256 = "faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c"
)

func serviceDefinitionTestStore(t *testing.T) (*ServiceDefinitionStore, string) {
	t.Helper()
	directory := privateTestDirectory(t)
	store, err := OpenServiceDefinitionStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	return store, directory
}

// alterOneByte returns the document with exactly one byte replaced, and the
// digest the altered document hashes to.
//
// The alteration is a value a human could plausibly have meant — one digit of the
// container port — so that what the tests below exercise is a definition that is
// still perfectly valid and is simply not the same definition. A byte that broke
// the grammar would be refused by the decoder and would prove nothing about the
// digest.
func alterOneByte(t *testing.T, document, from, to string) (string, string) {
	t.Helper()
	if len(from) != len(to) || strings.Count(document, from) != 1 {
		t.Fatalf("the alteration %q -> %q is not one byte in one place", from, to)
	}
	altered := strings.Replace(document, from, to, 1)
	parsed, err := servicedefinition.Decode([]byte(altered))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	return altered, digest
}

func freezeTestDefinition(t *testing.T, store *ServiceDefinitionStore, document, digest string, at string) (FrozenServiceDefinition, uint64, bool) {
	t.Helper()
	frozen, revision, created, err := store.Freeze([]byte(document), digest, externalTestTime(t, at))
	if err != nil {
		t.Fatal(err)
	}
	return frozen, revision, created
}

// TestServiceDefinitionStoreFreezesRevisionsThatCoexist is the nominal life of a
// definition, and the first closing criterion of the issue: a definition altered
// by one byte is another digest, coexists with the one it came from, and leaves
// the original readable byte for byte.
func TestServiceDefinitionStoreFreezesRevisionsThatCoexist(t *testing.T) {
	store, _ := serviceDefinitionTestStore(t)
	first, revision, created := freezeTestDefinition(t, store,
		definitionVectorDocument, definitionVectorSHA256, "2026-08-08T10:00:00Z")
	if !created || revision != 1 || first.Slug != "lab-notes" ||
		first.Document != definitionVectorDocument || first.Digest != definitionVectorSHA256 ||
		first.FrozenAt != "2026-08-08T10:00:00Z" {
		t.Fatalf("the first freeze is not the definition that was submitted: %+v", first)
	}

	// A revision: the same slug, one byte apart, frozen beside the first rather
	// than over it.
	revised, revisedDigest := alterOneByte(t, definitionVectorDocument, `"container_port":8080`, `"container_port":8081`)
	if revisedDigest == definitionVectorSHA256 {
		t.Fatal("one byte of difference produced the same digest")
	}
	second, revision, created := freezeTestDefinition(t, store, revised, revisedDigest, "2026-08-08T11:00:00Z")
	if !created || revision != 2 || second.Digest != revisedDigest || second.Document != revised {
		t.Fatalf("the revision was not frozen as its own document: %+v", second)
	}

	// Nothing was replaced and nothing was erased: both revisions are held, and
	// re-reading the first returns exactly the bytes that were frozen under its
	// digest.
	state := store.Snapshot()
	if len(state.Definitions) != 2 || state.DefinitionRevision != 2 {
		t.Fatalf("the two revisions do not coexist: %+v", state)
	}
	held := map[string]FrozenServiceDefinition{}
	for _, definition := range state.Definitions {
		held[definition.Digest] = definition
	}
	if held[definitionVectorSHA256].Document != definitionVectorDocument ||
		held[revisedDigest].Document != revised ||
		held[definitionVectorSHA256].FrozenAt != "2026-08-08T10:00:00Z" ||
		held[revisedDigest].FrozenAt != "2026-08-08T11:00:00Z" {
		t.Fatalf("a frozen definition is no longer the bytes it was frozen as: %+v", state.Definitions)
	}

	// A definition of another slug is another entry again: the inventory holds
	// documents, not one document per name.
	if _, revision, created := freezeTestDefinition(t, store,
		definitionMinimalDocument, definitionMinimalSHA256, "2026-08-08T12:00:00Z"); !created || revision != 3 {
		t.Fatalf("a second slug did not enter the inventory: revision=%d created=%v", revision, created)
	}
}

// TestServiceDefinitionStoreRefusesBytesThatAreNotTheirDigest is the other half
// of the first criterion: the alteration is caught where it arrives, and the
// definition it was made from stays exactly as it was.
func TestServiceDefinitionStoreRefusesBytesThatAreNotTheirDigest(t *testing.T) {
	store, _ := serviceDefinitionTestStore(t)
	freezeTestDefinition(t, store, definitionVectorDocument, definitionVectorSHA256, "2026-08-08T10:00:00Z")
	altered, _ := alterOneByte(t, definitionVectorDocument, `"container_port":8080`, `"container_port":8081`)

	if _, _, _, err := store.Freeze([]byte(altered), definitionVectorSHA256,
		externalTestTime(t, "2026-08-08T11:00:00Z")); err == nil {
		t.Fatal("a definition was frozen under a digest that does not name it")
	}
	state := store.Snapshot()
	if len(state.Definitions) != 1 || state.DefinitionRevision != 1 ||
		state.Definitions[0].Document != definitionVectorDocument {
		t.Fatalf("a refused freeze reached the inventory: %+v", state)
	}
}

// TestServiceDefinitionStoreFreezesTheSameBytesOnce is the decision this palier
// had to take and the reason it took it: the digest is the identity of a
// definition everywhere else in the product, so freezing the same bytes twice is
// the same revision, not a second one. Nothing is erased either way — the second
// freeze finds what the first left.
func TestServiceDefinitionStoreFreezesTheSameBytesOnce(t *testing.T) {
	store, _ := serviceDefinitionTestStore(t)
	first, _, _ := freezeTestDefinition(t, store,
		definitionVectorDocument, definitionVectorSHA256, "2026-08-08T10:00:00Z")

	repeated, revision, created := freezeTestDefinition(t, store,
		definitionVectorDocument, definitionVectorSHA256, "2026-08-08T11:00:00Z")
	if created || revision != 1 || repeated != first {
		t.Fatalf("the same bytes were frozen twice: revision=%d created=%v %+v", revision, created, repeated)
	}

	// A transport that reindented the document submitted the same definition, and
	// the store says so: the received bytes are canonised before anything is
	// compared, so the spelling of the submission decides nothing.
	reindented := "{\n  \"schema_version\": 1,\n  \"slug\": \"lab-notes\",\n" +
		"  \"image_repository\": \"registry.lab.your-cloud.test/your-cloud/lab-notes\",\n" +
		"  \"container_port\": 8080,\n  \"volumes\": [\"/srv/notes\", \"/var/lib/lab-notes\"],\n" +
		"  \"tmpfs\": [\"/tmp\"],\n  \"environment\": [\"LAB_NOTES_TITLE=Your Cloud lab notes\",\n" +
		"    \"LAB_NOTES_ORIGIN=https://{origin_host}/\", \"LAB_NOTES_READ_ONLY=1\"],\n" +
		"  \"secret_keys\": [\"LAB_NOTES_ADMIN_TOKEN\"]\n}"
	reshaped, revision, created := freezeTestDefinition(t, store,
		reindented, definitionVectorSHA256, "2026-08-08T12:00:00Z")
	if created || revision != 1 || reshaped.Document != definitionVectorDocument {
		t.Fatalf("a reindented submission was not the definition it carries: %+v", reshaped)
	}
	if state := store.Snapshot(); len(state.Definitions) != 1 || state.DefinitionRevision != 1 {
		t.Fatalf("repeating a freeze duplicated a revision: %+v", state)
	}
}

// TestServiceDefinitionStoreSurvivesARestart is the second closing criterion. A
// Controller that came back holds every definition it froze, as the same bytes,
// under the same digests, at the same dates — a plan pins a definition by its
// digest, so a definition forgotten across a restart would be a plan nobody could
// ever build again.
func TestServiceDefinitionStoreSurvivesARestart(t *testing.T) {
	store, directory := serviceDefinitionTestStore(t)
	freezeTestDefinition(t, store, definitionVectorDocument, definitionVectorSHA256, "2026-08-08T10:00:00Z")
	freezeTestDefinition(t, store, definitionMinimalDocument, definitionMinimalSHA256, "2026-08-08T11:00:00Z")
	before := store.Snapshot()

	restarted, err := OpenServiceDefinitionStore(directory, testControllerID, testInfrastructureID)
	if err != nil {
		t.Fatal(err)
	}
	after := restarted.Snapshot()
	if after.DefinitionRevision != before.DefinitionRevision || len(after.Definitions) != len(before.Definitions) {
		t.Fatalf("the restarted Controller holds another inventory: %+v", after)
	}
	for index, definition := range after.Definitions {
		if definition != before.Definitions[index] {
			t.Fatalf("a definition changed across the restart: %+v", definition)
		}
	}

	// The restarted Controller knows what it holds rather than merely carrying it:
	// the bytes of a definition it read from the file are still the same revision,
	// so a restart is not a way to freeze a duplicate of something already frozen.
	if _, revision, created := freezeTestDefinition(t, restarted,
		definitionVectorDocument, definitionVectorSHA256, "2026-08-08T12:00:00Z"); created || revision != 2 {
		t.Fatalf("the restarted Controller re-froze a definition it already held: revision=%d created=%v", revision, created)
	}
}

// TestServiceDefinitionStoreRefusesAForeignOrEditedDocument keeps this inventory
// as fail-closed as the two before it, and adds the check only this one can make:
// a document whose bytes are no longer the definition its digest names is refused
// at the read, so a Controller never serves a definition somebody edited under it.
func TestServiceDefinitionStoreRefusesAForeignOrEditedDocument(t *testing.T) {
	store, directory := serviceDefinitionTestStore(t)
	freezeTestDefinition(t, store, definitionVectorDocument, definitionVectorSHA256, "2026-08-08T10:00:00Z")
	path := filepath.Join(directory, serviceDefinitionFileName)

	if _, err := OpenServiceDefinitionStore(directory, testControllerID, "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("the definitions of another infrastructure were opened")
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(original), `container_port\":8080`, `container_port\":8081`, 1)
	if edited == string(original) {
		t.Fatal("the stored document was not the one this test edits")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenServiceDefinitionStore(directory, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("a definition edited under the Controller was served as frozen")
	}

	if err := os.WriteFile(path, []byte(`{"schema_version":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenServiceDefinitionStore(directory, testControllerID, testInfrastructureID); err == nil {
		t.Fatal("a corrupt definitions document was opened as an empty one")
	}
}

// TestServiceDefinitionReservedSlugsAreTheNamesTheOtherDoorsAnswerTo is the debt
// `#116` left where it could not be paid: the definitions package spells its four
// reserved names itself, because a definition depends on no plan schema, and this
// is the one place both lists are in scope.
//
// Two of the four are held against the constants that define them. The other two
// are pinned literals, and they are pinned on purpose: the product spells `probe`
// and `entrypoint` only inside account names — `your-cloud-probe` and
// `your-cloud-entrypoint` in internal/auxiliary — so there is no constant whose
// value is the bare name, and inventing one in the effect package to satisfy a
// test would be the wrong direction of dependency. What this test therefore holds
// is the fact that matters: none of the four names another door answers to can
// ever become a definition, and a name outside them can.
//
// The reserved set cannot be enumerated from here — it is private to the
// definitions package, as it should be — so the exhaustiveness this test proves
// is the one that carries the risk: every delivered name is refused. A fifth name
// reserved by mistake would be caught by the definition package's own tests, not
// by this one.
func TestServiceDefinitionReservedSlugsAreTheNamesTheOtherDoorsAnswerTo(t *testing.T) {
	if plan.ServiceProfileBentoPDF != "bentopdf" || plan.ServiceProfileVaultwarden != "vaultwarden" {
		t.Fatalf("the delivered profiles are spelled %q and %q",
			plan.ServiceProfileBentoPDF, plan.ServiceProfileVaultwarden)
	}
	for _, reserved := range []string{
		plan.ServiceProfileBentoPDF, plan.ServiceProfileVaultwarden, "probe", "entrypoint",
	} {
		document := strings.Replace(definitionMinimalDocument, `"slug":"minimal"`, `"slug":"`+reserved+`"`, 1)
		if _, err := servicedefinition.Decode([]byte(document)); err == nil {
			t.Fatalf("a definition took the name %q another door already answers to", reserved)
		}
	}
	// The control: the reservation is four names and not a family of them, so a
	// name that merely resembles one is a definition like any other.
	for _, allowed := range []string{"bentopdf2", "my-vaultwarden", "probes", "entry-point"} {
		document := strings.Replace(definitionMinimalDocument, `"slug":"minimal"`, `"slug":"`+allowed+`"`, 1)
		if _, err := servicedefinition.Decode([]byte(document)); err != nil {
			t.Fatalf("the slug %q was refused: %v", allowed, err)
		}
	}
}

// TestServiceDefinitionsCannotReachThePlanSurface is the third closing criterion,
// held as a property of what the two files import rather than as a discipline of
// review: the path a definition takes through this Controller receives nothing
// with which to build a plan, sign an envelope or apply anything to a machine.
//
// It is the test `#106` wrote for the declared inventory, applied to the frozen
// one for the same reason: freezing must have no effect, and the strongest way to
// say so is that the code that freezes cannot reach anything that acts.
func TestServiceDefinitionsCannotReachThePlanSurface(t *testing.T) {
	for _, name := range []string{"service_definitions.go", "service_definitions_http.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			for _, forbidden := range []string{"internal/plan", "internal/approval", "internal/auxiliary"} {
				if strings.Contains(imported.Path.Value, forbidden) {
					t.Fatalf("%s imports %s: freezing a definition must have no path to a plan", name, forbidden)
				}
			}
		}
	}
}

// TestServiceDefinitionFreezeTimeIsMintedByTheController pins the one field of a
// frozen definition that no submission carries. Which revision of a slug is the
// latest is read off this date, so a caller able to name it could make one
// revision look like the successor of another it preceded.
func TestServiceDefinitionFreezeTimeIsMintedByTheController(t *testing.T) {
	store, _ := serviceDefinitionTestStore(t)
	frozen, _, _ := freezeTestDefinition(t, store,
		definitionVectorDocument, definitionVectorSHA256, "2026-08-08T10:00:00.123456789Z")
	if frozen.FrozenAt != "2026-08-08T10:00:00.123456789Z" {
		t.Fatalf("frozen_at is not the canonical UTC instant of the freeze: %q", frozen.FrozenAt)
	}
	if _, err := parseCanonicalUTC(frozen.FrozenAt); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Freeze([]byte(definitionMinimalDocument), definitionMinimalSHA256,
		time.Date(2026, 8, 8, 12, 0, 0, 0, time.FixedZone("CEST", 2*3600))); err != nil {
		t.Fatal(err)
	}
	for _, definition := range store.Snapshot().Definitions {
		if !strings.HasSuffix(definition.FrozenAt, "Z") {
			t.Fatalf("a freeze was dated outside UTC: %q", definition.FrozenAt)
		}
	}
}
