package servicedefinition

import (
	"strings"
	"testing"
)

// TestVerifyAcceptsTheDefinitionItsDigestNames is the nominal half: the exact
// canonical bytes, and the same definition reshaped by a transport, are one
// definition under one digest — the digest is rebuilt from the parsed fields, so
// indentation is not part of what is being named.
func TestVerifyAcceptsTheDefinitionItsDigestNames(t *testing.T) {
	parsed, err := Verify([]byte(vectorReferenceDocument), vectorReferenceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := parsed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != vectorReferenceDocument {
		t.Fatalf("the verified definition is not the document that was verified: %s", encoded)
	}

	reshaped := strings.ReplaceAll(vectorReferenceDocument, `,"`, ",\n  \"")
	if reshaped == vectorReferenceDocument {
		t.Fatal("the reshaped document is the canonical one")
	}
	if _, err := Verify([]byte(reshaped), vectorReferenceSHA256); err != nil {
		t.Fatalf("a reindented transport changed the definition it carried: %v", err)
	}
}

// TestVerifyRefusesADefinitionThatIsNotItsDigest is the half the whole transport
// exists for. A definition altered by one byte no longer carries the digest a
// plan pinned, and the refusal happens before anything reads, displays or freezes
// it.
func TestVerifyRefusesADefinitionThatIsNotItsDigest(t *testing.T) {
	altered := strings.Replace(vectorReferenceDocument, `"container_port":8080`, `"container_port":8081`, 1)
	if altered == vectorReferenceDocument {
		t.Fatal("the alteration did not change the document")
	}
	if _, err := Verify([]byte(altered), vectorReferenceSHA256); err == nil {
		t.Fatal("a definition altered by one byte was accepted under the digest it came from")
	}
	if _, err := Verify([]byte(vectorReferenceDocument), vectorMinimalSHA256); err == nil {
		t.Fatal("a definition was accepted under the digest of another one")
	}
}

// TestVerifyRefusesEverySpellingOfADigestButOne keeps one value to one name: a
// freeze, a plan and a lookup are all keyed on this string, so a second spelling
// of the same digest would be a second name for one revision.
func TestVerifyRefusesEverySpellingOfADigestButOne(t *testing.T) {
	for name, digest := range map[string]string{
		"an empty digest":              "",
		"an upper-case digest":         strings.ToUpper(vectorReferenceSHA256),
		"a truncated digest":           vectorReferenceSHA256[:63],
		"a digest with one byte more":  vectorReferenceSHA256 + "00",
		"a digest naming its function": "sha256:" + vectorReferenceSHA256,
		"a digest outside hexadecimal": strings.Replace(vectorReferenceSHA256, "c", "g", 1),
		"a digest carrying a space":    vectorReferenceSHA256[:63] + " ",
	} {
		if _, err := Verify([]byte(vectorReferenceDocument), digest); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestVerifyRefusesBytesThatAreNotADefinitionBeforeAnythingElse keeps the two
// refusals in one order: bytes outside the contract are refused as bytes outside
// the contract, whatever digest accompanies them.
func TestVerifyRefusesBytesThatAreNotADefinitionBeforeAnythingElse(t *testing.T) {
	for name, document := range map[string]string{
		"nothing at all":            "",
		"a document that is a name": `"lab-notes"`,
		"a truncated document":      vectorReferenceDocument[:len(vectorReferenceDocument)-1],
		"a reserved slug":           strings.Replace(vectorMinimalDocument, `"slug":"minimal"`, `"slug":"probe"`, 1),
		"an unknown field":          strings.Replace(vectorMinimalDocument, `"schema_version":1`, `"schema_version":1,"account":"root"`, 1),
		"a document beyond its bound": strings.Replace(vectorMinimalDocument, `"environment":[]`,
			`"environment":["LAB_NOTES_TITLE=`+strings.Repeat("a", MaxDefinitionBytes)+`"]`, 1),
	} {
		if _, err := Verify([]byte(document), vectorReferenceSHA256); err == nil {
			t.Fatalf("%s was verified as a definition", name)
		}
	}
}
