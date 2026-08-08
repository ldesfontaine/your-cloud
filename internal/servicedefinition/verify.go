package servicedefinition

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Verify accepts one received definition only if it is the definition its digest
// names.
//
// It is the counterpart, function for function, of
// `verify_service_definition_document` on the Console side, and it exists for the
// same reason a definition travels as its exact canonical bytes beside its
// digest: the digest is rebuilt here from the fields parsed out of those very
// bytes and never read from what accompanied them. A transport may therefore
// reindent what it carries and can change nothing inside it, while a definition
// altered by one byte no longer carries the digest that names it and is refused
// before anything reads it, displays it or freezes it.
//
// Holding the two against one another is not the same act as hashing a document,
// and that is why it is a function rather than a comparison each caller writes:
// a caller that hashed and compared itself would decide, on its own, what an
// unequal digest means. Here it means one thing everywhere — the bytes are not
// the definition, and there is nothing further to do with them.
func Verify(document []byte, announcedSHA256 string) (Document, error) {
	// The announced digest is held to the one spelling this product writes,
	// before the document is even parsed. A second spelling of one value would be
	// a second name for one revision, and every freeze, every plan and every
	// lookup of a definition is keyed on that name.
	if !canonicalDefinitionDigest(announcedSHA256) {
		return Document{}, fmt.Errorf(
			"service definition digest must be %d lower-case hexadecimal characters", sha256.Size*2)
	}
	parsed, err := Decode(document)
	if err != nil {
		return Document{}, err
	}
	digest, err := parsed.SHA256()
	if err != nil {
		return Document{}, err
	}
	if digest != announcedSHA256 {
		return Document{}, errors.New("service definition does not carry the digest that names it")
	}
	return parsed, nil
}

// canonicalDefinitionDigest requires the exact spelling of a definition digest:
// thirty-two bytes written as lower-case hexadecimal. The round trip through the
// decoder is what refuses an upper-case or otherwise second spelling of the same
// value, which a length check and a character class alone would let through.
func canonicalDefinitionDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}
