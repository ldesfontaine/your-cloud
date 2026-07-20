package controller

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestRecoveryDerivationVectorMatchesConsoleContract(t *testing.T) {
	code := make([]byte, 32)
	salt := make([]byte, 32)
	spki := make([]byte, 32)
	for index := range code {
		code[index] = 0x5a
		salt[index] = 0x33
		spki[index] = 0x77
	}
	infrastructure, err := hex.DecodeString("123e4567e89b42d3a456426614174000")
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte("your-cloud/v0.0.3/recovery-signing\x00"), make([]byte, 8)...)
	binary.BigEndian.PutUint64(info[len("your-cloud/v0.0.3/recovery-signing\x00"):], 7)
	info = append(info, infrastructure...)
	info = append(info, spki...)
	seed, err := hkdf.Key(sha256.New, code, salt, string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := base64.RawURLEncoding.EncodeToString(seed), "LN7zfvU2WCR4AE5HECZPTIzyQWZcesuKelfj6D8aQLg"; got != want {
		t.Fatalf("recovery seed differs from the shared vector: got %q want %q", got, want)
	}
}
