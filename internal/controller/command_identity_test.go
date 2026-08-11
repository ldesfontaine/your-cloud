package controller

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMintingKeepsThePrivateHalfAndHandsOverOnlyThePublicOne is the property the
// whole trajectory rests on: the Controller strikes the pair, the private half
// stays on its disk readable by nobody else, and what may be carried to the
// machine is the public half and its fingerprint — never a byte of the other.
func TestMintingKeepsThePrivateHalfAndHandsOverOnlyThePublicOne(t *testing.T) {
	directory := filepath.Join(privateTestDirectory(t), "command-identities")

	minted, err := MintCommandIdentity(directory, "lab-machine-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if minted.MachineID != "lab-machine-1" {
		t.Fatalf("the mint named another machine: %+v", minted)
	}
	if !strings.HasPrefix(minted.PublicLine, "ssh-ed25519 ") {
		t.Fatalf("the public half is not the one algorithm the entry accepts: %q", minted.PublicLine)
	}
	if !strings.HasPrefix(minted.FingerprintSHA256, "SHA256:") {
		t.Fatalf("the fingerprint is not in the form the identity judge reads: %q", minted.FingerprintSHA256)
	}

	path := filepath.Join(directory, "lab-machine-1")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the private half is readable by someone else: %v", info.Mode().Perm())
	}
	if parent, err := os.Stat(directory); err != nil || parent.Mode().Perm() != 0o700 {
		t.Fatalf("the identity directory is not private: %v %v", parent, err)
	}

	// The private half is a real key the client would read, and no part of it
	// appears in anything the mint hands back.
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(stored, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n")) ||
		!bytes.HasSuffix(stored, []byte("-----END OPENSSH PRIVATE KEY-----\n")) {
		t.Fatalf("the private half is not a key the OpenSSH client reads:\n%s", stored)
	}
	body := bytes.ReplaceAll(stored, []byte("\n"), nil)
	body = bytes.TrimPrefix(body, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"))
	body = bytes.TrimSuffix(body, []byte("-----END OPENSSH PRIVATE KEY-----"))
	container, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("the container is not readable: %v", err)
	}
	if !bytes.HasPrefix(container, []byte("openssh-key-v1\x00")) {
		t.Fatal("the container is not the openssh-key-v1 one")
	}
	// The public half really is the one this container holds, and the two are
	// one pair rather than two unrelated keys.
	public, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(minted.PublicLine, "ssh-ed25519 "))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(container, public) {
		t.Fatal("the public half handed over is not the one the stored container holds")
	}
	seed := container[len(container)-ed25519.PrivateKeySize-32:]
	if bytes.Contains([]byte(minted.PublicLine+minted.FingerprintSHA256), seed[:16]) {
		t.Fatal("a fragment of the private half travelled with the public one")
	}
}

// TestMintingRefusesToRotateSilently: replacing the identity of a machine that
// already holds one belongs to the explicit replacement of the Controller. A
// mint that overwrote would be a rotation nobody approved, and the machine
// would stop answering the key this Controller holds.
func TestMintingRefusesToRotateSilently(t *testing.T) {
	directory := filepath.Join(privateTestDirectory(t), "command-identities")
	first, err := MintCommandIdentity(directory, "lab-machine-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, "lab-machine-1"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := MintCommandIdentity(directory, "lab-machine-1", nil); err == nil {
		t.Fatal("a second mint replaced an existing command identity")
	}

	after, err := os.ReadFile(filepath.Join(directory, "lab-machine-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused mint still touched the private half")
	}
	// And another machine gets its own pair: one identity per machine, never
	// one key spread over a fleet.
	second, err := MintCommandIdentity(directory, "lab-machine-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.PublicLine == first.PublicLine {
		t.Fatal("two machines were given the same command identity")
	}
}

// TestMintingRefusesWhatItCouldNotOwn: a mint names one canonical machine and
// one absolute directory, so nothing can be written beside a path a caller
// composed.
func TestMintingRefusesWhatItCouldNotOwn(t *testing.T) {
	directory := filepath.Join(privateTestDirectory(t), "command-identities")
	for name, machine := range map[string]string{
		"an empty identifier":     "",
		"a traversal":             "../../etc/passwd",
		"an uppercase identifier": "LAB-MACHINE-1",
		"a separator":             "lab/machine",
	} {
		if _, err := MintCommandIdentity(directory, machine, nil); err == nil {
			t.Fatalf("%s was minted", name)
		}
	}
	if _, err := MintCommandIdentity("relative/path", "lab-machine-1", nil); err == nil {
		t.Fatal("a relative identity directory was accepted")
	}
}

// TestAMintedIdentityIsReadByOpenSSHItself is the proof that matters more than
// the structural ones above: the format is not asserted against this file's own
// understanding of it, it is handed to the very tool suite the other end of the
// trajectory runs.
//
// `ssh-keygen` reads the private half, derives a public half from it, and prints
// a fingerprint. Both must be exactly what the mint handed over — a container
// that decoded but held another key, or a fingerprint taken over the wrong
// bytes, would pass every assertion above and fail here.
//
// The test skips where the suite is absent rather than pretending: a machine
// without OpenSSH is a machine that cannot run this proof, and saying so is
// better than a green that proved nothing.
func TestAMintedIdentityIsReadByOpenSSHItself(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("this machine holds no ssh-keygen: the format proof cannot be run here")
	}
	directory := filepath.Join(privateTestDirectory(t), "command-identities")
	minted, err := MintCommandIdentity(directory, "lab-machine-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "lab-machine-1")

	derived, err := exec.Command(keygen, "-y", "-f", path).Output()
	if err != nil {
		t.Fatalf("OpenSSH could not read the minted private half: %v", err)
	}
	// `ssh-keygen -y` prints the key material followed by the comment.
	if !strings.HasPrefix(strings.TrimSpace(string(derived)), minted.PublicLine) {
		t.Fatalf("OpenSSH derives %q from the private half, not the public line handed over (%q)",
			strings.TrimSpace(string(derived)), minted.PublicLine)
	}

	printed, err := exec.Command(keygen, "-lf", path).Output()
	if err != nil {
		t.Fatalf("OpenSSH could not fingerprint the minted private half: %v", err)
	}
	if !strings.Contains(string(printed), minted.FingerprintSHA256) {
		t.Fatalf("OpenSSH prints %q, not the fingerprint handed over (%q)",
			strings.TrimSpace(string(printed)), minted.FingerprintSHA256)
	}
	if !strings.Contains(string(printed), "ED25519") {
		t.Fatalf("the minted identity is not an Ed25519 one: %q", strings.TrimSpace(string(printed)))
	}
}
