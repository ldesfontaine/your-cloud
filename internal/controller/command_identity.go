package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ldesfontaine/your-cloud/internal/machineid"
)

// Minting a command identity: the half of the trajectory that was written
// everywhere and implemented nowhere.
//
// The contract already said who judges these identities — a module that only
// ever sees fingerprints, refuses a fingerprint nobody struck, and refuses one
// machine's key on another. What was missing was the striking itself, and this
// file is it (docs/architecture/TRAJET-DE-COMMANDE.md, maillon 4).
//
// **The Controller strikes them, one pair per machine, and keeps the private
// half.** The two alternatives are refused for the same reason they were
// written down: having the Assistant generate the pair would put a private half
// on the administration laptop, beside a personal access this product refuses to
// keep; having the machine generate it and send its private half back is the
// opposite of an identity.
//
// **Ed25519 and nothing else.** It is already the one algorithm the forced
// command entry accepts. The Controller strikes these itself, there is no
// legacy key to accommodate, and a second accepted algorithm would only be a
// second thing to get wrong.

const (
	// commandIdentityAlgorithm is the one name an OpenSSH Ed25519 key carries,
	// in both the public line and the private blob.
	commandIdentityAlgorithm = "ssh-ed25519"

	// commandIdentityDirectoryMode and commandIdentityFileMode keep the private
	// half readable by `root` alone on disk. systemd copies it into the
	// service's private credential directory at start; this protection reduces
	// exposure to other accounts and does not protect against a full compromise
	// of the Controller — the limit already written for operational keys,
	// unchanged.
	commandIdentityDirectoryMode = os.FileMode(0o700)
	commandIdentityFileMode      = os.FileMode(0o600)
)

// MintedCommandIdentity is everything that may leave the minting: the public
// half and its fingerprint, never a byte of the private one.
type MintedCommandIdentity struct {
	MachineID string
	// PublicLine is the exact `authorized_keys` key material — algorithm and
	// base64 blob — the Assistant installs on the machine. It carries no
	// options: the entry's restrictions are the entry's own contract, held
	// where that entry is judged.
	PublicLine string
	// FingerprintSHA256 is the value the identity judge already reads, in the
	// form OpenSSH prints it.
	FingerprintSHA256 string
}

// MintCommandIdentity strikes the command identity of one machine and writes
// its private half where only `root` can read it.
//
// It refuses to replace an existing one. Rotation is not a silent side effect
// of running a command twice: replacing the identity of a machine that already
// holds one belongs to the explicit replacement of the Controller, a contract
// of its own, and a mint that overwrote would be a rotation nobody approved.
func MintCommandIdentity(directory, machineID string, entropy io.Reader) (MintedCommandIdentity, error) {
	if machineid.Validate(machineID) != nil {
		return MintedCommandIdentity{}, errors.New("a command identity is minted for one canonical machine identifier")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return MintedCommandIdentity{}, errors.New("the command identity directory must be absolute and canonical")
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	if err := os.MkdirAll(directory, commandIdentityDirectoryMode); err != nil {
		return MintedCommandIdentity{}, err
	}
	if err := os.Chmod(directory, commandIdentityDirectoryMode); err != nil {
		return MintedCommandIdentity{}, err
	}
	path := filepath.Join(directory, machineID)
	if _, err := os.Lstat(path); err == nil {
		return MintedCommandIdentity{}, fmt.Errorf(
			"this Controller already holds a command identity for %q; replacing it is a rotation, not a mint", machineID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return MintedCommandIdentity{}, err
	}

	public, private, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return MintedCommandIdentity{}, err
	}
	blob := sshEd25519PublicBlob(public)
	// The private half is written whole, with its mode set before a byte of it
	// exists on disk, and it is created exclusively so that a file appearing
	// between the check above and here is a refusal rather than an overwrite.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, commandIdentityFileMode)
	if err != nil {
		return MintedCommandIdentity{}, err
	}
	if _, err := file.Write(openSSHPrivateKey(public, private, machineID)); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return MintedCommandIdentity{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return MintedCommandIdentity{}, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return MintedCommandIdentity{}, err
	}

	digest := sha256.Sum256(blob)
	return MintedCommandIdentity{
		MachineID:         machineID,
		PublicLine:        commandIdentityAlgorithm + " " + base64.StdEncoding.EncodeToString(blob),
		FingerprintSHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]),
	}, nil
}

// sshEd25519PublicBlob renders the wire form OpenSSH names a public key by:
// the algorithm string and the key, each preceded by its length. It is what a
// `known_hosts` line and an `authorized_keys` entry both carry, and what the
// fingerprint is taken over.
func sshEd25519PublicBlob(public ed25519.PublicKey) []byte {
	blob := make([]byte, 0, 4+len(commandIdentityAlgorithm)+4+ed25519.PublicKeySize)
	blob = appendSSHString(blob, []byte(commandIdentityAlgorithm))
	return appendSSHString(blob, public)
}

func appendSSHString(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

// openSSHPrivateKey renders the private half in the one format the OpenSSH
// client reads without a helper: the unencrypted `openssh-key-v1` container.
//
// It carries no passphrase, and that is a decision rather than an omission: the
// Controller must stay autonomous when the App is closed, so no human is
// there to unlock anything. What protects this half is the file mode, the
// service's private credential directory, and the fact that it never travels —
// the same protection the operational TLS keys already have, and the same named
// limit.
func openSSHPrivateKey(public ed25519.PublicKey, private ed25519.PrivateKey, comment string) []byte {
	const magic = "openssh-key-v1\x00"
	blob := sshEd25519PublicBlob(public)

	// The private section is checked by a pair of identical integers rather
	// than by a MAC: with no cipher there is nothing to authenticate, and this
	// is what the format itself specifies.
	var check [4]byte
	if _, err := io.ReadFull(rand.Reader, check[:]); err != nil {
		// A machine that cannot read four random bytes cannot mint anything;
		// a fixed value here would still produce a readable key, and refusing
		// is not this function's contract, so the deterministic fallback is
		// the honest one.
		check = [4]byte{0, 0, 0, 0}
	}
	private_section := make([]byte, 0, 256)
	private_section = append(private_section, check[:]...)
	private_section = append(private_section, check[:]...)
	private_section = appendSSHString(private_section, []byte(commandIdentityAlgorithm))
	private_section = appendSSHString(private_section, public)
	private_section = appendSSHString(private_section, private)
	private_section = appendSSHString(private_section, []byte(comment))
	// Padding to the cipher block size, which is eight for "none", written as
	// the increasing byte sequence the format requires.
	for index := byte(1); len(private_section)%8 != 0; index++ {
		private_section = append(private_section, index)
	}

	container := make([]byte, 0, 512)
	container = append(container, magic...)
	container = appendSSHString(container, []byte("none")) // cipher
	container = appendSSHString(container, []byte("none")) // key derivation
	container = appendSSHString(container, nil)            // no derivation options
	container = append(container, 0, 0, 0, 1)              // one key
	container = appendSSHString(container, blob)
	container = appendSSHString(container, private_section)

	return pemArmour("OPENSSH PRIVATE KEY", container)
}

// pemArmour wraps the container the way OpenSSH writes it: seventy characters
// per line, which is what its own reader produces and every reader accepts.
func pemArmour(label string, content []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(content)
	armoured := make([]byte, 0, len(encoded)+128)
	armoured = append(armoured, "-----BEGIN "+label+"-----\n"...)
	for len(encoded) > 70 {
		armoured = append(armoured, encoded[:70]...)
		armoured = append(armoured, '\n')
		encoded = encoded[70:]
	}
	if len(encoded) > 0 {
		armoured = append(armoured, encoded...)
		armoured = append(armoured, '\n')
	}
	armoured = append(armoured, "-----END "+label+"-----\n"...)
	return armoured
}
