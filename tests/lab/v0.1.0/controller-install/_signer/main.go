// Command lab-bundle-signer produces the synthetic anchor of the LAB and the
// detached Ed25519 signature over the exact bytes of a bundle manifest.
//
// It stands in for whatever seals the anchor into the App installer, and it
// proves nothing about that mechanism: the identity here is generated at mount
// time, it is thrown away at teardown, and no public claim rests on it. What it
// does let the LAB show is the half that matters — that the Assistant refuses a
// manifest this key did not sign, and that it refuses one this key signed for
// another artefact.
//
// It signs the file's bytes verbatim. There is deliberately no canonicalisation
// step: the signature covers what is on disk, so no re-rendering can ever be
// the difference between a manifest that verifies and one that does not.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
)

func main() {
	seed := flag.String("seed", "", "path to a 32-byte private seed file")
	manifest := flag.String("manifest", "", "path to the manifest whose bytes are signed")
	anchor := flag.String("anchor", "", "path receiving the 32-byte public anchor")
	signature := flag.String("signature", "", "path receiving the 64-byte detached signature")
	flag.Parse()

	if err := run(*seed, *manifest, *anchor, *signature); err != nil {
		fmt.Fprintf(os.Stderr, "lab-bundle-signer: %v\n", err)
		os.Exit(1)
	}
}

func run(seedPath, manifestPath, anchorPath, signaturePath string) error {
	if seedPath == "" || manifestPath == "" || anchorPath == "" || signaturePath == "" {
		return fmt.Errorf("-seed, -manifest, -anchor and -signature are all required")
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("the seed must be exactly %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	document, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	private := ed25519.NewKeyFromSeed(seed)
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("the derived public key is not an Ed25519 key")
	}
	if err := os.WriteFile(anchorPath, public, 0o644); err != nil {
		return err
	}
	return os.WriteFile(signaturePath, ed25519.Sign(private, document), 0o644)
}
