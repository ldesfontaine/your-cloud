package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	telemetryv1 "github.com/lucas-desfontaine/your-cloud/protocole/gen/go"
)

const signatureDomain = "your-cloud.telemetry.v1\x00"

type Identity struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

func LoadOrCreate(stateDir string) (*Identity, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("créer le stockage d'identité: %w", err)
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("protéger le stockage d'identité: %w", err)
	}
	path := filepath.Join(stateDir, "identity.seed")
	seed, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("générer l'identité: %w", err)
		}
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, seed, 0600); err != nil {
			return nil, fmt.Errorf("écrire l'identité temporaire: %w", err)
		}
		if err := os.Rename(temporary, path); err != nil {
			_ = os.Remove(temporary)
			return nil, fmt.Errorf("publier l'identité: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("lire l'identité: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identité locale invalide")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, fmt.Errorf("protéger l'identité: %w", err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	return &Identity{private: private, public: public, keyID: hex.EncodeToString(digest[:])}, nil
}

func (i *Identity) KeyID() string { return i.keyID }

func (i *Identity) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(i.public)
}

func signingInput(stream telemetryv1.TelemetryStream, payload []byte) []byte {
	input := make([]byte, 0, len(signatureDomain)+1+len(payload))
	input = append(input, []byte(signatureDomain)...)
	input = append(input, byte(stream))
	input = append(input, payload...)
	return input
}

func (i *Identity) Sign(stream telemetryv1.TelemetryStream, payload []byte) []byte {
	return ed25519.Sign(i.private, signingInput(stream, payload))
}

func Verify(public ed25519.PublicKey, stream telemetryv1.TelemetryStream, payload, signature []byte) bool {
	return ed25519.Verify(public, signingInput(stream, payload), signature)
}
