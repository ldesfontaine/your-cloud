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

	telemetryv1 "github.com/ldesfontaine/yourcloud/protocole/gen/go"
)

const signatureDomain = "your-cloud.telemetry.v1\x00"
const (
	currentSeed  = "identity.seed"
	pendingSeed  = "identity.seed.pending"
	previousSeed = "identity.seed.previous"
)

// Identity détient la clé privée propre à une machine et son identifiant public.
type Identity struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

// LoadOrCreate reprend l'identité locale ou en crée une sans exporter sa clé privée.
func LoadOrCreate(stateDir string) (*Identity, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("créer le stockage d'identité: %w", err)
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("protéger le stockage d'identité: %w", err)
	}
	path := filepath.Join(stateDir, currentSeed)
	return loadOrCreatePath(path)
}

func loadOrCreatePath(path string) (*Identity, error) {
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

// PrepareRenewal crée une identité candidate sans modifier l'identité active.
func PrepareRenewal(stateDir string) (*Identity, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("créer le stockage d'identité: %w", err)
	}
	pending, err := loadOrCreatePath(filepath.Join(stateDir, pendingSeed))
	if err != nil {
		return nil, err
	}
	current, err := LoadOrCreate(stateDir)
	if err != nil {
		return nil, err
	}
	if pending.KeyID() == current.KeyID() {
		return nil, fmt.Errorf("identité candidate identique à l'identité active")
	}
	return pending, nil
}

// CommitRenewal active la candidate en conservant l'ancienne pour rollback.
func CommitRenewal(stateDir string) error {
	current := filepath.Join(stateDir, currentSeed)
	pending := filepath.Join(stateDir, pendingSeed)
	previous := filepath.Join(stateDir, previousSeed)
	if _, err := os.Stat(pending); err != nil {
		return fmt.Errorf("identité candidate absente: %w", err)
	}
	if _, err := os.Stat(previous); err == nil {
		return fmt.Errorf("rollback précédent encore présent")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspecter le rollback d'identité: %w", err)
	}
	if err := os.Rename(current, previous); err != nil {
		return fmt.Errorf("préparer le rollback d'identité: %w", err)
	}
	if err := os.Rename(pending, current); err != nil {
		_ = os.Rename(previous, current)
		return fmt.Errorf("activer l'identité candidate: %w", err)
	}
	return nil
}

// RollbackRenewal restaure l'identité précédente après un échec vérifié.
func RollbackRenewal(stateDir string) error {
	current := filepath.Join(stateDir, currentSeed)
	previous := filepath.Join(stateDir, previousSeed)
	failed := filepath.Join(stateDir, pendingSeed)
	if _, err := os.Stat(previous); err != nil {
		return fmt.Errorf("identité précédente absente: %w", err)
	}
	if err := os.Rename(current, failed); err != nil {
		return fmt.Errorf("isoler l'identité échouée: %w", err)
	}
	if err := os.Rename(previous, current); err != nil {
		_ = os.Rename(failed, current)
		return fmt.Errorf("restaurer l'identité précédente: %w", err)
	}
	return nil
}

// FinalizeRenewal retire le rollback seulement après preuve de la nouvelle identité.
func FinalizeRenewal(stateDir string) error {
	path := filepath.Join(stateDir, previousSeed)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("retirer l'identité précédente: %w", err)
	}
	return nil
}

// KeyID retourne l'empreinte stable qui désigne la clé publique.
func (i *Identity) KeyID() string { return i.keyID }

// PublicBase64 expose uniquement la partie publique de l'identité.
func (i *Identity) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(i.public)
}

// signingInput sépare le domaine et le flux avant de joindre le payload exact.
func signingInput(stream telemetryv1.TelemetryStream, payload []byte) []byte {
	input := make([]byte, 0, len(signatureDomain)+1+len(payload))
	input = append(input, []byte(signatureDomain)...)
	input = append(input, byte(stream))
	input = append(input, payload...)
	return input
}

// Sign signe les octets exacts d'un payload pour un flux donné.
func (i *Identity) Sign(stream telemetryv1.TelemetryStream, payload []byte) []byte {
	return ed25519.Sign(i.private, signingInput(stream, payload))
}

// Verify contrôle une signature avec la même séparation de domaine que Sign.
func Verify(public ed25519.PublicKey, stream telemetryv1.TelemetryStream, payload, signature []byte) bool {
	return ed25519.Verify(public, signingInput(stream, payload), signature)
}
