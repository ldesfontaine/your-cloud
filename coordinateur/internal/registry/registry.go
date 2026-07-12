package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type entry struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
}

type document struct {
	SchemaVersion int              `json:"schema_version"`
	Identities    map[string]entry `json:"identities"`
}

// Registry contient uniquement les clés publiques actives dérivées de la console.
type Registry struct {
	keys map[string]ed25519.PublicKey
	ids  map[string]string
}

// Load valide la copie publique des identités sans accepter de secret de flotte.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lire le registre public: %w", err)
	}
	var raw document
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("registre public JSON invalide: %w", err)
	}
	if (raw.SchemaVersion != 1 && raw.SchemaVersion != 2) || raw.Identities == nil {
		return nil, fmt.Errorf("registre public de version inconnue")
	}
	result := &Registry{keys: make(map[string]ed25519.PublicKey), ids: make(map[string]string)}
	for machineID, item := range raw.Identities {
		if item.Status != "active" {
			continue
		}
		if item.Algorithm != "Ed25519" {
			return nil, fmt.Errorf("algorithme refusé pour %s", machineID)
		}
		public, err := base64.StdEncoding.DecodeString(item.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("clé publique invalide pour %s", machineID)
		}
		digest := sha256.Sum256(public)
		if hex.EncodeToString(digest[:]) != item.KeyID {
			return nil, fmt.Errorf("identifiant de clé incohérent pour %s", machineID)
		}
		result.keys[machineID] = ed25519.PublicKey(public)
		result.ids[machineID] = item.KeyID
	}
	return result, nil
}

// Identity retourne la clé active attendue pour une machine autorisée.
func (r *Registry) Identity(machineID string) (string, ed25519.PublicKey, bool) {
	key, ok := r.keys[machineID]
	return r.ids[machineID], key, ok
}
