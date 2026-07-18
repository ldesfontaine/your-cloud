package enrollment

import (
	"crypto/x509"
	"errors"
	"sync"

	"github.com/ldesfontaine/your-cloud/internal/securefile"
)

const (
	// RegistryPath is fixed so a Relay argument cannot grant authority to an
	// arbitrary file.
	RegistryPath = "/etc/your-cloud/enrollment.json"
)

// Store atomically swaps a fully validated registry on explicit reload.
type Store struct {
	mu       sync.RWMutex
	path     string
	registry *Registry
}

// OpenStore reads the initial root-provisioned policy before any listener.
func OpenStore(path string) (*Store, error) {
	store := &Store{path: path}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload leaves the previous policy active if reading or validation fails.
func (store *Store) Reload() error {
	if store == nil || store.path == "" {
		return errors.New("enrollment store path is required")
	}
	data, err := securefile.ReadRootOwned(store.path, MaxRegistryBytes)
	if err != nil {
		return err
	}
	registry, err := Decode(data)
	if err != nil {
		return err
	}
	store.mu.Lock()
	store.registry = registry
	store.mu.Unlock()
	return nil
}

// Authorize checks the current policy for every request.
func (store *Store) Authorize(certificate *x509.Certificate) (string, error) {
	store.mu.RLock()
	registry := store.registry
	store.mu.RUnlock()
	if registry == nil {
		return "", errors.New("enrollment policy is unavailable")
	}
	return registry.Authorize(certificate)
}
