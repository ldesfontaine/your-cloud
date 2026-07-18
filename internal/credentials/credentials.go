// Package credentials loads fixed systemd credential names without allowing a
// role to select arbitrary authority or private-key paths.
package credentials

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxCredentialBytes = int64(32 * 1024)

// DirectoryEnvironment is set by systemd for units using LoadCredential.
const DirectoryEnvironment = "CREDENTIALS_DIRECTORY"

// LoadPair reads one fixed certificate/key pair from the credential directory.
func LoadPair(directory, certificateName, keyName string) (tls.Certificate, error) {
	certificatePEM, err := read(directory, certificateName)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read certificate credential: %w", err)
	}
	keyPEM, err := read(directory, keyName)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read private-key credential: %w", err)
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load credential pair: %w", err)
	}
	return pair, nil
}

// LoadPublic reads one fixed public certificate bundle.
func LoadPublic(directory, name string) ([]byte, error) {
	return read(directory, name)
}

func read(directory, name string) ([]byte, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("credential directory must be absolute and canonical")
	}
	if filepath.Base(name) != name || name == "." || name == "" {
		return nil, errors.New("credential name must be one fixed base name")
	}
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxCredentialBytes {
		return nil, errors.New("credential has unsafe type or size")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil || int64(len(data)) > maxCredentialBytes {
		return nil, errors.New("credential cannot be read within its limit")
	}
	return data, nil
}
