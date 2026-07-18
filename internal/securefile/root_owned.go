// Package securefile reads small root-provisioned authority files through one
// descriptor without following a final symbolic link.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ReadRootOwned returns 1..maximum bytes from a canonical file in a private,
// root-owned real directory.
func ReadRootOwned(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("maximum file size must be positive")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("authority file path must be absolute and canonical")
	}
	if err := validateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("authority directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open authority file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect authority file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("authority file must be regular")
	}
	if err := validateRootOwnedMode(info); err != nil {
		return nil, fmt.Errorf("authority file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read authority file: %w", err)
	}
	if len(data) == 0 || int64(len(data)) > maximum {
		return nil, fmt.Errorf("authority file must contain 1..%d bytes", maximum)
	}
	return data, nil
}

func validateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("must be a real directory")
	}
	return validateRootOwnedMode(info)
}

func validateRootOwnedMode(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ownership is unavailable")
	}
	if stat.Uid != 0 {
		return errors.New("must be owned by root")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("must not be writable by group or others")
	}
	return nil
}
