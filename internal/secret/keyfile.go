// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package secret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrKeyFileExists is returned by SaveKeyFile when the target already holds a
// key, so setup can never silently clobber the key that opens existing secrets.
var ErrKeyFileExists = errors.New("secret: key file already exists")

// keyFileMode keeps the master-key file readable only by its owner.
const keyFileMode os.FileMode = 0o600

// LoadKeyFile reads a base64-encoded master key from path and validates it.
func LoadKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled key path
	if err != nil {
		return nil, fmt.Errorf("secret: read key file: %w", err)
	}
	return DecodeKey(string(data))
}

// SaveKeyFile writes key to path as base64 with owner-only permissions. It
// refuses to overwrite an existing file (ErrKeyFileExists): losing the key that
// sealed the live secrets would make them unrecoverable, so replacement must be
// a deliberate, separate act.
func SaveKeyFile(path string, key []byte) error {
	if len(key) != KeySize {
		return ErrKeySize
	}
	if _, err := os.Stat(path); err == nil {
		return ErrKeyFileExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secret: stat key file: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("secret: key dir: %w", err)
		}
	}
	// Create exclusively so a concurrent setup cannot race us to the file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrKeyFileExists
		}
		return fmt.Errorf("secret: create key file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(EncodeKey(key)); err != nil {
		return fmt.Errorf("secret: write key file: %w", err)
	}
	return f.Chmod(keyFileMode)
}

// SealerFromFile loads a master key from path and returns a Sealer over it.
func SealerFromFile(path string) (*Sealer, error) {
	key, err := LoadKeyFile(path)
	if err != nil {
		return nil, err
	}
	return NewSealer(key)
}
