// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ares.key")
	key, _ := NewKey()
	if err := SaveKeyFile(path, key); err != nil {
		t.Fatalf("SaveKeyFile: %v", err)
	}
	// Permissions must be owner-only.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("key file perm = %o, want %o", perm, keyFileMode)
	}
	got, err := LoadKeyFile(path)
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	if string(got) != string(key) {
		t.Error("loaded key differs from saved key")
	}
}

func TestSaveKeyFileRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.key")
	key, _ := NewKey()
	if err := SaveKeyFile(path, key); err != nil {
		t.Fatalf("first save: %v", err)
	}
	other, _ := NewKey()
	if err := SaveKeyFile(path, other); err != ErrKeyFileExists {
		t.Errorf("overwrite err = %v, want ErrKeyFileExists", err)
	}
	// The original key must be intact.
	got, _ := LoadKeyFile(path)
	if string(got) != string(key) {
		t.Error("existing key was clobbered")
	}
}

func TestSealerFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.key")
	key, _ := NewKey()
	if err := SaveKeyFile(path, key); err != nil {
		t.Fatalf("save: %v", err)
	}
	s, err := SealerFromFile(path)
	if err != nil {
		t.Fatalf("SealerFromFile: %v", err)
	}
	sealed, _ := s.SealString("hello")
	got, _ := s.OpenString(sealed)
	if got != "hello" {
		t.Errorf("round trip via file sealer = %q", got)
	}
}
