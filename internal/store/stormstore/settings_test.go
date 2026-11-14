// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"path/filepath"
	"testing"

	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/settings"
)

func TestSettingsRepoRoundTripAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")

	key, _ := secret.NewKey()
	sealer, _ := secret.NewSealer(key)

	// First boot: seal a secret and store AI config through the service.
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc := settings.NewService(sealer, st.Settings())
	if _, err := svc.Apply("tenant-x", settings.Update{
		AI:      &settings.AIConfig{Provider: "anthropic", Model: "claude-opus-5-5"},
		Secrets: []settings.SecretUpdate{{Name: settings.SecretAIAPIKey, Value: strp("persisted-key")}},
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second boot: the same key must open the persisted secret.
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	svc2 := settings.NewService(sealer, st2.Settings())
	got, ok, err := svc2.OSINTKey("tenant-x", settings.SecretAIAPIKey)
	if err != nil || !ok {
		t.Fatalf("open persisted secret: ok=%v err=%v", ok, err)
	}
	if got != "persisted-key" {
		t.Errorf("persisted secret = %q", got)
	}
	v, _ := svc2.View("tenant-x")
	if v.AI.Provider != "anthropic" || v.AI.Model != "claude-opus-5-5" {
		t.Errorf("persisted AI config lost: %+v", v.AI)
	}
}

func strp(s string) *string { return &s }
