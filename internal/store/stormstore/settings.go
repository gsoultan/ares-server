// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"fmt"

	"github.com/asdine/storm/v3"

	"github.com/gsoultan/ares-server/internal/settings"
)

// settingsRecord is the on-disk shape of one workspace's settings. Secrets are
// stored already sealed (ciphertext), so the database never holds a plaintext
// credential. Storm keeps this type in its own bucket, keyed by tenant id.
type settingsRecord struct {
	TenantID string `storm:"id"`
	AI       settings.AIConfig
	Secrets  map[string]settings.SealedSecret
}

// SettingsRepo is a durable settings.Repo backed by the same Storm database as
// the engagement store. It is a distinct type (not Store) so its Get/Put do not
// collide with the engagement store's own Get/Put.
type SettingsRepo struct {
	db *storm.DB
}

var _ settings.Repo = (*SettingsRepo)(nil)

// Settings returns a durable settings repository over this store's database.
func (s *Store) Settings() *SettingsRepo { return &SettingsRepo{db: s.db} }

// Get returns a workspace's stored settings, or ok=false when none are saved.
func (r *SettingsRepo) Get(tenantID string) (settings.Stored, bool, error) {
	var rec settingsRecord
	err := r.db.One("TenantID", tenantID, &rec)
	if err == storm.ErrNotFound {
		return settings.Stored{TenantID: tenantID}, false, nil
	}
	if err != nil {
		return settings.Stored{}, false, fmt.Errorf("stormstore: load settings %s: %w", tenantID, err)
	}
	return settings.Stored{TenantID: rec.TenantID, AI: rec.AI, Secrets: rec.Secrets}, true, nil
}

// Put writes a workspace's settings (secrets already sealed) through to disk.
func (r *SettingsRepo) Put(st settings.Stored) error {
	rec := settingsRecord{TenantID: st.TenantID, AI: st.AI, Secrets: st.Secrets}
	if err := r.db.Save(&rec); err != nil {
		return fmt.Errorf("stormstore: save settings %s: %w", st.TenantID, err)
	}
	return nil
}
