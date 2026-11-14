// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"fmt"
	"time"

	"github.com/asdine/storm/v3"

	"github.com/gsoultan/ares-server/internal/setup"
)

// setupConfigID is the fixed key of the single setup-config record.
const setupConfigID = "setup"

// setupConfigRecord is the on-disk first-run configuration and initialization
// marker. There is exactly one, under setupConfigID.
type setupConfigRecord struct {
	ID            string `storm:"id"`
	Initialized   bool
	InitializedAt time.Time
	DBDriver      string
	DBPath        string
}

// SetupRepo is a durable setup.Store backed by the engagement store's database.
type SetupRepo struct{ db *storm.DB }

var _ setup.Store = (*SetupRepo)(nil)

// Setup returns a durable setup-config store over this store's database.
func (s *Store) Setup() *SetupRepo { return &SetupRepo{db: s.db} }

// GetConfig implements setup.Store.
func (r *SetupRepo) GetConfig() (setup.Config, bool, error) {
	var rec setupConfigRecord
	err := r.db.One("ID", setupConfigID, &rec)
	if err == storm.ErrNotFound {
		return setup.Config{}, false, nil
	}
	if err != nil {
		return setup.Config{}, false, fmt.Errorf("stormstore: load setup config: %w", err)
	}
	return setup.Config{
		Initialized:   rec.Initialized,
		InitializedAt: rec.InitializedAt,
		DBDriver:      rec.DBDriver,
		DBPath:        rec.DBPath,
	}, true, nil
}

// PutConfig implements setup.Store.
func (r *SetupRepo) PutConfig(c setup.Config) error {
	rec := setupConfigRecord{
		ID:            setupConfigID,
		Initialized:   c.Initialized,
		InitializedAt: c.InitializedAt,
		DBDriver:      c.DBDriver,
		DBPath:        c.DBPath,
	}
	if err := r.db.Save(&rec); err != nil {
		return fmt.Errorf("stormstore: save setup config: %w", err)
	}
	return nil
}
