// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"context"
	"fmt"

	"github.com/gsoultan/storm/runtime"

	"github.com/gsoultan/ares-server/internal/setup"
	setupcfgpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/setupconfig"
)

// setupConfigID is the fixed primary key of the single setup-config row.
const setupConfigID = "setup"

// SetupRepo is a durable setup.Store over the generated setupconfig package.
type SetupRepo struct{ ex runtime.Executor }

var _ setup.Store = (*SetupRepo)(nil)

// Setup returns a durable setup-config store over this store's executor.
func (s *Store) Setup() *SetupRepo { return &SetupRepo{ex: s.ex} }

// GetConfig implements setup.Store.
func (r *SetupRepo) GetConfig() (setup.Config, bool, error) {
	row, ok, err := setupcfgpkg.New().IDEq(setupConfigID).One(context.Background(), r.ex)
	if err != nil {
		return setup.Config{}, false, fmt.Errorf("pgstore: load setup config: %w", err)
	}
	if !ok {
		return setup.Config{}, false, nil
	}
	return setup.Config{
		Initialized:   row.Initialized,
		InitializedAt: row.InitializedAt,
		DBDriver:      row.DbDriver,
		DBPath:        row.DbPath,
	}, true, nil
}

// PutConfig implements setup.Store, upserting the single row by primary key.
func (r *SetupRepo) PutConfig(c setup.Config) error {
	n := setupcfgpkg.Create()
	n.SetID(setupConfigID)
	n.SetInitialized(c.Initialized)
	n.SetInitializedAt(c.InitializedAt)
	n.SetDbDriver(c.DBDriver)
	n.SetDbPath(c.DBPath)
	if _, err := n.OnConflictID().Insert(context.Background(), r.ex); err != nil {
		return fmt.Errorf("pgstore: save setup config: %w", err)
	}
	return nil
}
