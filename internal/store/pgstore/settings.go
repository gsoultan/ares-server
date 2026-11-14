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

	"github.com/gsoultan/ares-server/internal/settings"
	settingpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/setting"
)

// SettingsRepo is a durable settings.Repo over the generated setting package.
type SettingsRepo struct{ ex runtime.Executor }

var _ settings.Repo = (*SettingsRepo)(nil)

// Settings returns a durable settings repository over this store's executor.
func (s *Store) Settings() *SettingsRepo { return &SettingsRepo{ex: s.ex} }

// Get returns a workspace's stored settings, or ok=false when none are saved.
func (r *SettingsRepo) Get(tenantID string) (settings.Stored, bool, error) {
	row, ok, err := settingpkg.New().TenantIDEq(tenantID).One(context.Background(), r.ex)
	if err != nil {
		return settings.Stored{}, false, fmt.Errorf("pgstore: load settings %s: %w", tenantID, err)
	}
	if !ok {
		return settings.Stored{TenantID: tenantID}, false, nil
	}
	st := settings.Stored{TenantID: tenantID}
	if err := row.Ai.Unmarshal(&st.AI); err != nil {
		return settings.Stored{}, false, fmt.Errorf("pgstore: decode settings ai %s: %w", tenantID, err)
	}
	if row.Secrets.Valid {
		if err := row.Secrets.V.Unmarshal(&st.Secrets); err != nil {
			return settings.Stored{}, false, fmt.Errorf("pgstore: decode settings secrets %s: %w", tenantID, err)
		}
	}
	return st, true, nil
}

// Put writes a workspace's settings (secrets already sealed) through to Postgres.
func (r *SettingsRepo) Put(st settings.Stored) error {
	ai, err := marshalJSON(st.AI)
	if err != nil {
		return fmt.Errorf("pgstore: encode settings ai %s: %w", st.TenantID, err)
	}
	n := settingpkg.Create()
	n.SetTenantID(st.TenantID)
	n.SetAi(ai)
	if len(st.Secrets) == 0 {
		n.SetSecretsNull()
	} else {
		secrets, err := marshalJSON(st.Secrets)
		if err != nil {
			return fmt.Errorf("pgstore: encode settings secrets %s: %w", st.TenantID, err)
		}
		n.SetSecrets(secrets)
	}
	if _, err := n.OnConflictTenantID().Insert(context.Background(), r.ex); err != nil {
		return fmt.Errorf("pgstore: save settings %s: %w", st.TenantID, err)
	}
	return nil
}
