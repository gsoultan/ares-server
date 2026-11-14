// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package engagement

import (
	"errors"
	"testing"

	"github.com/gsoultan/ares-server/internal/tenant"
)

func TestMemStoreHasDefaultWorkspace(t *testing.T) {
	s := NewMemStore()
	if _, ok := s.GetTenant(tenant.DefaultID); !ok {
		t.Fatal("a fresh store must hold the default workspace")
	}
	// An empty tenant id resolves to the default workspace.
	if _, ok := s.GetTenant(""); !ok {
		t.Fatal("empty tenant id should resolve to the default workspace")
	}
}

func TestCreateUnderUnknownTenantRefused(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Create("tnt-ghost", "Nope"); !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("create under unknown tenant: want ErrUnknownTenant, got %v", err)
	}
}

func TestListIsScopedToWorkspace(t *testing.T) {
	s := NewMemStore()
	acme := s.CreateTenant("Acme")
	globex := s.CreateTenant("Globex")

	if _, err := s.Create(acme.ID, "Acme web app"); err != nil {
		t.Fatalf("create acme: %v", err)
	}
	if _, err := s.Create(globex.ID, "Globex API"); err != nil {
		t.Fatalf("create globex: %v", err)
	}
	// One engagement left in the default workspace.
	if _, err := s.Create("", "House scan"); err != nil {
		t.Fatalf("create default: %v", err)
	}

	if got := s.List(acme.ID); len(got) != 1 || got[0].Name != "Acme web app" {
		t.Fatalf("Acme list = %+v, want exactly its own engagement", got)
	}
	if got := s.List(globex.ID); len(got) != 1 || got[0].Name != "Globex API" {
		t.Fatalf("Globex list = %+v, want exactly its own engagement", got)
	}
	if got := s.List(""); len(got) != 1 || got[0].Name != "House scan" {
		t.Fatalf("default list = %+v, want only the default-workspace engagement", got)
	}
}

func TestEngagementCarriesItsWorkspace(t *testing.T) {
	s := NewMemStore()
	acme := s.CreateTenant("Acme")
	eng, err := s.Create(acme.ID, "Acme web app")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if eng.TenantID != acme.ID {
		t.Fatalf("engagement tenant = %q, want %q", eng.TenantID, acme.ID)
	}
	// Default-workspace engagements are tagged explicitly, not left blank.
	def, err := s.Create("", "House scan")
	if err != nil {
		t.Fatalf("create default: %v", err)
	}
	if def.TenantID != tenant.DefaultID {
		t.Fatalf("default engagement tenant = %q, want %q", def.TenantID, tenant.DefaultID)
	}
}
