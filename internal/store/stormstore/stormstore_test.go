// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/asdine/storm/v3"
	bolt "go.etcd.io/bbolt"

	"github.com/gsoultan/ares-server/internal/audit"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares/module"
)

func TestPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	eng, err := s.Create("", "Demo")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := eng.ID
	if err := eng.Scope.AddInScope("127.0.0.1"); err != nil {
		t.Fatalf("in-scope: %v", err)
	}
	if err := eng.Scope.AddExclusion("10.0.0.0/8"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	if err := s.Save(eng); err != nil {
		t.Fatalf("save scope: %v", err)
	}
	if err := eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if err := s.Save(eng); err != nil {
		t.Fatalf("save auth: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen from disk.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, ok := s2.Get(id)
	if !ok {
		t.Fatalf("engagement %s did not survive restart", id)
	}
	if got.Status != engagement.StatusAuthorized {
		t.Fatalf("status = %s, want authorized", got.Status)
	}
	if got.Authorization == nil || got.Authorization.Document != "auth.pdf" {
		t.Fatalf("authorization did not persist: %+v", got.Authorization)
	}

	// The permission gate round-trips: in-scope allowed, excluded and
	// out-of-scope denied.
	if ok, _ := got.Scope.Allow(module.Target{Host: "127.0.0.1"}); !ok {
		t.Error("127.0.0.1 should be in scope after reload")
	}
	if ok, _ := got.Scope.Allow(module.Target{Host: "10.1.2.3"}); ok {
		t.Error("10.1.2.3 is excluded and must stay denied after reload")
	}
	if ok, _ := got.Scope.Allow(module.Target{Host: "8.8.8.8"}); ok {
		t.Error("8.8.8.8 is out of scope and must be denied after reload")
	}

	// The audit trail reloaded and still verifies.
	if err := got.Audit.Verify(); err != nil {
		t.Fatalf("reloaded audit should verify: %v", err)
	}
	sawAuth := false
	for _, e := range got.Audit.Entries() {
		if e.Action == "authorization-approved" {
			sawAuth = true
		}
	}
	if !sawAuth {
		t.Error("reloaded audit should contain the authorization entry")
	}

	// A newly created engagement after reload gets a fresh, distinct id.
	next, err := s2.Create("", "Second")
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	if next.ID == "" || next.ID == id {
		t.Fatalf("next id = %q, want a fresh distinct id", next.ID)
	}
}

// TestTenantsPersistAndIsolate confirms workspaces and their engagement
// membership survive a restart, and that List stays scoped per workspace.
func TestTenantsPersistAndIsolate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	acme := s.CreateTenant("Acme")
	globex := s.CreateTenant("Globex")
	if _, err := s.Create(acme.ID, "Acme web app"); err != nil {
		t.Fatalf("create acme: %v", err)
	}
	if _, err := s.Create(globex.ID, "Globex API"); err != nil {
		t.Fatalf("create globex: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	// Both workspaces plus the always-present default survive.
	if got := s2.ListTenants(); len(got) != 3 {
		t.Fatalf("tenants after reload = %d, want 3 (Acme, Globex, default)", len(got))
	}
	if acmeList := s2.List(acme.ID); len(acmeList) != 1 || acmeList[0].Name != "Acme web app" {
		t.Fatalf("Acme list after reload = %+v, want its own engagement", acmeList)
	}
	if globexList := s2.List(globex.ID); len(globexList) != 1 || globexList[0].Name != "Globex API" {
		t.Fatalf("Globex list after reload = %+v, want its own engagement", globexList)
	}
	// Cross-workspace isolation holds after reload.
	if cross := s2.List(globex.ID); len(cross) == 1 && cross[0].Name == "Acme web app" {
		t.Fatal("Globex must not see Acme's engagement after reload")
	}
	// A new workspace created after reload gets a fresh, distinct id.
	third := s2.CreateTenant("Initech")
	if third.ID == "" || third.ID == acme.ID || third.ID == globex.ID {
		t.Fatalf("next tenant id = %q, want a fresh distinct id", third.ID)
	}
}

// TestLegacyEngagementAdoptsDefaultWorkspace confirms an engagement persisted
// before tenancy existed (no TenantID on disk) loads into the default
// workspace, so older databases stay fully reachable.
func TestLegacyEngagementAdoptsDefaultWorkspace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")

	// Write a record directly with no TenantID, as an older build would have.
	db, err := storm.Open(path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	legacy := record{ID: "eng-1", Name: "Old engagement", Status: "draft", CreatedAt: time.Now()}
	if err := db.Save(&legacy); err != nil {
		t.Fatalf("raw save: %v", err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	got, ok := s.Get("eng-1")
	if !ok {
		t.Fatal("legacy engagement should load")
	}
	if got.TenantID != tenant.DefaultID {
		t.Fatalf("legacy engagement tenant = %q, want the default workspace", got.TenantID)
	}
	// It is reachable through the default workspace listing.
	if list := s.List(""); len(list) != 1 || list[0].ID != "eng-1" {
		t.Fatalf("default list = %+v, want the adopted legacy engagement", list)
	}
}

// TestTamperAtRestDetected confirms Open refuses a database whose stored audit
// chain has been altered outside the application.
func TestTamperAtRestDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	eng, err := s.Create("", "Victim")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := eng.ID
	if err := eng.Authorize(engagement.Authorization{Document: "d", ApprovedBy: "a"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if err := s.Save(eng); err != nil {
		t.Fatalf("save: %v", err)
	}
	s.Close()

	// Tamper with a stored audit entry without fixing its hash.
	db, err := storm.Open(path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	// Each audit entry is its own key, by engagement and seq.
	if err := db.Bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		k := auditKey(id, 1)
		v := b.Get(k)
		if v == nil {
			return fmt.Errorf("audit entry 1 not stored")
		}
		var e audit.Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		e.Detail = "tampered"
		nv, _ := json.Marshal(e)
		return b.Put(k, nv)
	}); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	db.Close()

	// Reopen must fail, naming the broken engagement.
	if _, err := Open(path); err == nil {
		t.Fatal("Open should refuse a tampered audit trail at rest")
	}
}
