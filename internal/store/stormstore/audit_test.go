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
	"time"

	"github.com/asdine/storm/v3"
	bolt "go.etcd.io/bbolt"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares/scope"
)

func auditCount(t *testing.T, path string) int {
	t.Helper()
	db, err := storm.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n := 0
	_ = db.Bolt.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(auditBucket); b != nil {
			n = b.Stats().KeyN
		}
		return nil
	})
	return n
}

// TestSaveAppendsOnlyNewAuditEntries: one record per entry, nothing rewritten,
// and the trail survives a reopen and further appends.
func TestSaveAppendsOnlyNewAuditEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := s.Create("", "append")
	for i := 0; i < 50; i++ {
		eng.Audit.Append("op", "result", "example.com", "x")
	}
	if err := s.Save(eng); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(eng); err != nil { // nothing new
		t.Fatal(err)
	}
	want := eng.Audit.Len()
	s.Close()
	if n := auditCount(t, path); n != want {
		t.Fatalf("%d audit records, want %d", n, want)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s2.Get(eng.ID)
	if got.Audit.Len() != want || got.Audit.Verify() != nil {
		t.Fatalf("reloaded %d entries (verify %v), want %d", got.Audit.Len(), got.Audit.Verify(), want)
	}
	got.Audit.Append("op", "after-reopen", "", "")
	if err := s2.Save(got); err != nil {
		t.Fatal(err)
	}
	s2.Close()
	if n := auditCount(t, path); n != want+1 {
		t.Fatalf("%d audit records after reopen+append, want %d", n, want+1)
	}
}

// TestOpenMigratesInlineAuditTrail opens a file written by the previous layout
// (the trail inside the engagement record) and checks it moves out intact.
func TestOpenMigratesInlineAuditTrail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := storm.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New()
	log.Append("system", "engagement-created", "legacy", "Legacy")
	log.Append("op", "scope-added", "example.com", "host")
	if err := db.Save(&record{ID: "legacy", TenantID: tenant.DefaultID, Name: "Legacy", Status: "draft",
		CreatedAt: time.Now(), Scope: scope.New().Snapshot(), Audit: log.Entries()}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	got, ok := s.Get("legacy")
	if !ok || got.Audit.Len() != 2 {
		t.Fatalf("legacy engagement: ok=%v entries=%d", ok, got.Audit.Len())
	}
	s.Close()
	if n := auditCount(t, path); n != 2 {
		t.Fatalf("migrated %d records, want 2", n)
	}
	db, _ = storm.Open(path)
	var rec record
	if err := db.One("ID", "legacy", &rec); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if len(rec.Audit) != 0 {
		t.Error("inline trail must be removed from the header after migration")
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if g, _ := s2.Get("legacy"); g.Audit.Len() != 2 || g.Audit.Verify() != nil {
		t.Fatal("trail changed on the second open")
	}
}
