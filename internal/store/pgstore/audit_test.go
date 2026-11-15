// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares/scope"
)

func countRows(t *testing.T, s *Store, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSaveAppendsOnlyNewAuditEntries checks the append-only layout: every
// entry is one row, a Save with nothing new writes nothing, small and bulk
// (COPY) appends both round-trip, and the chain still verifies on reload.
func TestSaveAppendsOnlyNewAuditEntries(t *testing.T) {
	s := freshStore(t)
	eng, err := s.Create("", "append")
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT count(*) FROM audit_entries WHERE engagement_id = $1`, eng.ID); n != 1 {
		t.Fatalf("after create: %d audit rows, want 1", n)
	}
	var xmin1 string
	_ = s.pool.QueryRow(context.Background(), `SELECT xmin::text FROM engagements WHERE id = $1`, eng.ID).Scan(&xmin1)

	// Nothing changed: no write at all (the header row keeps its version).
	if err := s.Save(eng); err != nil {
		t.Fatal(err)
	}
	// Only audit appends: the header is not rewritten.
	eng.Audit.Append("op", "note", "", "small")
	if err := s.Save(eng); err != nil {
		t.Fatal(err)
	}
	var xmin2 string
	_ = s.pool.QueryRow(context.Background(), `SELECT xmin::text FROM engagements WHERE id = $1`, eng.ID).Scan(&xmin2)
	if xmin1 != xmin2 {
		t.Errorf("header rewritten by an audit-only save (xmin %s -> %s)", xmin1, xmin2)
	}
	// A bulk append (COPY path) together with a header change.
	if err := eng.Scope.AddInScope("example.com"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < auditCopyThreshold*3; i++ {
		eng.Audit.Append("op", "result", "example.com", fmt.Sprintf("r%d", i))
	}
	if err := s.Save(eng); err != nil {
		t.Fatal(err)
	}
	want := eng.Audit.Len()
	if n := countRows(t, s, `SELECT count(*) FROM audit_entries WHERE engagement_id = $1`, eng.ID); n != want {
		t.Fatalf("%d audit rows, want %d", n, want)
	}
	if n := countRows(t, s, `SELECT count(*) FROM engagements WHERE id = $1 AND data ? 'audit'`, eng.ID); n != 0 {
		t.Error("header must not carry the audit trail")
	}

	s2, err := Open(dsn(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, ok := s2.Get(eng.ID)
	if !ok {
		t.Fatal("not reloaded")
	}
	if got.Audit.Len() != want {
		t.Fatalf("reloaded %d entries, want %d", got.Audit.Len(), want)
	}
	if err := got.Audit.Verify(); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if len(got.Scope.Snapshot().InScope) == 0 {
		t.Error("scope change lost")
	}
	// The reopened store knows what is persisted: one more entry is one row.
	got.Audit.Append("op", "after-reopen", "", "")
	if err := s2.Save(got); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s2, `SELECT count(*) FROM audit_entries WHERE engagement_id = $1`, eng.ID); n != want+1 {
		t.Fatalf("%d audit rows after reopen+append, want %d", n, want+1)
	}
}

// TestOpenMigratesInlineAuditTrail opens a database written by the previous
// layout (the whole trail inside the engagement's jsonb) and checks that the
// trail moves to its own rows once, intact.
func TestOpenMigratesInlineAuditTrail(t *testing.T) {
	s := freshStore(t)
	log := audit.New()
	log.Append("system", "engagement-created", "legacy", "Legacy")
	log.Append("op", "scope-added", "example.com", "host")
	doc := map[string]any{"status": "draft", "scope": scope.New().Snapshot(), "audit": log.Entries()}
	raw, _ := json.Marshal(doc)
	if _, err := s.pool.Exec(context.Background(),
		`INSERT INTO engagements (id, tenant_id, name, created_at, data) VALUES ($1, $2, $3, $4, $5)`,
		"legacy", tenant.DefaultID, "Legacy", time.Now(), raw); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dsn(t))
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	got, ok := s2.Get("legacy")
	if !ok || got.Audit.Len() != 2 {
		t.Fatalf("legacy engagement: ok=%v entries=%d, want 2", ok, got.Audit.Len())
	}
	if n := countRows(t, s2, `SELECT count(*) FROM audit_entries WHERE engagement_id = 'legacy'`); n != 2 {
		t.Fatalf("migrated %d audit rows, want 2", n)
	}
	if n := countRows(t, s2, `SELECT count(*) FROM engagements WHERE id = 'legacy' AND data ? 'audit'`); n != 0 {
		t.Error("inline trail must be removed from the header after migration")
	}
	s2.Close()

	// Opening again is a no-op that still verifies.
	s3, err := Open(dsn(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s3.Close()
	if got, _ := s3.Get("legacy"); got.Audit.Len() != 2 || got.Audit.Verify() != nil {
		t.Fatal("trail changed on the second open")
	}
}

// TestOpenLoadsMoreThanOnePage guards the generated queries' default LIMIT:
// every workspace and engagement must come back, not only the first 1,000.
func TestOpenLoadsMoreThanOnePage(t *testing.T) {
	s := freshStore(t)
	const n = pageSize + 5
	if _, err := s.pool.Exec(context.Background(), `
		INSERT INTO tenants (id, name, created_at)
		SELECT 't' || g, 'tenant ' || g, now() FROM generate_series(1, $1) g`, n); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(context.Background(), `
		INSERT INTO engagements (id, tenant_id, name, created_at, data)
		SELECT 'e' || g, $2, 'eng ' || g, now(), '{"status":"draft","scope":{}}'::jsonb FROM generate_series(1, $1) g`, n, tenant.DefaultID); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dsn(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s2.Close()
	if got := len(s2.ListTenants()); got != n+1 { // + the default workspace
		t.Errorf("loaded %d workspaces, want %d", got, n+1)
	}
	if got := len(s2.List(tenant.DefaultID)); got != n {
		t.Errorf("loaded %d engagements, want %d", got, n)
	}
}
