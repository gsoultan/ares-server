// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares-server/internal/setup"
	"github.com/gsoultan/ares-server/internal/tenant"
)

// dsn returns the test Postgres DSN, or skips. Point ARES_TEST_PG_URL at a
// throwaway database (the dev script's Postgres on :55433 works); each test
// resets the public schema, so storm's automigrate rebuilds it from scratch.
func dsn(t testing.TB) string {
	t.Helper()
	v := os.Getenv("ARES_TEST_PG_URL")
	if v == "" {
		t.Skip("set ARES_TEST_PG_URL to run the pgstore integration tests (e.g. the dev Postgres on :55433)")
	}
	return v
}

// freshStore resets the schema and opens a store, so each test starts clean.
func freshStore(t testing.TB) *Store {
	t.Helper()
	url := dsn(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		pool.Close()
		t.Fatalf("reset schema: %v", err)
	}
	pool.Close()

	s, err := Open(url) // Open runs storm automigrate on the clean schema.
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEngagementRoundTripPreservesAuditChain(t *testing.T) {
	s := freshStore(t)
	eng, err := s.Create("", "First engagement")
	if err != nil {
		t.Fatal(err)
	}
	eng.Audit.Append("operator", "scope-added", "example.com", "host")
	eng.Audit.Append("operator", "authorized", eng.ID, "signed")
	if err := s.Save(eng); err != nil {
		t.Fatal(err)
	}

	// Reopen from Postgres — the audit chain must verify (jsonb preserves nanos).
	s2, err := Open(dsn(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, ok := s2.Get(eng.ID)
	if !ok {
		t.Fatal("engagement not reloaded")
	}
	if err := got.Audit.Verify(); err != nil {
		t.Fatalf("audit chain failed to verify after reload: %v", err)
	}
	if got.Name != "First engagement" {
		t.Errorf("name = %q, want %q", got.Name, "First engagement")
	}
	if len(got.Audit.Entries()) != len(eng.Audit.Entries()) {
		t.Errorf("entry count = %d, want %d", len(got.Audit.Entries()), len(eng.Audit.Entries()))
	}
}

func TestUserStoreUniqueEmail(t *testing.T) {
	s := freshStore(t)
	users := s.Users()
	u := auth.User{
		ID: "u1", TenantID: tenant.DefaultID, Email: "Admin@Example.com",
		Name: "Admin", Role: auth.RoleSuperAdmin, PasswordHash: "hash",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := users.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	dup := u
	dup.ID = "u2"
	dup.Email = "admin@example.com"
	if err := users.CreateUser(dup); err != auth.ErrDuplicateEmail {
		t.Fatalf("expected ErrDuplicateEmail, got %v", err)
	}
	got, ok, err := users.GetUserByEmail("admin@example.com")
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if got.ID != "u1" || got.Role != auth.RoleSuperAdmin {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	n, err := users.CountUsers()
	if err != nil || n != 1 {
		t.Fatalf("count = %d err=%v, want 1", n, err)
	}
	if err := users.UpdateUser(auth.User{ID: "missing"}); err != auth.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestSessionAndSettingsRoundTrip(t *testing.T) {
	s := freshStore(t)
	sessions := s.Sessions()
	sess := auth.Session{UserID: "u1", TenantID: tenant.DefaultID, Role: auth.RoleSuperAdmin, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := sessions.Save("hash-abc", sess); err != nil {
		t.Fatal(err)
	}
	got, ok, err := sessions.Load("hash-abc")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.UserID != "u1" {
		t.Errorf("session userID = %q", got.UserID)
	}
	if err := sessions.Delete("hash-abc"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sessions.Load("hash-abc"); ok {
		t.Error("session should be gone after delete")
	}

	st := s.Settings()
	if _, ok, _ := st.Get(tenant.DefaultID); ok {
		t.Error("expected no settings before Put")
	}
	stored := settings.Stored{TenantID: tenant.DefaultID, AI: settings.AIConfig{Provider: "anthropic", Model: "claude"}}
	if err := st.Put(stored); err != nil {
		t.Fatal(err)
	}
	back, ok, err := st.Get(tenant.DefaultID)
	if err != nil || !ok {
		t.Fatalf("settings get: ok=%v err=%v", ok, err)
	}
	if back.AI.Provider != "anthropic" || back.AI.Model != "claude" {
		t.Errorf("settings round-trip mismatch: %+v", back.AI)
	}
}

func TestSetupConfigRoundTrip(t *testing.T) {
	s := freshStore(t)
	cfg := s.Setup()
	if _, ok, _ := cfg.GetConfig(); ok {
		t.Error("expected no setup config initially")
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := cfg.PutConfig(setup.Config{Initialized: true, InitializedAt: now, DBDriver: "postgres", DBPath: "postgres://…"}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := cfg.GetConfig()
	if err != nil || !ok {
		t.Fatalf("get config: ok=%v err=%v", ok, err)
	}
	if !got.Initialized || got.DBDriver != "postgres" {
		t.Errorf("config round-trip mismatch: %+v", got)
	}
}
