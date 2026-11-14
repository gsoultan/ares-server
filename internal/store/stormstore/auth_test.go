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

	"github.com/gsoultan/ares-server/internal/auth"
)

func TestUserRepoPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc := auth.NewService(st.Users(), st.Sessions())
	u, err := svc.CreateUser("t1", "admin@example.com", "Admin", "a-strong-password", auth.RoleSuperAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Duplicate email rejected by the unique index.
	if _, err := svc.CreateUser("t1", "ADMIN@example.com", "Dup", "another-strong-pass", auth.RoleMember); err != auth.ErrDuplicateEmail {
		t.Errorf("want ErrDuplicateEmail, got %v", err)
	}
	n, _ := svc.CountUsers()
	if n != 1 {
		t.Errorf("CountUsers = %d, want 1", n)
	}
	sess, _, err := svc.Login("admin@example.com", "a-strong-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	st.Close()

	// Reopen: the account and an active session must survive, and the super-admin
	// hash must still verify.
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	svc2 := auth.NewService(st2.Users(), st2.Sessions())
	got, err := svc2.CurrentUser(sess.Token)
	if err != nil {
		t.Fatalf("session did not survive restart: %v", err)
	}
	if got.ID != u.ID || got.Role != auth.RoleSuperAdmin {
		t.Errorf("persisted user wrong: %+v", got)
	}
	if _, _, err := svc2.Login("admin@example.com", "a-strong-password"); err != nil {
		t.Errorf("persisted password did not verify: %v", err)
	}
}

func TestSessionRepoDelete(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ares.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	repo := st.Sessions()
	s := auth.Session{UserID: "u1", TenantID: "t1", Role: auth.RoleMember, ExpiresAt: time.Now().Add(time.Hour)}
	if err := repo.Save("hash1", s); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, ok, _ := repo.Load("hash1"); !ok {
		t.Fatal("session should load")
	}
	if err := repo.Delete("hash1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := repo.Load("hash1"); ok {
		t.Error("deleted session should not load")
	}
	// Deleting a missing session is not an error.
	if err := repo.Delete("nope"); err != nil {
		t.Errorf("delete missing: %v", err)
	}
}
