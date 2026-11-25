// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"strings"
	"testing"
	"time"
)

func newSvc() *Service {
	return NewService(NewMemUserStore(), NewMemSessionStore())
}

func TestHashVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.Contains(h, "correct horse") {
		t.Error("hash must not contain the password")
	}
	ok, err := VerifyPassword(h, "correct horse battery")
	if err != nil || !ok {
		t.Errorf("verify correct = %v, %v", ok, err)
	}
	ok, _ = VerifyPassword(h, "wrong password here")
	if ok {
		t.Error("verify must reject a wrong password")
	}
}

func TestWeakPasswordRejected(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword, got %v", err)
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same password value")
	b, _ := HashPassword("same password value")
	if a == b {
		t.Error("two hashes of the same password must differ (random salt)")
	}
}

func TestCreateUserAndDuplicate(t *testing.T) {
	svc := newSvc()
	_, err := svc.CreateUser("t1", "Admin@Example.com", "Admin", "a-strong-password", RoleOwner)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Duplicate email (case-insensitive) must be rejected.
	if _, err := svc.CreateUser("t1", "admin@example.com", "Dup", "another-strong-pass", RoleMember); err != ErrDuplicateEmail {
		t.Errorf("want ErrDuplicateEmail, got %v", err)
	}
}

func TestCreateUserValidation(t *testing.T) {
	svc := newSvc()
	if _, err := svc.CreateUser("t1", "x@example.com", "X", "short", RoleMember); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword, got %v", err)
	}
	if _, err := svc.CreateUser("t1", "x@example.com", "X", "a-strong-password", Role("wat")); err != ErrInvalidRole {
		t.Errorf("want ErrInvalidRole, got %v", err)
	}
	if _, err := svc.CreateUser("t1", "", "X", "a-strong-password", RoleMember); err != ErrEmptyField {
		t.Errorf("want ErrEmptyField, got %v", err)
	}
}

func TestLoginFlow(t *testing.T) {
	svc := newSvc()
	_, err := svc.CreateUser("t1", "user@example.com", "User", "a-strong-password", RoleAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Wrong password.
	if _, _, err := svc.Login("user@example.com", "nope-nope-nope"); err != ErrInvalidCredentials {
		t.Errorf("wrong password err = %v", err)
	}
	// Unknown account — same error.
	if _, _, err := svc.Login("ghost@example.com", "whatever-here"); err != ErrInvalidCredentials {
		t.Errorf("unknown account err = %v", err)
	}
	// Success.
	sess, u, err := svc.Login("USER@example.com", "a-strong-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if sess.Token == "" || sess.UserID != u.ID || sess.TenantID != "t1" || sess.Role != RoleAdmin {
		t.Errorf("session wrong: %+v", sess)
	}
	// Authenticate with the token.
	got, err := svc.Authenticate(sess.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.UserID != u.ID {
		t.Errorf("authenticated user mismatch")
	}
	// The live account's email rides on the session (for audit attribution),
	// but never on the raw session handed to the client at sign-in.
	if got.Email != "user@example.com" {
		t.Errorf("authenticated session email = %q, want the account's", got.Email)
	}
	cur, err := svc.CurrentUser(sess.Token)
	if err != nil || cur.ID != u.ID {
		t.Errorf("CurrentUser = %v, %v", cur.ID, err)
	}
}

func TestLogoutRevokes(t *testing.T) {
	svc := newSvc()
	_, _ = svc.CreateUser("t1", "u@example.com", "U", "a-strong-password", RoleMember)
	sess, _, _ := svc.Login("u@example.com", "a-strong-password")
	if err := svc.Logout(sess.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Authenticate(sess.Token); err != ErrNotAuthenticated {
		t.Errorf("revoked token err = %v, want ErrNotAuthenticated", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	svc := NewService(NewMemUserStore(), NewMemSessionStore()).WithTTL(time.Millisecond)
	_, _ = svc.CreateUser("t1", "u@example.com", "U", "a-strong-password", RoleMember)
	sess, _, _ := svc.Login("u@example.com", "a-strong-password")
	time.Sleep(5 * time.Millisecond)
	if _, err := svc.Authenticate(sess.Token); err != ErrNotAuthenticated {
		t.Errorf("expired session err = %v, want ErrNotAuthenticated", err)
	}
}

func TestDisabledAccount(t *testing.T) {
	store := NewMemUserStore()
	svc := NewService(store, NewMemSessionStore())
	u, _ := svc.CreateUser("t1", "u@example.com", "U", "a-strong-password", RoleMember)
	u.Disabled = true
	if err := store.UpdateUser(u); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, _, err := svc.Login("u@example.com", "a-strong-password"); err != ErrDisabled {
		t.Errorf("disabled login err = %v, want ErrDisabled", err)
	}
}

func TestUnknownTokenRejected(t *testing.T) {
	svc := newSvc()
	if _, err := svc.Authenticate("not-a-real-token"); err != ErrNotAuthenticated {
		t.Errorf("err = %v, want ErrNotAuthenticated", err)
	}
	if _, err := svc.Authenticate(""); err != ErrNotAuthenticated {
		t.Errorf("empty token err = %v", err)
	}
}

func TestHashPasswordForDevSeedSkipsLengthPolicyOnly(t *testing.T) {
	if _, err := HashPassword("admin"); err == nil {
		t.Fatal("HashPassword must keep enforcing the minimum length")
	}
	h, err := HashPasswordForDevSeed("admin")
	if err != nil {
		t.Fatalf("HashPasswordForDevSeed: %v", err)
	}
	if ok, err := VerifyPassword(h, "admin"); err != nil || !ok {
		t.Fatalf("dev-seed hash must verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "wrong"); ok {
		t.Fatal("dev-seed hash must reject a wrong password")
	}
	if _, err := HashPasswordForDevSeed(""); err == nil {
		t.Fatal("an empty password must still be refused")
	}
}
