// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package setup

import (
	"path/filepath"
	"testing"

	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/tenant"
)

func newService(t *testing.T) (*Service, engagement.Store, *[]byte) {
	t.Helper()
	authSvc := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	tenants := engagement.NewMemStore()
	keyPath := filepath.Join(t.TempDir(), "ares.key")
	var delivered *[]byte
	captured := new([]byte)
	delivered = captured
	svc := NewService(NewMemStore(), authSvc, tenants, "ares.db", keyPath, func(k []byte) { *captured = k })
	return svc, tenants, delivered
}

func validReq() CommitRequest {
	return CommitRequest{
		DBDriver:    DriverFile,
		DBPath:      "ares.db",
		GenerateKey: true,
		Admin:       AdminInput{Name: "Root", Email: "root@example.com", Password: "a-very-strong-pass"},
		TenantName:  "Acme Security",
	}
}

func TestStatusNeededThenDone(t *testing.T) {
	svc, _, _ := newService(t)
	st, err := svc.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Needed || st.Initialized {
		t.Fatalf("fresh install must need setup: %+v", st)
	}
	// Drivers list must advertise file available and postgres not-yet.
	var fileOK, pgPresent bool
	for _, d := range st.Drivers {
		if d.Name == DriverFile && d.Available {
			fileOK = true
		}
		if d.Name == DriverPostgres && !d.Available {
			pgPresent = true
		}
	}
	if !fileOK || !pgPresent {
		t.Errorf("drivers wrong: %+v", st.Drivers)
	}

	if _, err := svc.Commit(validReq()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	st, _ = svc.Status()
	if st.Needed || !st.Initialized {
		t.Errorf("after commit setup must be done: %+v", st)
	}
}

func TestCommitProvisionsEverything(t *testing.T) {
	svc, tenants, key := newService(t)
	res, err := svc.Commit(validReq())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if res.GeneratedKey == "" {
		t.Error("generated key must be returned once")
	}
	if _, err := secret.DecodeKey(res.GeneratedKey); err != nil {
		t.Errorf("generated key not valid: %v", err)
	}
	if len(*key) != secret.KeySize {
		t.Error("onKey callback did not receive the master key")
	}
	// The default workspace must be renamed.
	tn, ok := tenants.GetTenant(tenant.DefaultID)
	if !ok || tn.Name != "Acme Security" {
		t.Errorf("default workspace not renamed: %+v", tn)
	}
	// The super-admin must be able to log in.
	authSvc := svc.auth
	if _, _, err := authSvc.Login("root@example.com", "a-very-strong-pass"); err != nil {
		t.Errorf("super-admin login failed: %v", err)
	}
}

func TestCommitRefusesSecondRun(t *testing.T) {
	svc, _, _ := newService(t)
	if _, err := svc.Commit(validReq()); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	// A second commit (even with a new key path would be a new install) must be
	// refused on the same service.
	req := validReq()
	req.Admin.Email = "attacker@example.com"
	if _, err := svc.Commit(req); err != ErrAlreadyInitialized {
		t.Errorf("second commit err = %v, want ErrAlreadyInitialized", err)
	}
}

func TestCommitValidation(t *testing.T) {
	svc, _, _ := newService(t)
	req := validReq()
	req.Admin.Password = "short"
	if _, err := svc.Commit(req); err != auth.ErrWeakPassword {
		t.Errorf("weak password err = %v", err)
	}

	svc2, _, _ := newService(t)
	req2 := validReq()
	req2.TenantName = "  "
	if _, err := svc2.Commit(req2); err != ErrTenantName {
		t.Errorf("empty tenant err = %v", err)
	}

	svc3, _, _ := newService(t)
	req3 := validReq()
	req3.DBDriver = DriverPostgres
	if _, err := svc3.Commit(req3); err != ErrDriverUnavailable {
		t.Errorf("postgres driver err = %v", err)
	}
}

func TestTestDatabase(t *testing.T) {
	svc, _, _ := newService(t)
	if err := svc.TestDatabase(DriverFile, filepath.Join(t.TempDir(), "ares.db")); err != nil {
		t.Errorf("writable dir should pass: %v", err)
	}
	if err := svc.TestDatabase(DriverFile, "/nonexistent-dir-xyz/ares.db"); err == nil {
		t.Error("unwritable dir should fail")
	}
	if err := svc.TestDatabase(DriverPostgres, ""); err != ErrDriverUnavailable {
		t.Errorf("postgres err = %v, want ErrDriverUnavailable", err)
	}
}
