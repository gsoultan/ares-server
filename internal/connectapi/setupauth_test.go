// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares-server/internal/setup"
)

// withAuthSetup wires auth + setup over mem stores sharing the handler's store.
func withAuthSetup(t *testing.T, h *Handler) *Handler {
	t.Helper()
	authSvc := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	settingsRepo := settings.NewMemRepo()
	onKey := func(key []byte) {
		sealer, err := secret.NewSealer(key)
		if err != nil {
			t.Fatalf("sealer: %v", err)
		}
		h.WithSettings(settings.NewService(sealer, settingsRepo))
	}
	setupSvc := setup.NewService(setup.NewMemStore(), authSvc, h.store, "ares.db", filepath.Join(t.TempDir(), "ares.key"), onKey)
	return h.WithAuth(authSvc).WithSetup(setupSvc)
}

func TestSetupThenLoginFlow(t *testing.T) {
	h := withAuthSetup(t, newTestHandler(t))
	ctx := context.Background()

	// Fresh install: setup needed, file driver available, postgres not yet.
	st, err := h.GetSetupStatus(ctx, connect.NewRequest(&aresv1.GetSetupStatusRequest{}))
	if err != nil {
		t.Fatalf("GetSetupStatus: %v", err)
	}
	if !st.Msg.GetNeeded() {
		t.Fatal("fresh install must need setup")
	}
	var sawFile, sawPG bool
	for _, d := range st.Msg.GetDrivers() {
		if d.GetName() == "file" && d.GetAvailable() {
			sawFile = true
		}
		if d.GetName() == "postgres" && !d.GetAvailable() {
			sawPG = true
		}
	}
	if !sawFile || !sawPG {
		t.Errorf("drivers wrong: %+v", st.Msg.GetDrivers())
	}

	// Settings are unavailable before setup.
	if _, err := h.GetSettings(ctx, connect.NewRequest(&aresv1.GetSettingsRequest{})); err == nil || connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("settings must be UNAVAILABLE before setup, got %v", err)
	}

	// Commit setup.
	commit, err := h.CommitSetup(ctx, connect.NewRequest(&aresv1.CommitSetupRequest{
		Driver: "file", Path: "ares.db", GenerateKey: true,
		Admin:      &aresv1.SetupAdmin{Name: "Root", Email: "root@example.com", Password: "a-very-strong-pass"},
		TenantName: "Acme Security",
	}))
	if err != nil {
		t.Fatalf("CommitSetup: %v", err)
	}
	if !commit.Msg.GetOk() || commit.Msg.GetGeneratedKey() == "" {
		t.Fatalf("commit must succeed and return a key once: %+v", commit.Msg)
	}

	// Setup now done, settings online.
	st2, _ := h.GetSetupStatus(ctx, connect.NewRequest(&aresv1.GetSetupStatusRequest{}))
	if st2.Msg.GetNeeded() || !st2.Msg.GetInitialized() {
		t.Errorf("setup should be done: %+v", st2.Msg)
	}
	if _, err := h.GetSettings(ctx, connect.NewRequest(&aresv1.GetSettingsRequest{})); err != nil {
		t.Errorf("settings should be available after setup: %v", err)
	}

	// Super-admin can log in.
	login, err := h.Login(ctx, connect.NewRequest(&aresv1.LoginRequest{Email: "root@example.com", Password: "a-very-strong-pass"}))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !login.Msg.GetOk() || login.Msg.GetToken() == "" {
		t.Fatalf("login must succeed with a token: %+v", login.Msg)
	}
	if login.Msg.GetUser().GetRole() != string(auth.RoleSuperAdmin) {
		t.Errorf("role = %q, want superadmin", login.Msg.GetUser().GetRole())
	}
	token := login.Msg.GetToken()

	// CurrentUser resolves the session.
	who, err := h.CurrentUser(ctx, connect.NewRequest(&aresv1.CurrentUserRequest{Token: token}))
	if err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
	if who.Msg.GetEmail() != "root@example.com" {
		t.Errorf("current user = %q", who.Msg.GetEmail())
	}

	// Logout revokes the session.
	if _, err := h.Logout(ctx, connect.NewRequest(&aresv1.LogoutRequest{Token: token})); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := h.CurrentUser(ctx, connect.NewRequest(&aresv1.CurrentUserRequest{Token: token})); err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("revoked token must be UNAUTHENTICATED, got %v", err)
	}

	// Setup cannot be replayed.
	again, err := h.CommitSetup(ctx, connect.NewRequest(&aresv1.CommitSetupRequest{
		Driver: "file", Path: "ares.db", GenerateKey: true,
		Admin:      &aresv1.SetupAdmin{Name: "Attacker", Email: "attacker@example.com", Password: "another-strong-pass"},
		TenantName: "Evil",
	}))
	if err != nil {
		t.Fatalf("CommitSetup(2): %v", err)
	}
	if again.Msg.GetOk() {
		t.Error("second CommitSetup must fail (already initialized)")
	}
}

func TestLoginWrongPasswordGeneric(t *testing.T) {
	h := withAuthSetup(t, newTestHandler(t))
	ctx := context.Background()
	_, _ = h.CommitSetup(ctx, connect.NewRequest(&aresv1.CommitSetupRequest{
		Driver: "file", Path: "ares.db", GenerateKey: true,
		Admin:      &aresv1.SetupAdmin{Name: "Root", Email: "root@example.com", Password: "a-very-strong-pass"},
		TenantName: "Acme",
	}))
	resp, err := h.Login(ctx, connect.NewRequest(&aresv1.LoginRequest{Email: "root@example.com", Password: "wrong-wrong-wrong"}))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.Msg.GetOk() || resp.Msg.GetToken() != "" {
		t.Error("wrong password must not succeed")
	}
	if resp.Msg.GetError() == "" {
		t.Error("expected a generic error message")
	}
}
