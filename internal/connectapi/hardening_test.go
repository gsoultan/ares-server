// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares-server/internal/setup"
)

// A disabled account must lose access on its very next request, not when its
// session would have expired.
func TestDisableRevokesSessionsImmediately(t *testing.T) {
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	u, err := a.CreateUser("t-a", "m@example.com", "M", "a-strong-password-x", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := a.Login("m@example.com", "a-strong-password-x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(sess.Token); err != nil {
		t.Fatalf("fresh session rejected: %v", err)
	}
	if _, err := a.SetDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(sess.Token); err == nil {
		t.Fatal("disabled account's session still authenticates")
	}
}

// A role change ends the session, so a demoted admin cannot keep acting with
// the old role, and a promoted member must sign in again for a fresh token.
func TestRoleChangeRevokesSessions(t *testing.T) {
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	u, _ := a.CreateUser("t-a", "ad@example.com", "A", "a-strong-password-x", auth.RoleAdmin)
	sess, _, _ := a.Login("ad@example.com", "a-strong-password-x")
	if _, err := a.SetRole(u.ID, auth.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(sess.Token); err == nil {
		t.Fatal("demoted account's session still authenticates with its old role")
	}
}

// GetSetupStatus is public. It must never return a database password, and
// after setup it must not disclose where the database or key file live.
func TestSetupStatusDoesNotLeakDSN(t *testing.T) {
	h := newTestHandler(t)
	authSvc := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	dsn := "postgres://ares:s3cr3t-pw@db.internal:5432/ares"
	h.WithAuth(authSvc).WithSetup(setup.NewService(setup.NewMemStore(), authSvc, h.store, dsn, filepath.Join(t.TempDir(), "k"), nil))

	st, err := h.GetSetupStatus(context.Background(), connect.NewRequest(&aresv1.GetSetupStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.Msg.GetDbPath(), "s3cr3t-pw") {
		t.Fatalf("pre-setup status leaks the password: %q", st.Msg.GetDbPath())
	}

	// Once an account exists, an anonymous caller sees no paths at all.
	if _, err := authSvc.CreateUser("t-a", "o@example.com", "O", "a-strong-password-x", auth.RoleOwner); err != nil {
		t.Fatal(err)
	}
	st, err = h.GetSetupStatus(context.Background(), connect.NewRequest(&aresv1.GetSetupStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if st.Msg.GetDbPath() != "" || st.Msg.GetKeyFilePath() != "" {
		t.Fatalf("post-setup anonymous status discloses paths: %q %q", st.Msg.GetDbPath(), st.Msg.GetKeyFilePath())
	}
}

// The filesystem probe must close once the install is set up.
func TestTestDatabaseClosedAfterSetup(t *testing.T) {
	h := newTestHandler(t)
	authSvc := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	h.WithAuth(authSvc).WithSetup(setup.NewService(setup.NewMemStore(), authSvc, h.store, "ares.db", filepath.Join(t.TempDir(), "k"), nil))
	if _, err := authSvc.CreateUser("t-a", "o@example.com", "O", "a-strong-password-x", auth.RoleOwner); err != nil {
		t.Fatal(err)
	}
	resp, err := h.TestDatabaseConnection(context.Background(), connect.NewRequest(&aresv1.TestDatabaseConnectionRequest{Path: filepath.Join(t.TempDir(), "x.db")}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetOk() {
		t.Fatal("TestDatabaseConnection still probes the filesystem after setup")
	}
}

// Two concurrent first-run commits must not both create a super-admin.
func TestCommitSetupIsSerialized(t *testing.T) {
	h := newTestHandler(t)
	authSvc := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	dir := t.TempDir()
	h.WithAuth(authSvc).WithSetup(setup.NewService(setup.NewMemStore(), authSvc, h.store, filepath.Join(dir, "ares.db"), filepath.Join(dir, "k"), nil))

	var wg sync.WaitGroup
	var oks atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := h.CommitSetup(context.Background(), connect.NewRequest(&aresv1.CommitSetupRequest{
				Path: filepath.Join(dir, "ares.db"), GenerateKey: true, TenantName: "Acme",
				Admin: &aresv1.SetupAdmin{Name: "A", Email: "admin" + string(rune('a'+i)) + "@example.com", Password: "a-strong-password-x"},
			}))
			if err == nil && resp.Msg.GetOk() {
				oks.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if n, _ := authSvc.CountUsers(); n != 1 || oks.Load() != 1 {
		t.Fatalf("concurrent setup created %d accounts (%d commits succeeded), want exactly 1", n, oks.Load())
	}
}

// A member must not list the platform's other clients or create workspaces.
func TestTenantListingIsScoped(t *testing.T) {
	h, a := authHandler(t)
	ta := h.store.CreateTenant("Client A")
	h.store.CreateTenant("Client B")
	member := sessFor(t, a, ta.ID, "m@example.com", auth.RoleMember)

	resp, err := h.ListTenants(asSession(member), connect.NewRequest(&aresv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetTenants()) != 1 || resp.Msg.GetTenants()[0].GetId() != ta.ID {
		t.Fatalf("member sees %d workspaces, want only its own", len(resp.Msg.GetTenants()))
	}
	if _, err := h.CreateTenant(asSession(member), connect.NewRequest(&aresv1.CreateTenantRequest{Name: "Mine"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("member CreateTenant err = %v, want PermissionDenied", err)
	}
}

// settingsHandler wires a settings service with a fresh key.
func settingsHandler(t *testing.T) (*Handler, *auth.Service) {
	t.Helper()
	h, a := authHandler(t)
	key, _ := secret.NewKey()
	sealer, _ := secret.NewSealer(key)
	h.WithSettings(settings.NewService(sealer, settings.NewMemRepo()))
	return h, a
}

// A member must not rewrite the workspace's provider settings or keys.
func TestMemberCannotChangeSettings(t *testing.T) {
	h, a := settingsHandler(t)
	member := sessFor(t, a, "t-a", "m@example.com", auth.RoleMember)
	_, err := h.UpdateSettings(asSession(member), connect.NewRequest(&aresv1.UpdateSettingsRequest{
		TenantId: "t-a", AiPresent: true, Ai: &aresv1.AISettings{Provider: "openai", Model: "x"},
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("member UpdateSettings err = %v, want PermissionDenied", err)
	}
	_, err = h.TestAIProvider(asSession(member), connect.NewRequest(&aresv1.TestAIProviderRequest{TenantId: "t-a"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("member TestAIProvider err = %v, want PermissionDenied", err)
	}
}

// The saved (or the operator's environment) API key must never be sent to an
// endpoint the caller types into the test form.
func TestAIKeyNotSentToUnsavedEndpoint(t *testing.T) {
	t.Setenv("ARES_AI_PROVIDER", "openai")
	t.Setenv("ARES_AI_MODEL", "gpt-x")
	t.Setenv("ARES_AI_API_KEY", "sk-operator-secret")
	t.Setenv("ARES_AI_ALLOW_PRIVATE_ENDPOINTS", "on") // let the test reach httptest

	var gotKey atomic.Value
	gotKey.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	h, a := settingsHandler(t)
	admin := sessFor(t, a, "t-a", "ad@example.com", auth.RoleAdmin)
	_, _ = h.TestAIProvider(asSession(admin), connect.NewRequest(&aresv1.TestAIProviderRequest{
		TenantId: "t-a", AiPresent: true,
		Ai: &aresv1.AISettings{Provider: "openai-compatible", Model: "m", BaseUrl: srv.URL},
	}))
	if k := gotKey.Load().(string); strings.Contains(k, "sk-operator-secret") {
		t.Fatalf("operator key was sent to a caller-chosen endpoint: %q", k)
	}

	// Saving that endpoint must not inherit the operator key either.
	if _, err := h.UpdateSettings(asSession(admin), connect.NewRequest(&aresv1.UpdateSettingsRequest{
		TenantId: "t-a", AiPresent: true,
		Ai: &aresv1.AISettings{Provider: "openai-compatible", Model: "m", BaseUrl: srv.URL},
	})); err != nil {
		t.Fatal(err)
	}
	cfg, err := h.settings.AIConfig("t-a")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey == "sk-operator-secret" {
		t.Fatal("workspace endpoint inherited the operator's environment key")
	}
}

// Without the operator's opt-in, a workspace cannot aim the advisor at an
// internal address (SSRF to the LAN or cloud metadata).
func TestAIEndpointRejectsInternalAddresses(t *testing.T) {
	h, a := settingsHandler(t)
	admin := sessFor(t, a, "t-a", "ad@example.com", auth.RoleAdmin)
	for _, u := range []string{
		"http://169.254.169.254/latest", "https://127.0.0.1:8080", "https://10.0.0.5/v1",
		"https://localhost/v1", "https://[::1]/v1", "file:///etc/passwd",
	} {
		_, err := h.UpdateSettings(asSession(admin), connect.NewRequest(&aresv1.UpdateSettingsRequest{
			TenantId: "t-a", AiPresent: true,
			Ai: &aresv1.AISettings{Provider: "openai-compatible", Model: "m", BaseUrl: u},
		}))
		if err == nil {
			t.Errorf("internal endpoint %q was accepted", u)
		}
	}
}
