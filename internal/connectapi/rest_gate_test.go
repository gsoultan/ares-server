// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/ares-server/internal/auth"
)

// echoTenant reports the resolved workspace header so tests can assert binding.
func echoTenant() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/engagements", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Tenant", r.Header.Get(restTenantHeader))
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func loginToken(t *testing.T, a *auth.Service, tenantID, email string, role auth.Role) string {
	t.Helper()
	if _, err := a.CreateUser(tenantID, email, email, "a-strong-password-x", role); err != nil {
		t.Fatalf("create %s: %v", email, err)
	}
	sess, _, err := a.Login(email, "a-strong-password-x")
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return sess.Token
}

func do(h http.Handler, method, path, bearer, tenant string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if tenant != "" {
		r.Header.Set(restTenantHeader, tenant)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRESTGateOpenBeforeSetup(t *testing.T) {
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	gate := NewAuthInterceptor(a, EnforceAuto).RESTMiddleware(echoTenant())
	// No users yet => auto mode does not enforce; an unauthenticated call passes.
	if w := do(gate, "GET", "/api/engagements", "", ""); w.Code != http.StatusOK {
		t.Fatalf("pre-setup call = %d, want 200", w.Code)
	}
}

func TestRESTGateRequiresAuthWhenArmed(t *testing.T) {
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	token := loginToken(t, a, "t-a", "admin@example.com", auth.RoleAdmin)
	gate := NewAuthInterceptor(a, EnforceAuto).RESTMiddleware(echoTenant())

	// An account exists => enforcing. Unauthenticated protected call is rejected.
	if w := do(gate, "GET", "/api/engagements", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauth protected = %d, want 401", w.Code)
	}
	// Health stays open.
	if w := do(gate, "GET", "/healthz", "", ""); w.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", w.Code)
	}
	// A bad token is rejected even on health.
	if w := do(gate, "GET", "/healthz", "not-a-real-token", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("bad token = %d, want 401", w.Code)
	}
	// A valid session binds the workspace to the caller's tenant.
	w := do(gate, "GET", "/api/engagements", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("auth call = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Echo-Tenant"); got != "t-a" {
		t.Errorf("bound tenant = %q, want t-a", got)
	}
}

func TestRESTGateRejectsCrossTenantHeader(t *testing.T) {
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	token := loginToken(t, a, "t-a", "admin@example.com", auth.RoleAdmin)
	gate := NewAuthInterceptor(a, EnforceOn).RESTMiddleware(echoTenant())

	// Non-super caller asking for another workspace via the header is denied.
	if w := do(gate, "GET", "/api/engagements", token, "t-b"); w.Code != http.StatusForbidden {
		t.Errorf("cross-tenant header = %d, want 403", w.Code)
	}
	// The caller's own workspace is allowed.
	if w := do(gate, "GET", "/api/engagements", token, "t-a"); w.Code != http.StatusOK {
		t.Errorf("own workspace = %d, want 200", w.Code)
	}
}

func TestRESTGateSuperAdminAnyTenant(t *testing.T) {
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	token := loginToken(t, a, "t-root", "super@example.com", auth.RoleSuperAdmin)
	gate := NewAuthInterceptor(a, EnforceOn).RESTMiddleware(echoTenant())

	// A super-admin may name any workspace; the header is left as supplied.
	w := do(gate, "GET", "/api/engagements", token, "t-b")
	if w.Code != http.StatusOK {
		t.Fatalf("super cross-tenant = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Echo-Tenant"); got != "t-b" {
		t.Errorf("super tenant = %q, want t-b (unbound)", got)
	}
}
