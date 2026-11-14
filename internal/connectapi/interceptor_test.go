// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares-server/internal/setup"
)

func serveWithAuth(t *testing.T) (aresv1connect.ControlPlaneClient, *auth.Service) {
	t.Helper()
	h := newTestHandler(t)
	authSvc := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	settingsRepo := settings.NewMemRepo()
	onKey := func(k []byte) {
		sealer, err := secret.NewSealer(k)
		if err != nil {
			t.Fatalf("sealer: %v", err)
		}
		h.WithSettings(settings.NewService(sealer, settingsRepo))
	}
	setupSvc := setup.NewService(setup.NewMemStore(), authSvc, h.store, "ares.db", filepath.Join(t.TempDir(), "ares.key"), onKey)
	h.WithAuth(authSvc).WithSetup(setupSvc)

	path, handler := aresv1connect.NewControlPlaneHandler(h, connect.WithInterceptors(NewAuthInterceptor(authSvc, EnforceAuto)))
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(h2c.NewHandler(mux, &http2.Server{}))
	t.Cleanup(srv.Close)

	httpClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	return aresv1connect.NewControlPlaneClient(httpClient, srv.URL, connect.WithGRPC()), authSvc
}

func commitSetup(t *testing.T, client aresv1connect.ControlPlaneClient) {
	t.Helper()
	resp, err := client.CommitSetup(context.Background(), connect.NewRequest(&aresv1.CommitSetupRequest{
		Driver: "file", Path: "ares.db", GenerateKey: true,
		Admin:      &aresv1.SetupAdmin{Name: "Root", Email: "root@example.com", Password: "a-very-strong-pass"},
		TenantName: "Acme",
	}))
	if err != nil {
		t.Fatalf("CommitSetup: %v", err)
	}
	if !resp.Msg.GetOk() {
		t.Fatalf("CommitSetup not ok: %s", resp.Msg.GetError())
	}
}

func TestInterceptorAutoEnforcement(t *testing.T) {
	client, _ := serveWithAuth(t)
	ctx := context.Background()

	// Pre-setup: no accounts yet, so protected RPCs are open (the wizard works).
	if _, err := client.ListModules(ctx, connect.NewRequest(&aresv1.ListModulesRequest{})); err != nil {
		t.Fatalf("pre-setup ListModules should be open: %v", err)
	}

	commitSetup(t, client)

	// Post-setup: protected RPCs now require a session.
	_, err := client.ListModules(ctx, connect.NewRequest(&aresv1.ListModulesRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("post-setup ListModules without token should be UNAUTHENTICATED, got %v", err)
	}

	// Login and retry with a bearer token.
	login, err := client.Login(ctx, connect.NewRequest(&aresv1.LoginRequest{Email: "root@example.com", Password: "a-very-strong-pass"}))
	if err != nil || !login.Msg.GetOk() {
		t.Fatalf("login: %v / %s", err, login.Msg.GetError())
	}
	req := connect.NewRequest(&aresv1.ListModulesRequest{})
	req.Header().Set("Authorization", "Bearer "+login.Msg.GetToken())
	if _, err := client.ListModules(ctx, req); err != nil {
		t.Fatalf("authenticated ListModules should work: %v", err)
	}

	// A bad token is always rejected.
	bad := connect.NewRequest(&aresv1.ListModulesRequest{})
	bad.Header().Set("Authorization", "Bearer not-a-real-token")
	if _, err := client.ListModules(ctx, bad); err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("bad token should be UNAUTHENTICATED, got %v", err)
	}
}

func TestInterceptorTenantIsolation(t *testing.T) {
	client, authSvc := serveWithAuth(t)
	ctx := context.Background()
	commitSetup(t, client)

	// A non-super user scoped to workspace "tenant-A".
	if _, err := authSvc.CreateUser("tenant-A", "member@example.com", "Member", "member-strong-pass", auth.RoleMember); err != nil {
		t.Fatalf("create member: %v", err)
	}
	login, err := client.Login(ctx, connect.NewRequest(&aresv1.LoginRequest{Email: "member@example.com", Password: "member-strong-pass"}))
	if err != nil || !login.Msg.GetOk() {
		t.Fatalf("member login: %v", err)
	}
	token := login.Msg.GetToken()

	withTok := func(tenantID string) error {
		req := connect.NewRequest(&aresv1.ListEngagementsRequest{TenantId: tenantID})
		req.Header().Set("Authorization", "Bearer "+token)
		_, err := client.ListEngagements(ctx, req)
		return err
	}

	// Own workspace: allowed.
	if err := withTok("tenant-A"); err != nil {
		t.Errorf("own workspace should be allowed: %v", err)
	}
	// Empty tenant: rewritten to the session's workspace, allowed.
	if err := withTok(""); err != nil {
		t.Errorf("empty tenant should be allowed (rewritten): %v", err)
	}
	// Another workspace: denied.
	if err := withTok("tenant-B"); err == nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("cross-workspace access should be PERMISSION_DENIED, got %v", err)
	}
}
