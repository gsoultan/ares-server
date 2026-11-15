// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
)

// authHandler returns a handler wired with an auth service over mem stores.
func authHandler(t *testing.T) (*Handler, *auth.Service) {
	t.Helper()
	a := auth.NewService(auth.NewMemUserStore(), auth.NewMemSessionStore())
	return newTestHandler(t).WithAuth(a), a
}

func asSession(sess auth.Session) context.Context {
	return auth.WithSession(context.Background(), sess)
}

func sessFor(t *testing.T, a *auth.Service, tenantID, email string, role auth.Role) auth.Session {
	t.Helper()
	u, err := a.CreateUser(tenantID, email, email, "a-strong-password-x", role)
	if err != nil {
		t.Fatalf("create %s: %v", email, err)
	}
	return auth.Session{UserID: u.ID, TenantID: u.TenantID, Role: u.Role}
}

func TestCreateUserAuthorization(t *testing.T) {
	h, a := authHandler(t)
	super := sessFor(t, a, "t-root", "super@example.com", auth.RoleSuperAdmin)
	admin := sessFor(t, a, "t-a", "admin@example.com", auth.RoleAdmin)
	member := sessFor(t, a, "t-a", "member@example.com", auth.RoleMember)

	// Member cannot manage users.
	_, err := h.CreateUser(asSession(member), connect.NewRequest(&aresv1.CreateUserRequest{
		TenantId: "t-a", Email: "x@example.com", Name: "X", Password: "a-strong-password-x", Role: "member",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("member create err = %v, want PermissionDenied", err)
	}

	// Admin cannot grant owner (above own role).
	_, err = h.CreateUser(asSession(admin), connect.NewRequest(&aresv1.CreateUserRequest{
		TenantId: "t-a", Email: "owner@example.com", Name: "O", Password: "a-strong-password-x", Role: "owner",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("admin grant owner err = %v, want PermissionDenied", err)
	}

	// Admin can create a member in own tenant.
	resp, err := h.CreateUser(asSession(admin), connect.NewRequest(&aresv1.CreateUserRequest{
		TenantId: "t-a", Email: "m2@example.com", Name: "M2", Password: "a-strong-password-x", Role: "member",
	}))
	if err != nil {
		t.Fatalf("admin create member: %v", err)
	}
	if resp.Msg.GetTenantId() != "t-a" || resp.Msg.GetRole() != "member" {
		t.Errorf("created user wrong: %+v", resp.Msg)
	}

	// Super-admin can grant superadmin.
	if _, err := h.CreateUser(asSession(super), connect.NewRequest(&aresv1.CreateUserRequest{
		TenantId: "t-b", Email: "super2@example.com", Name: "S2", Password: "a-strong-password-x", Role: "superadmin",
	})); err != nil {
		t.Errorf("super create superadmin: %v", err)
	}

	// A non-super's created user is forced into their own tenant even if they ask
	// for another (defense in depth; the interceptor also binds tenant_id).
	resp2, err := h.CreateUser(asSession(admin), connect.NewRequest(&aresv1.CreateUserRequest{
		TenantId: "t-OTHER", Email: "m3@example.com", Name: "M3", Password: "a-strong-password-x", Role: "member",
	}))
	if err != nil {
		t.Fatalf("admin create m3: %v", err)
	}
	if resp2.Msg.GetTenantId() != "t-a" {
		t.Errorf("non-super create must be forced to own tenant, got %q", resp2.Msg.GetTenantId())
	}
	_ = member
}

func TestListUsersScopedToWorkspace(t *testing.T) {
	h, a := authHandler(t)
	admin := sessFor(t, a, "t-a", "admin@example.com", auth.RoleAdmin)
	_ = sessFor(t, a, "t-a", "m1@example.com", auth.RoleMember)
	_ = sessFor(t, a, "t-b", "other@example.com", auth.RoleMember)

	resp, err := h.ListUsers(asSession(admin), connect.NewRequest(&aresv1.ListUsersRequest{TenantId: "t-b"}))
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	// Even though the admin asked for t-b, they get their own workspace.
	for _, u := range resp.Msg.GetUsers() {
		if u.GetTenantId() != "t-a" {
			t.Errorf("admin saw a user outside their workspace: %+v", u)
		}
	}
}

func TestSetUserRoleCrossTenantDenied(t *testing.T) {
	h, a := authHandler(t)
	admin := sessFor(t, a, "t-a", "admin@example.com", auth.RoleAdmin)
	victim := sessFor(t, a, "t-b", "victim@example.com", auth.RoleMember)

	_, err := h.SetUserRole(asSession(admin), connect.NewRequest(&aresv1.SetUserRoleRequest{
		UserId: victim.UserID, Role: "admin",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("cross-tenant role change err = %v, want PermissionDenied", err)
	}
}

func TestSetUserDisabledSelfLockoutGuard(t *testing.T) {
	h, a := authHandler(t)
	owner := sessFor(t, a, "t-a", "owner@example.com", auth.RoleOwner)
	_, err := h.SetUserDisabled(asSession(owner), connect.NewRequest(&aresv1.SetUserDisabledRequest{
		UserId: owner.UserID, Disabled: true,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("self-disable err = %v, want InvalidArgument", err)
	}
}

func TestUserMgmtRequiresSession(t *testing.T) {
	h, _ := authHandler(t)
	// No session in context.
	_, err := h.ListUsers(context.Background(), connect.NewRequest(&aresv1.ListUsersRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no-session err = %v, want Unauthenticated", err)
	}
}
