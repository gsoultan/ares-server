// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
)

// roleRank orders roles for "may not grant a role above your own" checks.
func roleRank(r auth.Role) int {
	switch r {
	case auth.RoleSuperAdmin:
		return 4
	case auth.RoleOwner:
		return 3
	case auth.RoleAdmin:
		return 2
	case auth.RoleMember:
		return 1
	default:
		return 0
	}
}

// actingSession returns the caller's session, or an error if there is none (user
// management always requires an authenticated manager).
func (h *Handler) actingSession(ctx context.Context) (auth.Session, error) {
	if h.auth == nil {
		return auth.Session{}, connect.NewError(connect.CodeUnavailable, errors.New("authentication is not available"))
	}
	sess, ok := SessionFromContext(ctx)
	if !ok {
		return auth.Session{}, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return sess, nil
}

// requireManager checks the caller may manage users at all.
func requireManager(sess auth.Session) error {
	switch sess.Role {
	case auth.RoleSuperAdmin, auth.RoleOwner, auth.RoleAdmin:
		return nil
	default:
		return connect.NewError(connect.CodePermissionDenied, errors.New("insufficient role to manage users"))
	}
}

// targetInScope checks the caller may act on a user in targetTenant. A non-super
// manager is confined to their own workspace. (The interceptor already binds the
// tenant_id field on requests that carry one; this covers requests keyed by user
// id.)
func targetInScope(sess auth.Session, targetTenant string) error {
	if sess.Role == auth.RoleSuperAdmin {
		return nil
	}
	if targetTenant != sess.TenantID {
		return connect.NewError(connect.CodePermissionDenied, errors.New("cross-workspace user management denied"))
	}
	return nil
}

// checkGrant ensures the caller may grant the given role: no one may grant a role
// higher than their own, and only a super-admin may grant superadmin.
func checkGrant(sess auth.Session, role auth.Role) error {
	if !role.Valid() {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid role"))
	}
	if role == auth.RoleSuperAdmin && sess.Role != auth.RoleSuperAdmin {
		return connect.NewError(connect.CodePermissionDenied, errors.New("only a super-admin may grant superadmin"))
	}
	if roleRank(role) > roleRank(sess.Role) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("cannot grant a role above your own"))
	}
	return nil
}

// ListUsers returns the accounts in a workspace. The interceptor has already
// bound tenant_id to the caller's workspace for non-super accounts.
func (h *Handler) ListUsers(ctx context.Context, req *connect.Request[aresv1.ListUsersRequest]) (*connect.Response[aresv1.ListUsersResponse], error) {
	sess, err := h.actingSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireManager(sess); err != nil {
		return nil, err
	}
	tenantID := req.Msg.GetTenantId()
	if sess.Role != auth.RoleSuperAdmin {
		tenantID = sess.TenantID
	}
	users, err := h.auth.ListUsers(tenantID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &aresv1.ListUsersResponse{Users: make([]*aresv1.UserInfo, 0, len(users))}
	for _, u := range users {
		out.Users = append(out.Users, userInfoProto(u))
	}
	return connect.NewResponse(out), nil
}

// CreateUser adds an account to a workspace.
func (h *Handler) CreateUser(ctx context.Context, req *connect.Request[aresv1.CreateUserRequest]) (*connect.Response[aresv1.UserInfo], error) {
	sess, err := h.actingSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireManager(sess); err != nil {
		return nil, err
	}
	tenantID := req.Msg.GetTenantId()
	if sess.Role != auth.RoleSuperAdmin {
		tenantID = sess.TenantID
	}
	role := auth.Role(req.Msg.GetRole())
	if err := checkGrant(sess, role); err != nil {
		return nil, err
	}
	u, err := h.auth.CreateUser(tenantID, req.Msg.GetEmail(), req.Msg.GetName(), req.Msg.GetPassword(), role)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrDuplicateEmail):
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrEmptyField), errors.Is(err, auth.ErrInvalidRole):
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		default:
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return connect.NewResponse(userInfoProto(u)), nil
}

// SetUserRole changes a user's role.
func (h *Handler) SetUserRole(ctx context.Context, req *connect.Request[aresv1.SetUserRoleRequest]) (*connect.Response[aresv1.UserInfo], error) {
	sess, err := h.actingSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireManager(sess); err != nil {
		return nil, err
	}
	target, ok, err := h.auth.GetUser(req.Msg.GetUserId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	if err := targetInScope(sess, target.TenantID); err != nil {
		return nil, err
	}
	newRole := auth.Role(req.Msg.GetRole())
	if err := checkGrant(sess, newRole); err != nil {
		return nil, err
	}
	// A non-super may not change an account whose current role already outranks
	// them (e.g. an admin may not demote an owner).
	if sess.Role != auth.RoleSuperAdmin && roleRank(target.Role) > roleRank(sess.Role) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("cannot modify an account above your role"))
	}
	u, err := h.auth.SetRole(target.ID, newRole)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(userInfoProto(u)), nil
}

// SetUserDisabled enables or disables an account.
func (h *Handler) SetUserDisabled(ctx context.Context, req *connect.Request[aresv1.SetUserDisabledRequest]) (*connect.Response[aresv1.UserInfo], error) {
	sess, err := h.actingSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireManager(sess); err != nil {
		return nil, err
	}
	target, ok, err := h.auth.GetUser(req.Msg.GetUserId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	if err := targetInScope(sess, target.TenantID); err != nil {
		return nil, err
	}
	// Guard against self-lockout and against a lower role disabling a higher one.
	if target.ID == sess.UserID {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("cannot change your own enabled state"))
	}
	if sess.Role != auth.RoleSuperAdmin && roleRank(target.Role) >= roleRank(sess.Role) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("cannot modify an account at or above your role"))
	}
	u, err := h.auth.SetDisabled(target.ID, req.Msg.GetDisabled())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(userInfoProto(u)), nil
}
