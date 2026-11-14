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
	"time"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
)

// Login verifies email + password and opens a server-side session, returning a
// bearer token. On failure it returns a generic error that reveals nothing about
// which accounts exist.
func (h *Handler) Login(_ context.Context, req *connect.Request[aresv1.LoginRequest]) (*connect.Response[aresv1.LoginResponse], error) {
	if h.auth == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("authentication is not available on this instance"))
	}
	sess, user, err := h.auth.Login(req.Msg.GetEmail(), req.Msg.GetPassword())
	if err != nil {
		// Invalid credentials and disabled accounts are surfaced in-band, generic.
		if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrDisabled) {
			return connect.NewResponse(&aresv1.LoginResponse{Ok: false, Error: "invalid email or password"}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&aresv1.LoginResponse{
		Ok:        true,
		Token:     sess.Token,
		ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
		User:      userInfoProto(user),
	}), nil
}

// Logout revokes a session token. It is idempotent.
func (h *Handler) Logout(_ context.Context, req *connect.Request[aresv1.LogoutRequest]) (*connect.Response[aresv1.LogoutResponse], error) {
	if h.auth == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("authentication is not available on this instance"))
	}
	if err := h.auth.Logout(req.Msg.GetToken()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&aresv1.LogoutResponse{Ok: true}), nil
}

// CurrentUser returns the account behind a valid session token.
func (h *Handler) CurrentUser(_ context.Context, req *connect.Request[aresv1.CurrentUserRequest]) (*connect.Response[aresv1.UserInfo], error) {
	if h.auth == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("authentication is not available on this instance"))
	}
	user, err := h.auth.CurrentUser(req.Msg.GetToken())
	if err != nil {
		if errors.Is(err, auth.ErrNotAuthenticated) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(userInfoProto(user)), nil
}

func userInfoProto(u auth.User) *aresv1.UserInfo {
	info := &aresv1.UserInfo{
		Id:       u.ID,
		TenantId: u.TenantID,
		Email:    u.Email,
		Name:     u.Name,
		Role:     string(u.Role),
		Disabled: u.Disabled,
	}
	if !u.CreatedAt.IsZero() {
		info.CreatedAt = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	return info
}
