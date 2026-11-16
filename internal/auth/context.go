// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import "context"

// sessionCtxKey carries the authenticated session through a request context.
type sessionCtxKey struct{}

// WithSession returns a context that carries the authenticated session. The
// auth interceptor and the REST middleware put it there; handlers read it with
// SessionFrom.
func WithSession(ctx context.Context, s Session) context.Context {
	s.Token = "" // never carry the raw bearer token deeper than the edge
	return context.WithValue(ctx, sessionCtxKey{}, s)
}

// SessionFrom returns the authenticated session, if any. ok is false for an
// unauthenticated call (a public procedure, or auth not enforced).
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionCtxKey{}).(Session)
	return s, ok
}

// IsManager reports whether a role may administer a workspace: its settings,
// its users and its provider keys.
func (r Role) IsManager() bool {
	switch r {
	case RoleSuperAdmin, RoleOwner, RoleAdmin:
		return true
	}
	return false
}
