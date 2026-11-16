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
	"net/http"
	"strings"
	"sync/atomic"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gsoultan/ares-server/internal/auth"
)

// SessionFromContext returns the authenticated session, if the interceptor put
// one there. ok is false for unauthenticated (public) calls.
func SessionFromContext(ctx context.Context) (auth.Session, bool) {
	return auth.SessionFrom(ctx)
}

// publicProcedures are the RPCs that never require a session: first-run setup
// and the authentication endpoints themselves (which authenticate from their
// own request body, not a bearer token).
var publicProcedures = map[string]bool{
	"GetSetupStatus":         true,
	"TestDatabaseConnection": true,
	"CommitSetup":            true,
	"Login":                  true,
	"Logout":                 true,
	"CurrentUser":            true,
}

// EnforceMode controls when the interceptor requires authentication on protected
// procedures.
type EnforceMode string

const (
	// EnforceAuto requires auth once the install has at least one account (i.e.
	// after first-run setup). Before setup, protected RPCs are open so the wizard
	// works. This is the default.
	EnforceAuto EnforceMode = "auto"
	// EnforceOn always requires auth on protected procedures.
	EnforceOn EnforceMode = "on"
	// EnforceOff never rejects for a missing session (it still authenticates a
	// presented token and still enforces tenant scoping when a session exists).
	EnforceOff EnforceMode = "off"
)

// ParseEnforceMode maps a string (e.g. from the environment) to a mode,
// defaulting to EnforceAuto.
func ParseEnforceMode(s string) EnforceMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on":
		return EnforceOn
	case "off":
		return EnforceOff
	default:
		return EnforceAuto
	}
}

// authInterceptor authenticates bearer tokens and enforces per-tenant scoping.
type authInterceptor struct {
	auth  *auth.Service
	mode  EnforceMode
	armed atomic.Bool // in auto mode, latches true once an account exists
}

// NewAuthInterceptor builds the control-plane auth interceptor. With a nil auth
// service it is a no-op (auth disabled). The concrete type also exposes
// RESTMiddleware, so the legacy REST surface shares the same enforcement latch.
func NewAuthInterceptor(a *auth.Service, mode EnforceMode) *authInterceptor {
	return &authInterceptor{auth: a, mode: mode}
}

// enforcing reports whether a missing session should be rejected for protected
// procedures right now.
func (i *authInterceptor) enforcing() bool {
	switch i.mode {
	case EnforceOn:
		return true
	case EnforceOff:
		return false
	default: // auto
		if i.armed.Load() {
			return true
		}
		n, err := i.auth.CountUsers()
		if err == nil && n > 0 {
			i.armed.Store(true)
			return true
		}
		return false
	}
}

func procName(procedure string) string {
	if i := strings.LastIndex(procedure, "/"); i >= 0 {
		return procedure[i+1:]
	}
	return procedure
}

// WrapUnary implements connect.Interceptor.
func (i *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if i.auth == nil {
			return next(ctx, req)
		}
		name := procName(req.Spec().Procedure)

		// Authenticate a presented token. A malformed/expired token is always an
		// error, even on public procedures: a client should not send a bad one.
		var sess auth.Session
		haveSess := false
		if token := bearerToken(req.Header().Get("Authorization")); token != "" {
			s, err := i.auth.Authenticate(token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired session"))
			}
			sess, haveSess = s, true
			ctx = auth.WithSession(ctx, s)
		}

		if publicProcedures[name] {
			return next(ctx, req)
		}

		// Protected procedure: require a session when enforcing.
		if !haveSess {
			if i.enforcing() {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
			}
			return next(ctx, req) // pre-setup / off mode: open
		}

		// Enforce tenant scoping centrally: a non-super account may act only within
		// its own workspace. An empty tenant_id is rewritten to the session's
		// tenant, so the session is the authority and the client need not send it.
		if sess.Role != auth.RoleSuperAdmin {
			if err := enforceTenant(req, sess.TenantID); err != nil {
				return nil, err
			}
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor (unused; pass-through).
func (i *authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor (unused; pass-through).
func (i *authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// bearerToken extracts the token from an Authorization header value.
func bearerToken(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// enforceTenant reads the request's tenant_id field (if any) and binds it to the
// caller's workspace: empty is set to the session tenant; a different value is
// rejected. This gives one central isolation boundary for every tenant-scoped
// RPC without per-handler code.
func enforceTenant(req connect.AnyRequest, tenantID string) error {
	msg, ok := req.Any().(proto.Message)
	if !ok {
		return nil
	}
	m := msg.ProtoReflect()
	fd := m.Descriptor().Fields().ByName("tenant_id")
	if fd == nil || fd.Kind() != protoreflect.StringKind {
		return nil // this RPC is not tenant-scoped
	}
	cur := m.Get(fd).String()
	if cur == "" {
		m.Set(fd, protoreflect.ValueOfString(tenantID))
		return nil
	}
	if cur != tenantID {
		return connect.NewError(connect.CodePermissionDenied, errors.New("cross-workspace access denied"))
	}
	return nil
}

// restTenantHeader names the workspace header on the legacy REST surface. It
// must match internal/api.tenantHeader; it is duplicated here to avoid an import
// cycle (that package builds the handler this middleware wraps).
const restTenantHeader = "X-Ares-Tenant"

// restPublicPaths are REST routes that stay open even when auth is enforced, so
// liveness probes keep working before and after sign-in.
var restPublicPaths = map[string]bool{
	"/healthz": true,
}

// RESTMiddleware wraps the legacy REST surface with the same bearer-token
// authentication and per-tenant isolation the gRPC/Connect interceptor applies.
// It shares the interceptor's "armed" latch, so REST and Connect switch on
// enforcement together. With a nil auth service it is a pass-through.
//
// When enforcing, every non-public REST route requires a valid session. A
// non-super caller's workspace header is bound to the session tenant (an
// explicit, mismatching header is rejected), so a REST client cannot reach
// another tenant's data.
func (i *authInterceptor) RESTMiddleware(next http.Handler) http.Handler {
	if i == nil || i.auth == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			sess     auth.Session
			haveSess bool
		)
		if token := bearerToken(r.Header.Get("Authorization")); token != "" {
			s, err := i.auth.Authenticate(token)
			if err != nil {
				http.Error(w, "invalid or expired session", http.StatusUnauthorized)
				return
			}
			sess, haveSess = s, true
		}

		if restPublicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		if !haveSess {
			if i.enforcing() {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r) // pre-setup / off mode: open
			return
		}

		// Bind the workspace to the session for a non-super caller, mirroring the
		// central tenant enforcement on the gRPC path.
		if sess.Role != auth.RoleSuperAdmin {
			if cur := r.Header.Get(restTenantHeader); cur != "" && cur != sess.TenantID {
				http.Error(w, "cross-workspace access denied", http.StatusForbidden)
				return
			}
			r.Header.Set(restTenantHeader, sess.TenantID)
		}
		next.ServeHTTP(w, r.WithContext(auth.WithSession(r.Context(), sess)))
	})
}
