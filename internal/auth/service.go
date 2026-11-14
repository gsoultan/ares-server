// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/gsoultan/ares-server/internal/uuid"
)

// Errors returned by the service.
var (
	// ErrInvalidCredentials is returned for a wrong email or password. It is
	// deliberately identical for both so it reveals nothing about which accounts
	// exist.
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	// ErrNotAuthenticated is returned when a token is missing, unknown, or expired.
	ErrNotAuthenticated = errors.New("auth: not authenticated")
	// ErrDisabled is returned when a disabled account attempts to authenticate.
	ErrDisabled = errors.New("auth: account is disabled")
	// ErrInvalidRole is returned when an unknown role is supplied.
	ErrInvalidRole = errors.New("auth: invalid role")
	// ErrEmptyField is returned when a required field is blank.
	ErrEmptyField = errors.New("auth: email and name are required")
)

// Service performs authentication over a user store and a session store.
type Service struct {
	users    UserStore
	sessions SessionStore
	ttl      time.Duration
}

// NewService builds an auth service with the default session TTL.
func NewService(users UserStore, sessions SessionStore) *Service {
	return &Service{users: users, sessions: sessions, ttl: DefaultSessionTTL}
}

// WithTTL overrides the session lifetime.
func (s *Service) WithTTL(d time.Duration) *Service {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// CountUsers reports how many accounts exist (used to detect first run).
func (s *Service) CountUsers() (int, error) { return s.users.CountUsers() }

// CreateUser creates and stores a user with a hashed password. It enforces the
// password-length policy and role validity; the caller is responsible for the
// authorization to create the account.
func (s *Service) CreateUser(tenantID, email, name, password string, role Role) (User, error) {
	email = NormalizeEmail(email)
	if email == "" || name == "" {
		return User{}, ErrEmptyField
	}
	if !role.Valid() {
		return User{}, ErrInvalidRole
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	u := User{
		ID:           uuid.NewV7(),
		TenantID:     tenantID,
		Email:        email,
		Name:         name,
		Role:         role,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.CreateUser(u); err != nil {
		return User{}, err
	}
	return u, nil
}

// ListUsers returns the accounts in a workspace.
func (s *Service) ListUsers(tenantID string) ([]User, error) {
	return s.users.ListUsers(tenantID)
}

// GetUser returns an account by id.
func (s *Service) GetUser(id string) (User, bool, error) {
	return s.users.GetUserByID(id)
}

// SetRole changes a user's role and persists it.
func (s *Service) SetRole(id string, role Role) (User, error) {
	if !role.Valid() {
		return User{}, ErrInvalidRole
	}
	u, ok, err := s.users.GetUserByID(id)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, ErrUserNotFound
	}
	u.Role = role
	u.UpdatedAt = time.Now().UTC()
	if err := s.users.UpdateUser(u); err != nil {
		return User{}, err
	}
	return u, nil
}

// SetDisabled enables or disables an account and persists the change.
func (s *Service) SetDisabled(id string, disabled bool) (User, error) {
	u, ok, err := s.users.GetUserByID(id)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, ErrUserNotFound
	}
	u.Disabled = disabled
	u.UpdatedAt = time.Now().UTC()
	if err := s.users.UpdateUser(u); err != nil {
		return User{}, err
	}
	return u, nil
}

// Login verifies credentials and opens a session. On any failure of lookup or
// password it returns ErrInvalidCredentials, with no distinction between an
// unknown account and a wrong password.
func (s *Service) Login(email, password string) (Session, User, error) {
	u, ok, err := s.users.GetUserByEmail(email)
	if err != nil {
		return Session{}, User{}, err
	}
	if !ok {
		// Spend comparable work so the response time does not reveal whether the
		// account exists.
		_, _ = VerifyPassword(dummyHash, password)
		return Session{}, User{}, ErrInvalidCredentials
	}
	match, err := VerifyPassword(u.PasswordHash, password)
	if err != nil || !match {
		return Session{}, User{}, ErrInvalidCredentials
	}
	if u.Disabled {
		return Session{}, User{}, ErrDisabled
	}
	sess, err := s.openSession(u)
	if err != nil {
		return Session{}, User{}, err
	}
	return sess, u, nil
}

// Authenticate validates a bearer token and returns the live session, or
// ErrNotAuthenticated when it is unknown or expired. An expired session is
// cleaned up as it is rejected.
func (s *Service) Authenticate(token string) (Session, error) {
	if token == "" {
		return Session{}, ErrNotAuthenticated
	}
	h := hashToken(token)
	sess, ok, err := s.sessions.Load(h)
	if err != nil {
		return Session{}, err
	}
	if !ok {
		return Session{}, ErrNotAuthenticated
	}
	if sess.Expired() {
		_ = s.sessions.Delete(h)
		return Session{}, ErrNotAuthenticated
	}
	return sess, nil
}

// CurrentUser returns the user behind a valid token.
func (s *Service) CurrentUser(token string) (User, error) {
	sess, err := s.Authenticate(token)
	if err != nil {
		return User{}, err
	}
	u, ok, err := s.users.GetUserByID(sess.UserID)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, ErrNotAuthenticated
	}
	return u, nil
}

// Logout revokes a session token. Revoking an unknown token is a no-op.
func (s *Service) Logout(token string) error {
	if token == "" {
		return nil
	}
	return s.sessions.Delete(hashToken(token))
}

// openSession mints a new session for a user and stores it by token hash.
func (s *Service) openSession(u User) (Session, error) {
	token, err := newToken()
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	sess := Session{
		Token:     token,
		UserID:    u.ID,
		TenantID:  u.TenantID,
		Role:      u.Role,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	if err := s.sessions.Save(hashToken(token), sess); err != nil {
		return Session{}, fmt.Errorf("auth: save session: %w", err)
	}
	return sess, nil
}

// dummyHash is a valid hash of a throwaway value, used to equalize login timing
// when an account does not exist. It is computed once at init.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := HashPassword("ares-timing-equalizer-value")
	if err != nil {
		// HashPassword only fails on a short password or RNG failure; this input
		// is long, so a failure here is a build/runtime impossibility.
		panic("auth: dummy hash: " + err.Error())
	}
	return h
}
