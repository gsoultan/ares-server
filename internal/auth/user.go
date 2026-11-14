// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package auth is Ares's multi-tenant identity layer: user accounts with
// built-in email + password authentication (PBKDF2-hashed), roles, and
// server-side sessions. A super-administrator owns the platform; every other
// user belongs to exactly one workspace (tenant), and the session an RPC carries
// decides which workspace's data it may touch. Isolation is enforced here and at
// the API boundary, not left to convention.
package auth

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// Role is a user's authorization level. The super-administrator is platform-
// wide; owner/admin/member are scoped to a single workspace.
type Role string

const (
	// RoleSuperAdmin can administer the platform and every workspace. Created at
	// first-run setup.
	RoleSuperAdmin Role = "superadmin"
	// RoleOwner owns a workspace (full control within it, including user mgmt).
	RoleOwner Role = "owner"
	// RoleAdmin administers a workspace's engagements and settings.
	RoleAdmin Role = "admin"
	// RoleMember operates within a workspace.
	RoleMember Role = "member"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleSuperAdmin, RoleOwner, RoleAdmin, RoleMember:
		return true
	}
	return false
}

// User is one account. PasswordHash is a self-describing PBKDF2 hash; the
// plaintext password is never stored.
type User struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenantId"`
	Email        string    `json:"email"` // unique across the platform, normalized lower-case
	Name         string    `json:"name"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"-"` // never serialized out of the store
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// Errors returned by user stores.
var (
	ErrDuplicateEmail = errors.New("auth: a user with that email already exists")
	ErrUserNotFound   = errors.New("auth: user not found")
)

// NormalizeEmail lower-cases and trims an email for consistent uniqueness and
// lookup. Login and creation both route through it.
func NormalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// UserStore persists user accounts. Email uniqueness is global and enforced by
// the store. Implementations must be safe for concurrent use.
type UserStore interface {
	// CreateUser stores a new user, returning ErrDuplicateEmail if the email is
	// already taken.
	CreateUser(User) error
	// GetUserByEmail returns a user by normalized email.
	GetUserByEmail(email string) (User, bool, error)
	// GetUserByID returns a user by id.
	GetUserByID(id string) (User, bool, error)
	// ListUsers returns the users in a workspace.
	ListUsers(tenantID string) ([]User, error)
	// UpdateUser replaces an existing user (by id), returning ErrUserNotFound if
	// it does not exist.
	UpdateUser(User) error
	// CountUsers returns the total number of accounts (used to detect first run).
	CountUsers() (int, error)
}

// MemUserStore is an in-memory UserStore for tests and ephemeral runs.
type MemUserStore struct {
	mu      sync.Mutex
	byID    map[string]User
	byEmail map[string]string // email -> id
}

// NewMemUserStore builds an empty in-memory user store.
func NewMemUserStore() *MemUserStore {
	return &MemUserStore{byID: map[string]User{}, byEmail: map[string]string{}}
}

// CreateUser implements UserStore.
func (s *MemUserStore) CreateUser(u User) error {
	u.Email = NormalizeEmail(u.Email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[u.Email]; ok {
		return ErrDuplicateEmail
	}
	s.byID[u.ID] = u
	s.byEmail[u.Email] = u.ID
	return nil
}

// GetUserByEmail implements UserStore.
func (s *MemUserStore) GetUserByEmail(email string) (User, bool, error) {
	email = NormalizeEmail(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[email]
	if !ok {
		return User{}, false, nil
	}
	u, ok := s.byID[id]
	return u, ok, nil
}

// GetUserByID implements UserStore.
func (s *MemUserStore) GetUserByID(id string) (User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	return u, ok, nil
}

// ListUsers implements UserStore.
func (s *MemUserStore) ListUsers(tenantID string) ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []User
	for _, u := range s.byID {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	return out, nil
}

// UpdateUser implements UserStore.
func (s *MemUserStore) UpdateUser(u User) error {
	u.Email = NormalizeEmail(u.Email)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byID[u.ID]
	if !ok {
		return ErrUserNotFound
	}
	// Keep the email index consistent if the email changed.
	if old.Email != u.Email {
		if _, taken := s.byEmail[u.Email]; taken {
			return ErrDuplicateEmail
		}
		delete(s.byEmail, old.Email)
		s.byEmail[u.Email] = u.ID
	}
	s.byID[u.ID] = u
	return nil
}

// CountUsers implements UserStore.
func (s *MemUserStore) CountUsers() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID), nil
}
