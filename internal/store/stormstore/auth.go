// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"fmt"
	"time"

	"github.com/asdine/storm/v3"

	"github.com/gsoultan/ares-server/internal/auth"
)

// userRecord is the on-disk shape of a user account. Email carries a unique
// index so the database itself enforces one account per email. The password is
// stored only as its PBKDF2 hash.
type userRecord struct {
	ID           string `storm:"id"`
	TenantID     string `storm:"index"`
	Email        string `storm:"unique"`
	Name         string
	Role         string
	PasswordHash string
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// sessionRecord is the on-disk shape of a session, keyed by the token's hash.
// The raw token is never stored.
type sessionRecord struct {
	TokenHash string `storm:"id"`
	UserID    string
	TenantID  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// UserRepo is a durable auth.UserStore backed by the engagement store's
// database. It is a distinct type so its methods do not collide with the
// engagement store's own.
type UserRepo struct{ db *storm.DB }

var _ auth.UserStore = (*UserRepo)(nil)

// Users returns a durable user store over this store's database.
func (s *Store) Users() *UserRepo { return &UserRepo{db: s.db} }

func toUser(r userRecord) auth.User {
	return auth.User{
		ID: r.ID, TenantID: r.TenantID, Email: r.Email, Name: r.Name,
		Role: auth.Role(r.Role), PasswordHash: r.PasswordHash, Disabled: r.Disabled,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func fromUser(u auth.User) userRecord {
	return userRecord{
		ID: u.ID, TenantID: u.TenantID, Email: auth.NormalizeEmail(u.Email), Name: u.Name,
		Role: string(u.Role), PasswordHash: u.PasswordHash, Disabled: u.Disabled,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

// CreateUser implements auth.UserStore, mapping a unique-index conflict onto
// auth.ErrDuplicateEmail.
func (r *UserRepo) CreateUser(u auth.User) error {
	rec := fromUser(u)
	if err := r.db.Save(&rec); err != nil {
		if err == storm.ErrAlreadyExists {
			return auth.ErrDuplicateEmail
		}
		return fmt.Errorf("stormstore: create user: %w", err)
	}
	return nil
}

// GetUserByEmail implements auth.UserStore.
func (r *UserRepo) GetUserByEmail(email string) (auth.User, bool, error) {
	var rec userRecord
	err := r.db.One("Email", auth.NormalizeEmail(email), &rec)
	if err == storm.ErrNotFound {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, fmt.Errorf("stormstore: get user by email: %w", err)
	}
	return toUser(rec), true, nil
}

// GetUserByID implements auth.UserStore.
func (r *UserRepo) GetUserByID(id string) (auth.User, bool, error) {
	var rec userRecord
	err := r.db.One("ID", id, &rec)
	if err == storm.ErrNotFound {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, fmt.Errorf("stormstore: get user by id: %w", err)
	}
	return toUser(rec), true, nil
}

// ListUsers implements auth.UserStore.
func (r *UserRepo) ListUsers(tenantID string) ([]auth.User, error) {
	var recs []userRecord
	if err := r.db.Find("TenantID", tenantID, &recs); err != nil && err != storm.ErrNotFound {
		return nil, fmt.Errorf("stormstore: list users: %w", err)
	}
	out := make([]auth.User, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toUser(rec))
	}
	return out, nil
}

// UpdateUser implements auth.UserStore.
func (r *UserRepo) UpdateUser(u auth.User) error {
	var existing userRecord
	if err := r.db.One("ID", u.ID, &existing); err != nil {
		if err == storm.ErrNotFound {
			return auth.ErrUserNotFound
		}
		return fmt.Errorf("stormstore: update user lookup: %w", err)
	}
	rec := fromUser(u)
	if err := r.db.Save(&rec); err != nil {
		if err == storm.ErrAlreadyExists {
			return auth.ErrDuplicateEmail
		}
		return fmt.Errorf("stormstore: update user: %w", err)
	}
	return nil
}

// CountUsers implements auth.UserStore.
func (r *UserRepo) CountUsers() (int, error) {
	n, err := r.db.Count(&userRecord{})
	if err != nil {
		return 0, fmt.Errorf("stormstore: count users: %w", err)
	}
	return n, nil
}

// SessionRepo is a durable auth.SessionStore backed by the same database.
type SessionRepo struct{ db *storm.DB }

var _ auth.SessionStore = (*SessionRepo)(nil)

// Sessions returns a durable session store over this store's database.
func (s *Store) Sessions() *SessionRepo { return &SessionRepo{db: s.db} }

// Save implements auth.SessionStore.
func (r *SessionRepo) Save(tokenHash string, s auth.Session) error {
	rec := sessionRecord{
		TokenHash: tokenHash, UserID: s.UserID, TenantID: s.TenantID,
		Role: string(s.Role), CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
	}
	if err := r.db.Save(&rec); err != nil {
		return fmt.Errorf("stormstore: save session: %w", err)
	}
	return nil
}

// Load implements auth.SessionStore.
func (r *SessionRepo) Load(tokenHash string) (auth.Session, bool, error) {
	var rec sessionRecord
	err := r.db.One("TokenHash", tokenHash, &rec)
	if err == storm.ErrNotFound {
		return auth.Session{}, false, nil
	}
	if err != nil {
		return auth.Session{}, false, fmt.Errorf("stormstore: load session: %w", err)
	}
	return auth.Session{
		UserID: rec.UserID, TenantID: rec.TenantID, Role: auth.Role(rec.Role),
		CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	}, true, nil
}

// Delete implements auth.SessionStore.
func (r *SessionRepo) Delete(tokenHash string) error {
	err := r.db.DeleteStruct(&sessionRecord{TokenHash: tokenHash})
	if err != nil && err != storm.ErrNotFound {
		return fmt.Errorf("stormstore: delete session: %w", err)
	}
	return nil
}
