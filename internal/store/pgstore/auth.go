// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/gsoultan/storm/runtime"

	"github.com/gsoultan/ares-server/internal/auth"
	sessionpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/session"
	userpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/user"
)

// UserRepo is a durable auth.UserStore over the storm-generated user package.
type UserRepo struct{ ex runtime.Executor }

var _ auth.UserStore = (*UserRepo)(nil)

// Users returns a durable user store over this store's executor.
func (s *Store) Users() *UserRepo { return &UserRepo{ex: s.ex} }

func toUser(r userpkg.Row) auth.User {
	return auth.User{
		ID: r.ID, TenantID: r.TenantID, Email: r.Email, Name: r.Name,
		Role: auth.Role(r.Role), PasswordHash: r.PasswordHash, Disabled: r.Disabled,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

// CreateUser implements auth.UserStore, mapping a unique-constraint conflict onto
// auth.ErrDuplicateEmail.
func (r *UserRepo) CreateUser(u auth.User) error {
	n := userpkg.Create()
	n.SetID(u.ID)
	n.SetTenantID(u.TenantID)
	n.SetEmail(auth.NormalizeEmail(u.Email))
	n.SetName(u.Name)
	n.SetRole(string(u.Role))
	n.SetPasswordHash(u.PasswordHash)
	n.SetDisabled(u.Disabled)
	n.SetCreatedAt(u.CreatedAt)
	n.SetUpdatedAt(u.UpdatedAt)
	if _, err := n.Insert(context.Background(), r.ex); err != nil {
		if errors.Is(err, runtime.ErrUniqueViolation) {
			return auth.ErrDuplicateEmail
		}
		return fmt.Errorf("pgstore: create user: %w", err)
	}
	return nil
}

// GetUserByEmail implements auth.UserStore.
func (r *UserRepo) GetUserByEmail(email string) (auth.User, bool, error) {
	row, ok, err := userpkg.New().EmailEq(auth.NormalizeEmail(email)).One(context.Background(), r.ex)
	if err != nil {
		return auth.User{}, false, fmt.Errorf("pgstore: get user by email: %w", err)
	}
	if !ok {
		return auth.User{}, false, nil
	}
	return toUser(row), true, nil
}

// GetUserByID implements auth.UserStore.
func (r *UserRepo) GetUserByID(id string) (auth.User, bool, error) {
	row, ok, err := userpkg.New().IDEq(id).One(context.Background(), r.ex)
	if err != nil {
		return auth.User{}, false, fmt.Errorf("pgstore: get user by id: %w", err)
	}
	if !ok {
		return auth.User{}, false, nil
	}
	return toUser(row), true, nil
}

// ListUsers implements auth.UserStore.
func (r *UserRepo) ListUsers(tenantID string) ([]auth.User, error) {
	rows, err := userpkg.New().TenantIDEq(tenantID).All(context.Background(), r.ex, nil)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list users: %w", err)
	}
	out := make([]auth.User, 0, len(rows))
	for _, row := range rows {
		out = append(out, toUser(row))
	}
	return out, nil
}

// UpdateUser implements auth.UserStore, returning ErrUserNotFound when the id is
// unknown and ErrDuplicateEmail when the new email collides.
func (r *UserRepo) UpdateUser(u auth.User) error {
	if _, ok, err := r.GetUserByID(u.ID); err != nil {
		return err
	} else if !ok {
		return auth.ErrUserNotFound
	}
	m := userpkg.MutateKey(u.ID)
	m.SetTenantID(u.TenantID)
	m.SetEmail(auth.NormalizeEmail(u.Email))
	m.SetName(u.Name)
	m.SetRole(string(u.Role))
	m.SetPasswordHash(u.PasswordHash)
	m.SetDisabled(u.Disabled)
	m.SetCreatedAt(u.CreatedAt)
	m.SetUpdatedAt(u.UpdatedAt)
	if err := m.Update(context.Background(), r.ex); err != nil {
		if errors.Is(err, runtime.ErrUniqueViolation) {
			return auth.ErrDuplicateEmail
		}
		return fmt.Errorf("pgstore: update user: %w", err)
	}
	return nil
}

// CountUsers implements auth.UserStore.
func (r *UserRepo) CountUsers() (int, error) {
	n, err := userpkg.New().Count(context.Background(), r.ex)
	if err != nil {
		return 0, fmt.Errorf("pgstore: count users: %w", err)
	}
	return int(n), nil
}

// SessionRepo is a durable auth.SessionStore over the generated session package.
type SessionRepo struct{ ex runtime.Executor }

var _ auth.SessionStore = (*SessionRepo)(nil)

// Sessions returns a durable session store over this store's executor.
func (s *Store) Sessions() *SessionRepo { return &SessionRepo{ex: s.ex} }

// Save implements auth.SessionStore, upserting by token hash.
func (r *SessionRepo) Save(tokenHash string, s auth.Session) error {
	n := sessionpkg.Create()
	n.SetTokenHash(tokenHash)
	n.SetUserID(s.UserID)
	n.SetTenantID(s.TenantID)
	n.SetRole(string(s.Role))
	n.SetCreatedAt(s.CreatedAt)
	n.SetExpiresAt(s.ExpiresAt)
	if _, err := n.OnConflictTokenHash().Insert(context.Background(), r.ex); err != nil {
		return fmt.Errorf("pgstore: save session: %w", err)
	}
	return nil
}

// Load implements auth.SessionStore.
func (r *SessionRepo) Load(tokenHash string) (auth.Session, bool, error) {
	row, ok, err := sessionpkg.New().TokenHashEq(tokenHash).One(context.Background(), r.ex)
	if err != nil {
		return auth.Session{}, false, fmt.Errorf("pgstore: load session: %w", err)
	}
	if !ok {
		return auth.Session{}, false, nil
	}
	return auth.Session{
		UserID: row.UserID, TenantID: row.TenantID, Role: auth.Role(row.Role),
		CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
	}, true, nil
}

// Delete implements auth.SessionStore.
func (r *SessionRepo) Delete(tokenHash string) error {
	if err := sessionpkg.Delete(context.Background(), r.ex, tokenHash); err != nil {
		return fmt.Errorf("pgstore: delete session: %w", err)
	}
	return nil
}

// DeleteForUser implements auth.SessionStore.
func (r *SessionRepo) DeleteForUser(userID string) error {
	if _, err := sessionpkg.New().UserIDEq(userID).DeleteAll(context.Background(), r.ex); err != nil {
		return fmt.Errorf("pgstore: delete sessions for user: %w", err)
	}
	return nil
}
