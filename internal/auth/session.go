// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DefaultSessionTTL is how long a session stays valid without re-authentication.
const DefaultSessionTTL = 12 * time.Hour

// Session is a server-side authentication session. The raw Token is returned to
// the client once and is never stored; the store keeps only its hash, so a
// database disclosure does not hand out live sessions.
type Session struct {
	Token     string    `json:"token"` // opaque bearer token (raw, client-side only)
	UserID    string    `json:"userId"`
	TenantID  string    `json:"tenantId"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Expired reports whether the session is past its expiry.
func (s Session) Expired() bool { return time.Now().After(s.ExpiresAt) }

// SessionStore persists sessions keyed by the token's hash. Implementations must
// be safe for concurrent use.
type SessionStore interface {
	// Save stores a session by the hash of its token.
	Save(tokenHash string, s Session) error
	// Load returns the session for a token hash, or ok=false.
	Load(tokenHash string) (Session, bool, error)
	// Delete removes a session by token hash.
	Delete(tokenHash string) error
	// DeleteForUser removes every session of a user. It revokes access at once
	// when an account is disabled or its role changes.
	DeleteForUser(userID string) error
}

// newToken returns a 256-bit random bearer token, URL-safe base64.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the hex SHA-256 of a token, the key under which the session
// is stored. Looking a token up requires presenting it, so the stored hash alone
// is not a usable credential.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// MemSessionStore is an in-memory SessionStore for tests and ephemeral runs.
type MemSessionStore struct {
	mu sync.Mutex
	m  map[string]Session
}

// NewMemSessionStore builds an empty in-memory session store.
func NewMemSessionStore() *MemSessionStore { return &MemSessionStore{m: map[string]Session{}} }

// Save implements SessionStore.
func (s *MemSessionStore) Save(tokenHash string, sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Never retain the raw token in the stored copy.
	sess.Token = ""
	s.m[tokenHash] = sess
	return nil
}

// Load implements SessionStore.
func (s *MemSessionStore) Load(tokenHash string) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[tokenHash]
	return sess, ok, nil
}

// Delete implements SessionStore.
func (s *MemSessionStore) Delete(tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tokenHash)
	return nil
}

// DeleteForUser implements SessionStore.
func (s *MemSessionStore) DeleteForUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, sess := range s.m {
		if sess.UserID == userID {
			delete(s.m, h)
		}
	}
	return nil
}
