// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"sync"
	"time"
)

// Every authenticated request loads its session, and (to apply a disable or a
// role change at once) the account behind it. Against Postgres that is two
// round trips before the handler runs, on every request. CachedSessions and
// CachedUsers put a short-lived in-process cache in front of the two stores:
//
//   - Every write that goes through the cached store (Save, Delete,
//     DeleteForUser, UpdateUser) evicts the affected entries before it returns,
//     so a logout, a disable or a role change made through this process takes
//     effect on the very next request, exactly as without the cache.
//   - A fill that raced with an eviction is dropped rather than stored, so a
//     slow read can never put back what a write just removed.
//   - The TTL only bounds how long a change made by another process (a second
//     server on the same database) can take to be seen. Keep it to seconds.
//
// The caches hold no secrets beyond what the stores already return (sessions
// are keyed by the token's hash, users carry their password hash), and are
// bounded in size.

// DefaultCacheTTL bounds staleness against writes from other processes.
const DefaultCacheTTL = 2 * time.Second

// defaultCacheMax bounds each cache's entries; it is cleared when full.
const defaultCacheMax = 100_000

type cacheEntry[V any] struct {
	v       V
	expires time.Time
}

// ttlCache is a small bounded TTL map with eviction-safe fills.
type ttlCache[V any] struct {
	mu  sync.Mutex
	m   map[string]cacheEntry[V]
	gen uint64 // bumps on every eviction; a fill begun before one is dropped
	ttl time.Duration
	max int
	now func() time.Time
}

func newTTLCache[V any](ttl time.Duration) *ttlCache[V] {
	return &ttlCache[V]{m: make(map[string]cacheEntry[V]), ttl: ttl, max: defaultCacheMax, now: time.Now}
}

// get returns a live entry, and the generation to pass to put on a miss.
func (c *ttlCache[V]) get(k string) (V, bool, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if ok && c.now().Before(e.expires) {
		return e.v, true, c.gen
	}
	if ok {
		delete(c.m, k)
	}
	var zero V
	return zero, false, c.gen
}

// put stores v unless an eviction happened since gen was read.
func (c *ttlCache[V]) put(k string, v V, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if len(c.m) >= c.max {
		clear(c.m)
	}
	c.m[k] = cacheEntry[V]{v: v, expires: c.now().Add(c.ttl)}
}

// evict removes the given keys.
func (c *ttlCache[V]) evict(keys ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	for _, k := range keys {
		delete(c.m, k)
	}
}

// evictWhere removes every entry whose value matches.
func (c *ttlCache[V]) evictWhere(match func(V) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	for k, e := range c.m {
		if match(e.v) {
			delete(c.m, k)
		}
	}
}

// sessionResult is a cached Load: a found session, or a remembered miss (so a
// flood of requests with an unknown token does not each reach the database).
type sessionResult struct {
	s  Session
	ok bool
}

// CachingSessionStore is a SessionStore with a short-lived read cache.
type CachingSessionStore struct {
	inner SessionStore
	c     *ttlCache[sessionResult]
}

// CachedSessions wraps a SessionStore with a read cache of the given TTL
// (DefaultCacheTTL when ttl <= 0).
func CachedSessions(inner SessionStore, ttl time.Duration) *CachingSessionStore {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &CachingSessionStore{inner: inner, c: newTTLCache[sessionResult](ttl)}
}

// Save implements SessionStore.
func (s *CachingSessionStore) Save(tokenHash string, sess Session) error {
	s.c.evict(tokenHash) // drop a remembered miss for this token
	return s.inner.Save(tokenHash, sess)
}

// Load implements SessionStore.
func (s *CachingSessionStore) Load(tokenHash string) (Session, bool, error) {
	r, hit, gen := s.c.get(tokenHash)
	if hit {
		return r.s, r.ok, nil
	}
	sess, ok, err := s.inner.Load(tokenHash)
	if err != nil {
		return Session{}, false, err
	}
	s.c.put(tokenHash, sessionResult{s: sess, ok: ok}, gen)
	return sess, ok, nil
}

// Delete implements SessionStore.
func (s *CachingSessionStore) Delete(tokenHash string) error {
	err := s.inner.Delete(tokenHash)
	s.c.evict(tokenHash)
	return err
}

// DeleteForUser removes every session of a user and evicts them from the cache.
// It delegates to the wrapped store when that store supports it.
func (s *CachingSessionStore) DeleteForUser(userID string) error {
	var err error
	if d, ok := s.inner.(interface{ DeleteForUser(string) error }); ok {
		err = d.DeleteForUser(userID)
	}
	s.c.evictWhere(func(r sessionResult) bool { return r.ok && r.s.UserID == userID })
	return err
}

// Unwrap returns the wrapped store.
func (s *CachingSessionStore) Unwrap() SessionStore { return s.inner }

// userResult is a cached GetUserByID.
type userResult struct {
	u  User
	ok bool
}

// CachingUserStore is a UserStore whose by-id reads are cached; every other
// call goes straight through.
type CachingUserStore struct {
	UserStore
	c *ttlCache[userResult]
}

// CachedUsers wraps a UserStore with a read cache of the given TTL
// (DefaultCacheTTL when ttl <= 0) on GetUserByID, the per-request lookup.
func CachedUsers(inner UserStore, ttl time.Duration) *CachingUserStore {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &CachingUserStore{UserStore: inner, c: newTTLCache[userResult](ttl)}
}

// GetUserByID implements UserStore.
func (s *CachingUserStore) GetUserByID(id string) (User, bool, error) {
	r, hit, gen := s.c.get(id)
	if hit {
		return r.u, r.ok, nil
	}
	u, ok, err := s.UserStore.GetUserByID(id)
	if err != nil {
		return User{}, false, err
	}
	s.c.put(id, userResult{u: u, ok: ok}, gen)
	return u, ok, nil
}

// CreateUser implements UserStore (evicting a remembered miss for the id).
func (s *CachingUserStore) CreateUser(u User) error {
	s.c.evict(u.ID)
	return s.UserStore.CreateUser(u)
}

// UpdateUser implements UserStore.
func (s *CachingUserStore) UpdateUser(u User) error {
	err := s.UserStore.UpdateUser(u)
	s.c.evict(u.ID)
	return err
}

// Invalidate drops a user's cached record (for a change made outside this
// store, such as a direct database edit or another code path).
func (s *CachingUserStore) Invalidate(userID string) { s.c.evict(userID) }
