// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"sync/atomic"
	"testing"
	"time"
)

// countingSessions counts Loads that reach the underlying store.
type countingSessions struct {
	SessionStore
	loads atomic.Int64
}

func (c *countingSessions) Load(h string) (Session, bool, error) {
	c.loads.Add(1)
	return c.SessionStore.Load(h)
}

type countingUsers struct {
	UserStore
	gets atomic.Int64
}

func (c *countingUsers) GetUserByID(id string) (User, bool, error) {
	c.gets.Add(1)
	return c.UserStore.GetUserByID(id)
}

func newCachedService(t *testing.T) (*Service, *countingSessions, *countingUsers, Session, User) {
	t.Helper()
	cs := &countingSessions{SessionStore: NewMemSessionStore()}
	cu := &countingUsers{UserStore: NewMemUserStore()}
	svc := NewService(CachedUsers(cu, time.Minute), CachedSessions(cs, time.Minute))
	u, err := svc.CreateUser("", "op@example.test", "Op", "correct horse battery staple", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := svc.Login("op@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return svc, cs, cu, sess, u
}

func TestCachedAuthenticateHitsStoreOnce(t *testing.T) {
	svc, cs, _, sess, _ := newCachedService(t)
	for i := 0; i < 100; i++ {
		if _, err := svc.Authenticate(sess.Token); err != nil {
			t.Fatal(err)
		}
	}
	if n := cs.loads.Load(); n != 1 {
		t.Errorf("100 authentications loaded the session %d times, want 1", n)
	}
	// Unknown tokens are remembered too, so a flood of bad tokens stays off the store.
	for i := 0; i < 10; i++ {
		_, _ = svc.Authenticate("not-a-token")
	}
	if n := cs.loads.Load(); n != 2 {
		t.Errorf("repeated unknown token loaded %d times in total, want 2", n)
	}
}

func TestCachedLogoutTakesEffectImmediately(t *testing.T) {
	svc, _, _, sess, _ := newCachedService(t)
	if _, err := svc.Authenticate(sess.Token); err != nil {
		t.Fatal(err)
	}
	if err := svc.Logout(sess.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(sess.Token); err != ErrNotAuthenticated {
		t.Fatalf("after logout: want ErrNotAuthenticated, got %v", err)
	}
}

func TestCachedUserChangesTakeEffectImmediately(t *testing.T) {
	svc, _, cu, _, u := newCachedService(t)
	if _, ok, _ := svc.GetUser(u.ID); !ok {
		t.Fatal("user not found")
	}
	if _, err := svc.SetDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _, _ := svc.GetUser(u.ID)
	if !got.Disabled {
		t.Fatal("a disable must be visible on the next read, not after the TTL")
	}
	if _, err := svc.SetRole(u.ID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := svc.GetUser(u.ID); got.Role != RoleMember {
		t.Fatalf("role after change = %s, want member", got.Role)
	}
	before := cu.gets.Load()
	for i := 0; i < 10; i++ {
		_, _, _ = svc.GetUser(u.ID)
	}
	if cu.gets.Load() != before {
		t.Error("repeated reads must be served from the cache")
	}
}

func TestCachedSessionDeleteForUserEvicts(t *testing.T) {
	cs := CachedSessions(NewMemSessionStore(), time.Minute)
	_ = cs.Save("h1", Session{UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = cs.Save("h2", Session{UserID: "u2", ExpiresAt: time.Now().Add(time.Hour)})
	_, _, _ = cs.Load("h1")
	_, _, _ = cs.Load("h2")
	if err := cs.DeleteForUser("u1"); err != nil {
		t.Fatal(err)
	}
	// With a store that supports it the row is gone; with one that does not,
	// at least the cache must not keep serving it.
	if _, ok := cs.c.m["h1"]; ok {
		t.Error("u1's cached session must be evicted")
	}
	if _, ok := cs.c.m["h2"]; !ok {
		t.Error("u2's cached session must stay")
	}
}

func TestTTLCacheDropsFillThatRacedAnEviction(t *testing.T) {
	c := newTTLCache[int](time.Minute)
	_, _, gen := c.get("k") // a miss: a load starts
	c.evict("k")            // a write lands meanwhile
	c.put("k", 1, gen)      // the stale load finishes
	if _, hit, _ := c.get("k"); hit {
		t.Fatal("a fill that started before an eviction must not be stored")
	}
}

func TestTTLCacheExpires(t *testing.T) {
	c := newTTLCache[int](time.Second)
	now := time.Now()
	c.now = func() time.Time { return now }
	_, _, gen := c.get("k")
	c.put("k", 1, gen)
	if _, hit, _ := c.get("k"); !hit {
		t.Fatal("want a hit inside the TTL")
	}
	now = now.Add(2 * time.Second)
	if _, hit, _ := c.get("k"); hit {
		t.Fatal("want a miss after the TTL")
	}
}

func TestKDFConcurrency(t *testing.T) {
	for _, c := range []struct {
		env   string
		procs int
		want  int
	}{{"", 0, 1}, {"", 2, 2}, {"", 16, 16}, {"3", 16, 3}, {"x", 8, 8}, {"0", 8, 8}} {
		if got := kdfConcurrency(c.env, c.procs); got != c.want {
			t.Errorf("kdfConcurrency(%q, %d) = %d, want %d", c.env, c.procs, got, c.want)
		}
	}
}
