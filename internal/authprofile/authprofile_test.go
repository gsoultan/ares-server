// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package authprofile

import (
	"context"
	"strings"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares/websession"
)

func newService(t *testing.T) *Service {
	t.Helper()
	key := make([]byte, secret.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return NewService(sealer, NewMemRepo())
}

// TestSetSealsAndMasks proves a stored credential is sealed (the ciphertext
// never contains the secret) and the view exposes only a masked hint.
func TestSetSealsAndMasks(t *testing.T) {
	svc := newService(t)
	v, err := svc.Set("", "eng1", Profile{
		Hosts:      []string{"app.example.com"},
		Credential: websession.Credential{Bearer: "super-secret-token-12345"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !v.Set || v.Mechanism != "bearer" {
		t.Fatalf("view = %+v, want set bearer", v)
	}
	if strings.Contains(v.Hint, "super-secret") {
		t.Fatalf("hint leaked the secret: %q", v.Hint)
	}

	// The stored ciphertext must not contain the plaintext.
	st, _, _ := svc.repo.Get(tenant.Resolve(""))
	sec := st.Profiles["eng1"]
	if strings.Contains(sec.Ciphertext, "super-secret") {
		t.Fatal("sealed ciphertext leaked the secret")
	}

	// Open round-trips the exact credential for internal use.
	p, ok, err := svc.open("", "eng1")
	if err != nil || !ok {
		t.Fatalf("open: ok=%v err=%v", ok, err)
	}
	if p.Credential.Bearer != "super-secret-token-12345" {
		t.Fatalf("opened bearer = %q", p.Credential.Bearer)
	}
}

// TestClearRemoves proves clearing deletes the stored profile.
func TestClearRemoves(t *testing.T) {
	svc := newService(t)
	if _, err := svc.Set("", "eng1", Profile{Credential: websession.Credential{Cookie: "sid=x"}}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := svc.Clear("", "eng1"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	v, _ := svc.ViewFor("", "eng1")
	if v.Set {
		t.Fatal("profile should be cleared")
	}
}

// TestEmptyCredentialClears proves setting an empty credential removes any
// existing one rather than storing a useless record.
func TestEmptyCredentialClears(t *testing.T) {
	svc := newService(t)
	if _, err := svc.Set("", "eng1", Profile{Credential: websession.Credential{Bearer: "t"}}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := svc.Set("", "eng1", Profile{}); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	if v, _ := svc.ViewFor("", "eng1"); v.Set {
		t.Fatal("empty credential should have cleared the profile")
	}
}

// TestProviderScopesToEngagement proves the provider authenticates only hosts
// the engagement scope admits, and refuses a login whose URL is out of scope.
func TestProviderScopesToEngagement(t *testing.T) {
	svc := newService(t)
	prov := NewProvider(svc)

	store := engagement.NewMemStore()
	eng, err := store.Create("", "test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = eng.Scope.AddInScope("app.example.com")

	// Bearer scoped to one in-scope host and one out-of-scope host: only the
	// in-scope host is authenticated.
	if _, err := svc.Set(eng.TenantID, eng.ID, Profile{
		Hosts:      []string{"app.example.com", "evil.example.org"},
		Credential: websession.Credential{Bearer: "tok"},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	sess, err := prov.SessionFor(context.Background(), eng)
	if err != nil {
		t.Fatalf("SessionFor: %v", err)
	}
	if sess == nil {
		t.Fatal("expected a session for an in-scope credential")
	}
	if !sess.Authenticates("https://app.example.com/x") {
		t.Error("in-scope host should be authenticated")
	}
	if sess.Authenticates("https://evil.example.org/x") {
		t.Error("out-of-scope host must not be authenticated")
	}
}

// TestProviderRefusesOutOfScopeLogin proves a form login whose URL is not in
// scope is refused, so the credential is never posted off-target.
func TestProviderRefusesOutOfScopeLogin(t *testing.T) {
	svc := newService(t)
	prov := NewProvider(svc)
	store := engagement.NewMemStore()
	eng, _ := store.Create("", "test")
	_ = eng.Scope.AddInScope("app.example.com")

	if _, err := svc.Set(eng.TenantID, eng.ID, Profile{
		Credential: websession.Credential{Form: &websession.LoginForm{
			URL:    "https://login.evil.example.org/in",
			Fields: map[string]string{"u": "a", "p": "b"},
		}},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := prov.SessionFor(context.Background(), eng); err == nil {
		t.Fatal("expected a refusal for an out-of-scope login URL")
	}
}

// TestProviderNoProfile proves an engagement with no credential yields no
// session and no error (probes run anonymously).
func TestProviderNoProfile(t *testing.T) {
	prov := NewProvider(newService(t))
	store := engagement.NewMemStore()
	eng, _ := store.Create("", "test")
	_ = eng.Scope.AddInScope("app.example.com")
	sess, err := prov.SessionFor(context.Background(), eng)
	if err != nil || sess != nil {
		t.Fatalf("want (nil,nil), got (%v,%v)", sess, err)
	}
}
