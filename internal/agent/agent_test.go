// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package agent

import (
	"testing"
	"time"
)

func openGate(string, string) bool { return true }

func mintAndEnroll(t *testing.T, r *Registry, tenant, eng string, caps []string) (*Agent, string) {
	t.Helper()
	tok, err := r.MintEnrollToken(tenant, eng, caps)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	a, cred, err := r.Enroll(tok, []byte("pubkey"), HostFacts{Hostname: "h", OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return a, cred
}

func TestEnrollBindsTenantEngagementAndCapabilities(t *testing.T) {
	r := NewRegistry(openGate)
	a, cred := mintAndEnroll(t, r, "t1", "e1", []string{"recon", "passivesniff"})
	if a.TenantID != "t1" || a.EngagementID != "e1" {
		t.Fatalf("agent not bound: %+v", a)
	}
	if a.State != StateActive {
		t.Fatalf("want active, got %s", a.State)
	}
	got, err := r.Authenticate(cred)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != a.ID || got.TenantID != "t1" || got.EngagementID != "e1" {
		t.Fatalf("authenticate returned wrong binding: %+v", got)
	}
	if err := r.AuthorizeCapability(a.ID, "recon"); err != nil {
		t.Fatalf("recon should be allowed: %v", err)
	}
	if err := r.AuthorizeCapability(a.ID, "mitmexposure"); err != ErrCapabilityGate {
		t.Fatalf("off-list capability must be refused, got %v", err)
	}
}

func TestEnrollTokenIsSingleUse(t *testing.T) {
	r := NewRegistry(openGate)
	tok, err := r.MintEnrollToken("t1", "e1", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, _, err := r.Enroll(tok, nil, HostFacts{}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if _, _, err := r.Enroll(tok, nil, HostFacts{}); err != ErrInvalidToken {
		t.Fatalf("second enroll must fail, got %v", err)
	}
}

func TestEnrollTokenExpires(t *testing.T) {
	r := NewRegistry(openGate)
	base := time.Now()
	r.now = func() time.Time { return base }
	tok, err := r.MintEnrollToken("t1", "e1", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r.now = func() time.Time { return base.Add(DefaultEnrollTokenTTL + time.Second) }
	if _, _, err := r.Enroll(tok, nil, HostFacts{}); err != ErrInvalidToken {
		t.Fatalf("expired token must fail, got %v", err)
	}
}

func TestRevokeStopsCredential(t *testing.T) {
	r := NewRegistry(openGate)
	a, cred := mintAndEnroll(t, r, "t1", "e1", []string{"recon"})
	if err := r.Revoke(a.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := r.Authenticate(cred); err != ErrUnknownAgent {
		t.Fatalf("revoked credential must not authenticate, got %v", err)
	}
	keep, err := r.Heartbeat(a.ID)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if keep {
		t.Fatal("revoked agent must be told to stop")
	}
}

func TestClosedEngagementRefusesAgent(t *testing.T) {
	open := true
	gate := func(string, string) bool { return open }
	r := NewRegistry(gate)
	a, cred := mintAndEnroll(t, r, "t1", "e1", []string{"recon"})
	// Halt the engagement.
	open = false
	if _, err := r.Authenticate(cred); err != ErrNotAuthorized {
		t.Fatalf("closed engagement must refuse auth, got %v", err)
	}
	keep, err := r.Heartbeat(a.ID)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if keep {
		t.Fatal("agent of a closed engagement must be told to stop")
	}
	// Minting a token for a closed engagement is refused too.
	if _, err := r.MintEnrollToken("t1", "e1", nil); err != ErrNotAuthorized {
		t.Fatalf("mint for closed engagement must fail, got %v", err)
	}
}

func TestStaleFlagging(t *testing.T) {
	r := NewRegistry(openGate)
	base := time.Now()
	r.now = func() time.Time { return base }
	a, _ := mintAndEnroll(t, r, "t1", "e1", nil)
	got, _ := r.Get(a.ID)
	if got.Stale(base) {
		t.Fatal("fresh agent must not be stale")
	}
	if !got.Stale(base.Add(StaleAfter + time.Second)) {
		t.Fatal("agent past the heartbeat window must be stale")
	}
}

func TestUnknownCredentialRejected(t *testing.T) {
	r := NewRegistry(openGate)
	if _, err := r.Authenticate("not-a-real-credential"); err != ErrUnknownAgent {
		t.Fatalf("want ErrUnknownAgent, got %v", err)
	}
}
