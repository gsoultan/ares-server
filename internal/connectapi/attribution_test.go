// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
)

// signedIn returns a context carrying a member session of the default
// workspace, as the auth interceptor builds it (email filled from the account).
func signedIn(email string) context.Context {
	return auth.WithSession(context.Background(), auth.Session{
		UserID: "u-" + email, TenantID: engagement.ResolveTenant(""), Role: auth.RoleMember, Email: email,
	})
}

// A signed-in operator cannot write audit entries in someone else's name: the
// actor the client claims is replaced by the session's account.
func TestAuditActorIsTheSignedInAccount(t *testing.T) {
	h := newTestHandler(t)
	engID := authorizedEngagement(t, h)
	ctx := signedIn("ana@example.com")

	if _, err := h.SetDetection(ctx, connect.NewRequest(&aresv1.SetDetectionRequest{
		Id: engID, Technique: "T1190", Outcome: "detected", Actor: "the-ciso",
	})); err != nil {
		t.Fatalf("SetDetection: %v", err)
	}
	if _, err := h.Halt(ctx, connect.NewRequest(&aresv1.HaltRequest{Id: engID, Actor: "the-ciso"})); err != nil {
		t.Fatalf("Halt: %v", err)
	}

	eng, _ := h.store.Get(engID)
	seen := map[string]string{}
	for _, e := range eng.Audit.Entries() {
		seen[e.Action] = e.Actor
	}
	for _, action := range []string{"detection-recorded", "engagement-halted"} {
		if got := seen[action]; got != "ana@example.com" {
			t.Errorf("%s actor = %q, want the signed-in account", action, got)
		}
	}
}

// Without a session (auth off, or before setup) the client's name still lands
// in the trail, so single-user installs keep their current behaviour.
func TestAuditActorWithoutSessionUsesClaim(t *testing.T) {
	h := newTestHandler(t)
	engID := authorizedEngagement(t, h)
	if _, err := h.Halt(context.Background(), connect.NewRequest(&aresv1.HaltRequest{Id: engID, Actor: "lead"})); err != nil {
		t.Fatalf("Halt: %v", err)
	}
	eng, _ := h.store.Get(engID)
	entries := eng.Audit.Entries()
	if last := entries[len(entries)-1]; last.Action != "engagement-halted" || last.Actor != "lead" {
		t.Fatalf("last entry = %+v, want engagement-halted by lead", last)
	}
}

// Attaching the permission records both the client's signatory (approved_by)
// and the signed-in account that entered it.
func TestAuthorizeRecordsWhoAttachedThePermission(t *testing.T) {
	h := newTestHandler(t)
	ctx := signedIn("ana@example.com")
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Attr"}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetId()
	if _, err := h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{Id: id, InScope: []string{"127.0.0.1"}})); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Authorize(ctx, connect.NewRequest(&aresv1.AuthorizeRequest{Id: id, Document: "sow.pdf", ApprovedBy: "Client CISO"})); err != nil {
		t.Fatal(err)
	}
	eng, _ := h.store.Get(id)
	got := map[string]string{}
	for _, e := range eng.Audit.Entries() {
		got[e.Action] = e.Actor
	}
	if got["authorization-approved"] != "Client CISO" {
		t.Errorf("approved by = %q, want the client signatory", got["authorization-approved"])
	}
	if got["authorization-recorded"] != "ana@example.com" {
		t.Errorf("recorded by = %q, want the signed-in account", got["authorization-recorded"])
	}
	if got["scope-updated"] != "ana@example.com" {
		t.Errorf("scope updated by = %q, want the signed-in account", got["scope-updated"])
	}
}

// An install key can be cancelled only through the engagement it was minted
// for. Naming another engagement's key id is answered as an unknown key, and
// the key stays usable.
func TestCancelAgentKeyIsScopedToItsEngagement(t *testing.T) {
	h := newTestHandler(t)
	ar := agent.NewRegistry(h.engagementGate())
	h.WithAgents(ar)
	ctx := context.Background()

	victim := authorizedEngagement(t, h)
	mint, err := h.MintAgentKey(ctx, connect.NewRequest(&aresv1.MintAgentKeyRequest{
		EngagementId: victim, Capabilities: []string{agent.CapDiscovery},
		Consent: &aresv1.Consent{Who: "o", How: "letter", RecordedBy: "op"},
	}))
	if err != nil {
		t.Fatalf("MintAgentKey: %v", err)
	}
	keyID := mint.Msg.GetKeyId()

	// Another workspace with its own engagement.
	other := h.store.CreateTenant("Other client")
	attackerEng, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{
		TenantId: other.ID, Name: "Mine",
	}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	_, err = h.CancelAgentKey(ctx, connect.NewRequest(&aresv1.CancelAgentKeyRequest{
		TenantId: other.ID, EngagementId: attackerEng.Msg.GetId(), KeyId: keyID,
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("cross-workspace cancel: want NotFound, got %v", err)
	}
	if keys := ar.ListEnrollTokens(engagement.ResolveTenant(""), victim); len(keys) != 1 {
		t.Fatalf("victim's key must stay usable, got %d keys", len(keys))
	}

	// Its own engagement can cancel it.
	if _, err := h.CancelAgentKey(ctx, connect.NewRequest(&aresv1.CancelAgentKeyRequest{
		EngagementId: victim, KeyId: keyID,
	})); err != nil {
		t.Fatalf("own cancel: %v", err)
	}
}
