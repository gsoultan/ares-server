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
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
)

// authorizedEngagement creates, scopes and authorizes an engagement so it can run.
func authorizedEngagement(t *testing.T, h *Handler) string {
	t.Helper()
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Agents"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	if _, err := h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{Id: id, InScope: []string{"127.0.0.1"}})); err != nil {
		t.Fatalf("SetScope: %v", err)
	}
	if _, err := h.Authorize(ctx, connect.NewRequest(&aresv1.AuthorizeRequest{Id: id, Document: "auth.pdf", ApprovedBy: "lead"})); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return id
}

func TestAgentKeyAndManagementFlow(t *testing.T) {
	h := newTestHandler(t)
	h.WithAgents(agent.NewRegistry(h.engagementGate()))
	ctx := context.Background()
	engID := authorizedEngagement(t, h)

	// Minting without a permission record is refused.
	_, err := h.MintAgentKey(ctx, connect.NewRequest(&aresv1.MintAgentKeyRequest{
		EngagementId: engID, Capabilities: []string{"recon"},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("mint without consent: want InvalidArgument, got %v", err)
	}

	// Mint with a permission record.
	mint, err := h.MintAgentKey(ctx, connect.NewRequest(&aresv1.MintAgentKeyRequest{
		EngagementId: engID,
		Capabilities: []string{"recon", "passivesniff"},
		Consent: &aresv1.Consent{
			Who: "Owner, Acme IT", How: "signed authorization letter", RecordedBy: "op@acme",
		},
	}))
	if err != nil {
		t.Fatalf("MintAgentKey: %v", err)
	}
	if mint.Msg.GetKeyId() == "" || mint.Msg.GetInstallKey() == "" {
		t.Fatalf("mint returned empty key: %+v", mint.Msg)
	}

	// The key shows in the unused-keys list.
	keys, err := h.ListAgentKeys(ctx, connect.NewRequest(&aresv1.ListAgentKeysRequest{EngagementId: engID}))
	if err != nil {
		t.Fatalf("ListAgentKeys: %v", err)
	}
	if len(keys.Msg.GetKeys()) != 1 || keys.Msg.GetKeys()[0].GetKeyId() != mint.Msg.GetKeyId() {
		t.Fatalf("want the minted key listed, got %+v", keys.Msg.GetKeys())
	}

	// Enroll an agent with that key (agent-side registry call), then it lists.
	a, _, err := h.agents.Enroll(mint.Msg.GetInstallKey(), []byte("pk"), agent.HostFacts{Hostname: "h1", OS: "linux", IP: "10.1.2.3"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// The spent key no longer lists.
	keys, _ = h.ListAgentKeys(ctx, connect.NewRequest(&aresv1.ListAgentKeysRequest{EngagementId: engID}))
	if len(keys.Msg.GetKeys()) != 0 {
		t.Fatalf("spent key must not list, got %+v", keys.Msg.GetKeys())
	}

	// ListAgents shows the enrolled agent with its consent and status.
	agents, err := h.ListAgents(ctx, connect.NewRequest(&aresv1.ListAgentsRequest{EngagementId: engID}))
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents.Msg.GetAgents()) != 1 {
		t.Fatalf("want one agent, got %d", len(agents.Msg.GetAgents()))
	}
	av := agents.Msg.GetAgents()[0]
	if av.GetId() != a.ID || av.GetConsent().GetRecordedBy() != "op@acme" || av.GetHost().GetIp() != "10.1.2.3" {
		t.Fatalf("unexpected agent view: %+v", av)
	}
	if av.GetStatus() != aresv1.AgentStatus_AGENT_STATUS_CONNECTED {
		t.Fatalf("fresh agent should be connected, got %v", av.GetStatus())
	}

	// Remove it; it should then report removed and the credential should die.
	if _, err := h.RemoveAgent(ctx, connect.NewRequest(&aresv1.RemoveAgentRequest{EngagementId: engID, AgentId: a.ID})); err != nil {
		t.Fatalf("RemoveAgent: %v", err)
	}
	got, _ := h.GetAgent(ctx, connect.NewRequest(&aresv1.GetAgentRequest{EngagementId: engID, AgentId: a.ID}))
	if got.Msg.GetStatus() != aresv1.AgentStatus_AGENT_STATUS_REMOVED {
		t.Fatalf("removed agent should report removed, got %v", got.Msg.GetStatus())
	}
}

func TestAgentRPCsDisabledWithoutRegistry(t *testing.T) {
	h := newTestHandler(t) // no WithAgents
	_, err := h.ListAgents(context.Background(), connect.NewRequest(&aresv1.ListAgentsRequest{EngagementId: "x"}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("want Unavailable without a registry, got %v", err)
	}
}
