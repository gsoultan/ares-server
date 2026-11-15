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

func TestAgentServiceEnrollHeartbeatDeregister(t *testing.T) {
	h := newTestHandler(t)
	reg := agent.NewRegistry(h.engagementGate())
	h.WithAgents(reg)
	engID := authorizedEngagement(t, h)
	ctx := context.Background()

	// Operator mints a key.
	mint, err := h.MintAgentKey(ctx, connect.NewRequest(&aresv1.MintAgentKeyRequest{
		EngagementId: engID,
		Capabilities: []string{"discovery"},
		Consent:      &aresv1.Consent{Who: "owner", How: "letter", RecordedBy: "op"},
	}))
	if err != nil {
		t.Fatalf("MintAgentKey: %v", err)
	}

	svc := NewAgentServer(reg, h.store)

	// Agent enrolls with the install key (public call).
	enr, err := svc.Enroll(ctx, connect.NewRequest(&aresv1.EnrollRequest{
		EnrollmentToken: mint.Msg.GetInstallKey(),
		PublicKey:       []byte("pk"),
		Host:            &aresv1.HostFacts{Hostname: "h1", Os: "linux", Ip: "10.0.0.5"},
	}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !enr.Msg.GetOk() || enr.Msg.GetCredential() == "" || enr.Msg.GetAgentId() == "" {
		t.Fatalf("enroll response incomplete: %+v", enr.Msg)
	}

	// Authenticate the credential as the interceptor would, then heartbeat.
	bound, err := reg.Authenticate(enr.Msg.GetCredential())
	if err != nil {
		t.Fatalf("authenticate credential: %v", err)
	}
	actx := context.WithValue(ctx, agentCtxKey{}, bound)

	hb, err := svc.Heartbeat(actx, connect.NewRequest(&aresv1.HeartbeatRequest{AgentVersion: "0.0.1"}))
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if hb.Msg.GetDirective() != aresv1.AgentDirective_AGENT_DIRECTIVE_CONTINUE {
		t.Fatalf("want continue, got %v", hb.Msg.GetDirective())
	}

	// Deregister revokes it; the credential then dies.
	if _, err := svc.Deregister(actx, connect.NewRequest(&aresv1.DeregisterRequest{Reason: "uninstall"})); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if _, err := reg.Authenticate(enr.Msg.GetCredential()); err == nil {
		t.Fatal("credential must not authenticate after deregister")
	}
}

func TestAgentServiceCallsRequireCredential(t *testing.T) {
	h := newTestHandler(t)
	svc := NewAgentServer(agent.NewRegistry(nil), h.store)
	// No agent in context → unauthenticated.
	if _, err := svc.Heartbeat(context.Background(), connect.NewRequest(&aresv1.HeartbeatRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("heartbeat without credential: want Unauthenticated, got %v", err)
	}
}

func TestAgentCredentialInterceptorParsesHeader(t *testing.T) {
	h := newTestHandler(t)
	reg := agent.NewRegistry(h.engagementGate())
	h.WithAgents(reg)
	engID := authorizedEngagement(t, h)
	_, raw, err := reg.MintEnrollToken("", engID, []string{"discovery"},
		agent.Consent{Who: "o", How: "letter", RecordedBy: "op"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	a, cred, err := reg.Enroll(raw, nil, agent.HostFacts{})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	i := NewAgentCredentialInterceptor(reg)

	// "Bearer <cred>" and a bare credential both authenticate to the same agent.
	for _, header := range []string{"Bearer " + cred, cred} {
		got, err := i.authenticate(header)
		if err != nil || got.ID != a.ID {
			t.Fatalf("authenticate(%q): agent=%v err=%v", header, got, err)
		}
	}
	// Empty and bogus are rejected.
	if _, err := i.authenticate(""); err == nil {
		t.Fatal("empty header must be rejected")
	}
	if _, err := i.authenticate("Bearer nope"); err == nil {
		t.Fatal("bogus credential must be rejected")
	}
}
