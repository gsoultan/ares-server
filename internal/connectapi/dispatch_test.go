// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

// reconStub is named like a real discovery module so it is on the capability map.
type reconStub struct{}

func (reconStub) Name() string { return "recon" }
func (reconStub) Run(_ context.Context, _ module.Scope, _ []module.Target, _ chan<- module.Result) error {
	return nil
}

func dispatchHandler(t *testing.T) (*Handler, *agent.Registry, worker.OutcomeStore) {
	t.Helper()
	reg := module.NewRegistry()
	_ = reg.Register(reconStub{})
	store := engagement.NewMemStore()
	q := queue.New(8)
	outcomes := worker.NewMemOutcomes()
	h := New(store, reg, q, outcomes)
	ar := agent.NewRegistry(h.engagementGate())
	h.WithAgents(ar)
	return h, ar, outcomes
}

func enrolledAgent(t *testing.T, h *Handler, ar *agent.Registry, engID string, caps []string) *agent.Agent {
	t.Helper()
	mint, err := h.MintAgentKey(context.Background(), connect.NewRequest(&aresv1.MintAgentKeyRequest{
		EngagementId: engID, Capabilities: caps,
		Consent: &aresv1.Consent{Who: "o", How: "letter", RecordedBy: "op"},
	}))
	if err != nil {
		t.Fatalf("MintAgentKey: %v", err)
	}
	a, _, err := ar.Enroll(mint.Msg.GetInstallKey(), nil, agent.HostFacts{Hostname: "h"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return a
}

func TestDispatchAgentJobAuthorizesAndQueues(t *testing.T) {
	h, ar, _ := dispatchHandler(t)
	engID := authorizedEngagement(t, h)
	ctx := context.Background()

	// Agent allowed "discovery" (which contains recon).
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapDiscovery})

	// Dispatch recon: authorized and queued.
	resp, err := h.DispatchAgentJob(ctx, connect.NewRequest(&aresv1.DispatchAgentJobRequest{
		EngagementId: engID, AgentId: a.ID, Module: "recon",
		Targets: []*aresv1.Target{{Host: "127.0.0.1"}},
	}))
	if err != nil {
		t.Fatalf("DispatchAgentJob: %v", err)
	}
	if resp.Msg.GetTaskId() == "" {
		t.Fatal("expected a task id")
	}
	// The task is queued for the agent, carrying the scope snapshot and targets.
	tasks := ar.DrainTasks(a.ID)
	if len(tasks) != 1 || tasks[0].Module != "recon" {
		t.Fatalf("expected one queued recon task, got %+v", tasks)
	}
	var snap map[string]any
	if err := json.Unmarshal(tasks[0].ScopeSnapshot, &snap); err != nil {
		t.Fatalf("scope snapshot not JSON: %v", err)
	}
	// Status reflects "running a check".
	got, _ := ar.Get(a.ID)
	if got.CurrentCapability != "recon" {
		t.Fatalf("expected running recon, got %q", got.CurrentCapability)
	}
}

func TestDispatchRefusedWhenCapabilityNotAllowed(t *testing.T) {
	h, ar, _ := dispatchHandler(t)
	engID := authorizedEngagement(t, h)
	// Agent allowed only webcheck, not discovery.
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapWebCheck})
	_, err := h.DispatchAgentJob(context.Background(), connect.NewRequest(&aresv1.DispatchAgentJobRequest{
		EngagementId: engID, AgentId: a.ID, Module: "recon",
		Targets: []*aresv1.Target{{Host: "127.0.0.1"}},
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("recon off the allow-list: want PermissionDenied, got %v", err)
	}
}

func TestDispatchRefusesUnknownModule(t *testing.T) {
	h, ar, _ := dispatchHandler(t)
	engID := authorizedEngagement(t, h)
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapDiscovery})
	_, err := h.DispatchAgentJob(context.Background(), connect.NewRequest(&aresv1.DispatchAgentJobRequest{
		EngagementId: engID, AgentId: a.ID, Module: "definitely-not-a-module",
		Targets: []*aresv1.Target{{Host: "127.0.0.1"}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown module: want InvalidArgument, got %v", err)
	}
}

func TestPushResultsRecordsOutcome(t *testing.T) {
	h, ar, outcomes := dispatchHandler(t)
	engID := authorizedEngagement(t, h)
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapDiscovery})
	svc := NewAgentServer(ar, h.store, outcomes)

	results := []module.Result{{Capability: "recon", Kind: "asset", Target: module.Target{Host: "10.0.0.1"}}}
	raw, _ := json.Marshal(results)
	actx := context.WithValue(context.Background(), agentCtxKey{}, a)
	if _, err := svc.PushResults(actx, connect.NewRequest(&aresv1.PushResultsRequest{
		TaskId: "task-1", Results: raw,
	})); err != nil {
		t.Fatalf("PushResults: %v", err)
	}
	got, ok := outcomes.Get("task-1")
	if !ok || got.Engagement != engID || len(got.Results) != 1 || got.Module != "recon" {
		t.Fatalf("outcome not recorded correctly: %+v (ok=%v)", got, ok)
	}
	// Current-capability cleared after results arrive.
	cur, _ := ar.Get(a.ID)
	if cur.CurrentCapability != "" {
		t.Fatalf("current capability should be cleared, got %q", cur.CurrentCapability)
	}
}
