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
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares/canary"
)

func TestDispatchEgressCheckMintsTokens(t *testing.T) {
	h, ar, _ := dispatchHandler(t)
	store := canary.NewStore()
	h.WithEgressCanary(store, "https://canary.example.test/", "oob.example.test.", "", "")
	engID := authorizedEngagement(t, h)
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapEgressCheck})

	if _, err := h.DispatchAgentJob(context.Background(), connect.NewRequest(&aresv1.DispatchAgentJobRequest{
		EngagementId: engID, AgentId: a.ID, Module: "egresscheck",
	})); err != nil {
		t.Fatalf("DispatchAgentJob: %v", err)
	}
	tasks := ar.DrainTasks(a.ID)
	if len(tasks) != 1 || tasks[0].Module != "egresscheck" {
		t.Fatalf("expected one egresscheck task, got %+v", tasks)
	}
	var p agentTaskParams
	if err := json.Unmarshal(tasks[0].Params, &p); err != nil {
		t.Fatalf("params: %v", err)
	}
	// DNS, DoH and direct HTTPS; no alt-port or high-port listener configured.
	if len(p.Egress) != 3 {
		t.Fatalf("want 3 channels, got %+v", p.Egress)
	}
	for _, tok := range p.Egress {
		switch tok.Channel {
		case "dns-direct", "doh":
			if tok.Name != tok.Token+".oob.example.test" {
				t.Errorf("%s name = %q", tok.Channel, tok.Name)
			}
		case "https-direct":
			if tok.URL != "https://canary.example.test/c/"+tok.Token {
				t.Errorf("https url = %q", tok.URL)
			}
		default:
			t.Errorf("unexpected channel %q", tok.Channel)
		}
		if tok.Token == "" {
			t.Errorf("empty token for %s", tok.Channel)
		}
	}
}

func TestDispatchEgressCheckRefusedWithoutCanary(t *testing.T) {
	h, ar, _ := dispatchHandler(t)
	engID := authorizedEngagement(t, h)
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapEgressCheck})
	_, err := h.DispatchAgentJob(context.Background(), connect.NewRequest(&aresv1.DispatchAgentJobRequest{
		EngagementId: engID, AgentId: a.ID, Module: "egresscheck",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no canary: want FailedPrecondition, got %v", err)
	}
}

func TestDispatchPersistCollectIsAgentNative(t *testing.T) {
	h, ar, _ := dispatchHandler(t)
	engID := authorizedEngagement(t, h)
	a := enrolledAgent(t, h, ar, engID, []string{agent.CapHostPosture})
	if _, err := h.DispatchAgentJob(context.Background(), connect.NewRequest(&aresv1.DispatchAgentJobRequest{
		EngagementId: engID, AgentId: a.ID, Module: "persistcollect",
	})); err != nil {
		t.Fatalf("persistcollect is agent-native and allowed: %v", err)
	}
}
