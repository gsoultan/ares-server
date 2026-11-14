// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/ai"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakeProvider is a test ai.Provider that records the last request.
type fakeProvider struct {
	calls int
	last  ai.Request
	reply string
}

func (p *fakeProvider) Name() string  { return "fake" }
func (p *fakeProvider) Model() string { return "fake-1" }
func (p *fakeProvider) Complete(_ context.Context, req ai.Request) (ai.Response, error) {
	p.calls++
	p.last = req
	return ai.Response{Text: p.reply, Model: "fake-1", Usage: ai.Usage{InputTokens: 10, OutputTokens: 20}}, nil
}

func adviseEngagement(t *testing.T, h *Handler) string {
	t.Helper()
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Advice demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	data, _ := structpb.NewStruct(map[string]any{
		"title":    "Open redirect confirmed",
		"severity": "medium",
		"issueKey": "open-redirect",
	})
	h.outcomes.Save(worker.Outcome{
		JobID:      "job-1",
		Engagement: id,
		Module:     "redirectprobe",
		Results: []module.Result{{
			Capability: "redirectprobe",
			Kind:       "finding",
			Technique:  "T1204.001",
			Target:     module.Target{URL: "https://x/"},
			Data:       data.AsMap(),
		}},
	})
	return id
}

func TestAdviseDisabledWhenNoProvider(t *testing.T) {
	h := newTestHandler(t)
	id := adviseEngagement(t, h)
	resp, err := h.Advise(context.Background(), connect.NewRequest(&aresv1.AdviseRequest{
		EngagementId: id, Feature: ai.FeatureNarratePaths, OptIn: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetEnabled() {
		t.Error("with no provider configured, enabled must be false")
	}
	if resp.Msg.GetText() != "" {
		t.Error("no text should be produced when disabled")
	}
	if resp.Msg.GetNotice() == "" {
		t.Error("the data-sharing notice should still be returned")
	}
}

func TestAdviseOptInRequired(t *testing.T) {
	h := newTestHandler(t)
	fp := &fakeProvider{reply: "advice"}
	h.WithAdvisor(ai.NewAdvisor(fp, 0))
	id := adviseEngagement(t, h)

	resp, err := h.Advise(context.Background(), connect.NewRequest(&aresv1.AdviseRequest{
		EngagementId: id, Feature: ai.FeatureNarratePaths, OptIn: false,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.GetEnabled() {
		t.Error("enabled should be true when a provider is configured")
	}
	if !resp.Msg.GetOptInRequired() {
		t.Error("opt_in_required must be true without opt-in")
	}
	if fp.calls != 0 {
		t.Error("the provider must NOT be called without opt-in — no data may leave Ares")
	}
}

func TestAdviseExplainFindingGrounded(t *testing.T) {
	h := newTestHandler(t)
	fp := &fakeProvider{reply: "here is the explanation"}
	h.WithAdvisor(ai.NewAdvisor(fp, 0))
	id := adviseEngagement(t, h)

	// Find the finding id the UI would pass.
	list, err := h.ListFindings(context.Background(), connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetFindings()) == 0 {
		t.Fatal("expected a finding to explain")
	}
	fid := list.Msg.GetFindings()[0].GetId()

	resp, err := h.Advise(context.Background(), connect.NewRequest(&aresv1.AdviseRequest{
		EngagementId: id, Feature: ai.FeatureExplainFinding, FindingId: fid, OptIn: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetText() != "here is the explanation" {
		t.Errorf("text = %q", resp.Msg.GetText())
	}
	if resp.Msg.GetInputTokens() != 10 || resp.Msg.GetOutputTokens() != 20 {
		t.Errorf("usage not surfaced: in=%d out=%d", resp.Msg.GetInputTokens(), resp.Msg.GetOutputTokens())
	}
	if fp.calls != 1 {
		t.Fatalf("provider should be called once, got %d", fp.calls)
	}
	// Grounded prompt + guardrail.
	if !strings.Contains(fp.last.Messages[0].Content, "Open redirect confirmed") {
		t.Error("explain-finding prompt must be grounded in the finding data")
	}
	if !strings.Contains(strings.ToLower(fp.last.System), "advisory only") {
		t.Error("the guardrail system prompt must be sent")
	}
}

func TestAdviseExplainFindingMissingID(t *testing.T) {
	h := newTestHandler(t)
	h.WithAdvisor(ai.NewAdvisor(&fakeProvider{reply: "x"}, 0))
	id := adviseEngagement(t, h)
	_, err := h.Advise(context.Background(), connect.NewRequest(&aresv1.AdviseRequest{
		EngagementId: id, Feature: ai.FeatureExplainFinding, OptIn: true,
	}))
	if err == nil {
		t.Error("explain-finding without a finding_id must be an invalid-argument error")
	}
}

func TestAdviseUnknownFeature(t *testing.T) {
	h := newTestHandler(t)
	h.WithAdvisor(ai.NewAdvisor(&fakeProvider{reply: "x"}, 0))
	id := adviseEngagement(t, h)
	_, err := h.Advise(context.Background(), connect.NewRequest(&aresv1.AdviseRequest{
		EngagementId: id, Feature: "nonsense", OptIn: true,
	}))
	if err == nil {
		t.Error("an unknown feature must error")
	}
}
