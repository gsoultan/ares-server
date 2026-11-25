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

// draftReply is a valid module spec, as the model would return it.
func draftReply(t *testing.T) string {
	t.Helper()
	return `{"v":1,"name":"acmedraft","title":"Acme status page is public","summary":"confirms the Acme status page is served to anyone by reading its heading once.","severity":"medium","issueKey":"acme-status-exposed","technique":"T1592","surface":"web","cost":{"requests":1,"seconds":2},"probe":{"method":"GET","path":"/acme-status","status":200,"bodyRegex":"<h1>Acme Server Status"},"example":{"status":200,"body":"<h1>Acme Server Status for x</h1>"},"guidance":{"plainSummary":"A page on your server shows who is visiting. Ask your host to make it private.","summary":"Restrict /acme-status to an admin network.","fix":["Allow only 127.0.0.1 to the status page."],"verify":["Request /acme-status from outside and confirm 403."]}}`
}

func TestAdviseDraftModule(t *testing.T) {
	h := newTestHandler(t)
	fp := &fakeProvider{reply: draftReply(t)}
	h.WithAdvisor(ai.NewAdvisor(fp, 0))
	id := adviseEngagement(t, h)
	ctx := context.Background()

	// A brief is required, and checked before anything is sent.
	_, err := h.Advise(ctx, connect.NewRequest(&aresv1.AdviseRequest{EngagementId: id, Feature: ai.FeatureDraftModule, OptIn: true}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no brief: err = %v, want invalid_argument", err)
	}
	// Without the opt-in nothing is sent.
	resp, err := h.Advise(ctx, connect.NewRequest(&aresv1.AdviseRequest{EngagementId: id, Feature: ai.FeatureDraftModule, Brief: "CVE-2026-1111 Acme status page"}))
	if err != nil || !resp.Msg.GetOptInRequired() || fp.calls != 0 {
		t.Fatalf("no opt-in: resp=%+v err=%v calls=%d", resp.Msg, err, fp.calls)
	}

	resp, err = h.Advise(ctx, connect.NewRequest(&aresv1.AdviseRequest{
		EngagementId: id, Feature: ai.FeatureDraftModule, OptIn: true, Brief: "CVE-2026-1111 Acme status page is public",
	}))
	if err != nil {
		t.Fatal(err)
	}
	d := resp.Msg.GetModuleDraft()
	if d == nil || d.GetName() != "acmedraft" || len(d.GetFiles()) == 0 || len(d.GetProblems()) != 0 {
		t.Fatalf("draft = %+v", d)
	}
	if len(d.GetReviewNotes()) == 0 || resp.Msg.GetText() == "" {
		t.Error("the draft must carry review notes and a text rendering")
	}
	// The prompt is grounded in the brief, the engagement and the registry.
	prompt := fp.last.Messages[0].Content
	for _, want := range []string{"CVE-2026-1111", "redirectprobe", "T1204.001"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt is not grounded on %q", want)
		}
	}
	// Drafting writes nothing and registers nothing.
	if _, ok := h.reg.Get("acmedraft"); ok {
		t.Fatal("a draft was registered")
	}
}
