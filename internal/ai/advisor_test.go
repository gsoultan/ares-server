// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// mockProvider records the last request and returns a canned response.
type mockProvider struct {
	last  Request
	reply string
}

func (m *mockProvider) Name() string  { return "mock" }
func (m *mockProvider) Model() string { return "mock-1" }
func (m *mockProvider) Complete(_ context.Context, req Request) (Response, error) {
	m.last = req
	return Response{Text: m.reply, Model: "mock-1", Usage: Usage{InputTokens: 1, OutputTokens: 1}}, nil
}

func TestAdvisorGuardrailSystemPrompt(t *testing.T) {
	// The guardrail must assert advisory-only and the scope/authorization boundary.
	for _, want := range []string{"advisory only", "scope", "authoriz", "do not invent", "exploit"} {
		if !strings.Contains(strings.ToLower(advisorSystem), strings.ToLower(want)) {
			t.Errorf("advisor system prompt is missing the guardrail phrase %q", want)
		}
	}
}

func TestExplainFindingGroundsOnData(t *testing.T) {
	mp := &mockProvider{reply: "explanation"}
	a := NewAdvisor(mp, 256)
	f := FindingInput{Title: "Open redirect confirmed", Severity: "medium", Technique: "T1204.001", IssueKey: "open-redirect"}
	resp, err := a.ExplainFinding(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "explanation" {
		t.Errorf("text = %q", resp.Text)
	}
	if mp.last.System != advisorSystem {
		t.Error("ExplainFinding must send the guardrail system prompt")
	}
	// The finding data must be grounded into the prompt.
	for _, want := range []string{"Open redirect confirmed", "T1204.001", "open-redirect"} {
		if !strings.Contains(mp.last.Messages[0].Content, want) {
			t.Errorf("prompt is not grounded on %q", want)
		}
	}
}

func TestAdviseDispatchesByFeature(t *testing.T) {
	mp := &mockProvider{reply: "ok"}
	a := NewAdvisor(mp, 128)

	cases := map[string]any{
		FeatureExplainFinding: FindingInput{Title: "SSTI confirmed"},
		FeatureSuggestChecks:  ProfileInput{Target: "https://x", Summary: "nginx + php"},
		FeatureNarratePaths:   RiskInput{Target: "https://x", Score: 80, Rating: "high"},
		FeatureDraftReport:    ReportInput{Engagement: "acme", Rating: "high"},
	}
	for feature, in := range cases {
		payload, _ := json.Marshal(in)
		resp, err := a.Advise(context.Background(), feature, payload)
		if err != nil {
			t.Fatalf("Advise(%s): %v", feature, err)
		}
		if resp.Text != "ok" {
			t.Errorf("Advise(%s) text = %q", feature, resp.Text)
		}
	}

	if _, err := a.Advise(context.Background(), "nonsense", nil); err == nil {
		t.Error("unknown feature must error")
	}
}

func TestSuggestChecksRemindsAboutScope(t *testing.T) {
	mp := &mockProvider{reply: "ok"}
	a := NewAdvisor(mp, 128)
	_, err := a.SuggestNextChecks(context.Background(), ProfileInput{Target: "https://x", Signals: []string{"WordPress"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(mp.last.Messages[0].Content), "scope") {
		t.Error("suggest-checks prompt must instruct the model to remind about scope + authorization")
	}
}

func TestFeaturesAndNotice(t *testing.T) {
	if len(Features()) != 5 {
		t.Errorf("want 5 features, got %v", Features())
	}
	for _, want := range []string{"never runs a test", "scope", "authoriz"} {
		if !strings.Contains(strings.ToLower(Notice), strings.ToLower(want)) {
			t.Errorf("Notice is missing %q", want)
		}
	}
}
