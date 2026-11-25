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
	"errors"
	"strings"
	"testing"
)

// specReply is the scaffold example with a new name, as a model would return it.
func specReply(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(draftExample), &m); err != nil {
		t.Fatal(err)
	}
	m["name"] = "acmestatusdraft"
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestDraftSystemPromptGuardrails(t *testing.T) {
	for _, want := range []string{"advisory only", "never write code", "read-only", "exploit", "refusal", "scope and authorization", "ground every statement"} {
		if !strings.Contains(strings.ToLower(draftSystem), want) {
			t.Errorf("draft system prompt is missing %q", want)
		}
	}
}

func TestDraftExampleRenders(t *testing.T) {
	d := buildDraft(draftExample, ModuleDraftInput{Brief: "x"}, "mock mock-1")
	if !d.Rendered() {
		t.Fatalf("the embedded example spec does not render: %v", d.Problems)
	}
}

func TestDraftModuleRendersAValidSpec(t *testing.T) {
	mp := &mockProvider{reply: "```json\n" + specReply(t, func(m map[string]any) {
		m["origin"] = map[string]any{"source": "manual", "by": "a trusted human reviewer"}
	}) + "\n```"}
	a := NewAdvisor(mp, 256)
	d, resp, err := a.DraftModule(context.Background(), ModuleDraftInput{
		Brief: "CVE-2026-12345: the Acme server status page is public by default.", Target: "Acme demo",
		ExistingModules: []string{"corsprobe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Rendered() || len(d.Problems) > 0 {
		t.Fatalf("draft not rendered: %v", d.Problems)
	}
	if mp.last.System != draftSystem {
		t.Error("DraftModule must send the drafting guardrail")
	}
	if mp.last.MaxTokens < draftMaxTokens {
		t.Errorf("max tokens %d, want at least %d", mp.last.MaxTokens, draftMaxTokens)
	}
	for _, want := range []string{"CVE-2026-12345", "Acme demo", "corsprobe"} {
		if !strings.Contains(mp.last.Messages[0].Content, want) {
			t.Errorf("prompt is not grounded on %q", want)
		}
	}
	// Provenance is set by Ares, never by the model.
	if o := d.Spec.Origin; o.Source != "cve" || o.Ref != "CVE-2026-12345" || !strings.Contains(o.By, "AI advisor (mock mock-1)") {
		t.Errorf("origin = %+v", o)
	}
	if !strings.Contains(string(d.Files[0].Content), "AI advisor") {
		t.Error("the rendered module does not say it was AI-drafted")
	}
	if len(d.Notes) == 0 || !strings.Contains(d.Notes[0], "Nothing in it has run") {
		t.Errorf("review notes = %v", d.Notes)
	}
	if !strings.Contains(resp.Text, "acmestatusdraft") || !strings.Contains(resp.Text, "Before it merges") {
		t.Errorf("text = %q", resp.Text)
	}
}

func TestDraftModuleRefusesUnsafeSpecs(t *testing.T) {
	cases := map[string]struct {
		reply string
		want  string
	}{
		"write method": {specReply(t, func(m map[string]any) { m["probe"].(map[string]any)["method"] = "POST" }), "only GET or HEAD"},
		"off-target":   {specReply(t, func(m map[string]any) { m["probe"].(map[string]any)["path"] = "https://evil.example/" }), "absolute path"},
		"code field":   {specReply(t, func(m map[string]any) { m["code"] = "os.Exit(1)" }), "unknown field"},
		"name in use":  {specReply(t, func(m map[string]any) { m["name"] = "corsprobe" }), "already a registered module"},
		"no json":      {"I would rather explain this in prose.", "did not return a JSON spec"},
	}
	for name, c := range cases {
		d := buildDraft(c.reply, ModuleDraftInput{Brief: "b", ExistingModules: []string{"corsprobe"}}, "mock mock-1")
		if d.Rendered() {
			t.Errorf("%s: an unsafe spec was rendered", name)
		}
		if !strings.Contains(strings.Join(d.Problems, "\n"), c.want) {
			t.Errorf("%s: problems %v do not mention %q", name, d.Problems, c.want)
		}
		if !strings.Contains(d.Markdown(), "did not pass") {
			t.Errorf("%s: markdown does not say the draft was refused", name)
		}
	}
}

func TestDraftModuleRefusal(t *testing.T) {
	d := buildDraft(`{"refusal": "It can only be confirmed by exploiting the deserializer."}`, ModuleDraftInput{Brief: "b"}, "m")
	if d.Rendered() || !strings.Contains(d.Refusal, "deserializer") || !strings.Contains(d.Markdown(), "did not draft") {
		t.Fatalf("refusal not carried: %+v", d)
	}
}

func TestDraftModuleNeedsABrief(t *testing.T) {
	mp := &mockProvider{reply: "{}"}
	_, _, err := NewAdvisor(mp, 0).DraftModule(context.Background(), ModuleDraftInput{Brief: "  "})
	if !errors.Is(err, ErrEmptyBrief) {
		t.Fatalf("err = %v, want ErrEmptyBrief", err)
	}
	if mp.last.System != "" {
		t.Error("an empty brief must not reach the provider")
	}
}

func TestAdviseDispatchesDraftModule(t *testing.T) {
	mp := &mockProvider{reply: specReply(t, nil)}
	payload, _ := json.Marshal(ModuleDraftInput{Brief: "Acme status page"})
	resp, err := NewAdvisor(mp, 0).Advise(context.Background(), FeatureDraftModule, payload)
	if err != nil || !strings.Contains(resp.Text, "acmestatusdraft") {
		t.Fatalf("Advise(draft-module) = %q, %v", resp.Text, err)
	}
}
