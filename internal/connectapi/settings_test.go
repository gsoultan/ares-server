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

	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/settings"
)

func withSettings(t *testing.T, h *Handler) *Handler {
	t.Helper()
	key, _ := secret.NewKey()
	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return h.WithSettings(settings.NewService(sealer, settings.NewMemRepo()))
}

func TestGetSettingsUnavailableWithoutStore(t *testing.T) {
	h := newTestHandler(t)
	_, err := h.GetSettings(context.Background(), connect.NewRequest(&aresv1.GetSettingsRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("want CodeUnavailable before setup, got %v", err)
	}
}

func TestUpdateSettingsSecretIsWriteOnly(t *testing.T) {
	h := withSettings(t, newTestHandler(t))
	resp, err := h.UpdateSettings(context.Background(), connect.NewRequest(&aresv1.UpdateSettingsRequest{
		AiPresent: true,
		Ai:        &aresv1.AISettings{Provider: "anthropic", Model: "claude-opus-5-5", MaxTokens: 2048},
		Secrets: []*aresv1.SecretUpdate{
			{Name: settings.SecretAIAPIKey, Value: "sk-ant-SUPERSECRET7788", ValuePresent: true},
		},
	}))
	if err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	v := resp.Msg
	if v.GetAi().GetProvider() != "anthropic" || v.GetAi().GetMaxTokens() != 2048 {
		t.Errorf("AI config not stored: %+v", v.GetAi())
	}
	var found bool
	for _, s := range v.GetSecrets() {
		if s.GetName() == settings.SecretAIAPIKey {
			found = true
			if !s.GetSet() {
				t.Error("secret must be reported set")
			}
			if strings.Contains(s.GetHint(), "SUPERSECRET") {
				t.Errorf("plaintext leaked into hint: %q", s.GetHint())
			}
			if s.GetHint() != "••••7788" {
				t.Errorf("hint = %q, want masked last-4", s.GetHint())
			}
		}
	}
	if !found {
		t.Fatal("ai.api_key status missing from view")
	}

	// A plain GetSettings must likewise never return the value.
	got, err := h.GetSettings(context.Background(), connect.NewRequest(&aresv1.GetSettingsRequest{}))
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	for _, s := range got.Msg.GetSecrets() {
		if strings.Contains(s.GetHint(), "SUPERSECRET") {
			t.Error("GetSettings leaked plaintext")
		}
	}
}

func TestAiConfiguredReflectsReadiness(t *testing.T) {
	h := withSettings(t, newTestHandler(t))
	// With nothing configured, ai_configured must be false.
	got, err := h.GetSettings(context.Background(), connect.NewRequest(&aresv1.GetSettingsRequest{}))
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.Msg.GetAiConfigured() {
		t.Error("ai_configured must be false when no provider is set")
	}
}

func TestTestAIProviderReportsMisconfig(t *testing.T) {
	h := withSettings(t, newTestHandler(t))
	// No provider configured and no override → not ok, with a key-free reason,
	// and no RPC error (surfaced for the UI).
	resp, err := h.TestAIProvider(context.Background(), connect.NewRequest(&aresv1.TestAIProviderRequest{}))
	if err != nil {
		t.Fatalf("TestAIProvider: %v", err)
	}
	if resp.Msg.GetOk() {
		t.Error("unconfigured provider must not report ok")
	}
	if resp.Msg.GetError() == "" {
		t.Error("expected a reason when not ok")
	}
}

func TestUpdateSettingsUnknownSecretRejected(t *testing.T) {
	h := withSettings(t, newTestHandler(t))
	_, err := h.UpdateSettings(context.Background(), connect.NewRequest(&aresv1.UpdateSettingsRequest{
		Secrets: []*aresv1.SecretUpdate{{Name: "evil.key", Value: "x", ValuePresent: true}},
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want CodeInvalidArgument, got %v", err)
	}
}
