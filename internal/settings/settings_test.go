// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package settings

import (
	"strings"
	"testing"

	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/tenant"
)

func newService(t *testing.T) *Service {
	t.Helper()
	key, _ := secret.NewKey()
	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return NewService(sealer, NewMemRepo())
}

func strptr(s string) *string { return &s }

func findSecret(v View, name string) SecretView {
	for _, sv := range v.Secrets {
		if sv.Name == name {
			return sv
		}
	}
	return SecretView{}
}

func TestApplyStoresNonSecretAI(t *testing.T) {
	svc := newService(t)
	ai := AIConfig{Provider: "anthropic", Model: "claude-opus-5-5", MaxTokens: 1024}
	v, err := svc.Apply("", Update{AI: &ai})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if v.AI.Provider != "anthropic" || v.AI.Model != "claude-opus-5-5" || v.AI.MaxTokens != 1024 {
		t.Errorf("AI not stored: %+v", v.AI)
	}
	if v.TenantID != tenant.DefaultID {
		t.Errorf("empty tenant must resolve to default, got %q", v.TenantID)
	}
}

func TestSecretIsWriteOnlyAndMasked(t *testing.T) {
	svc := newService(t)
	v, err := svc.Apply("", Update{Secrets: []SecretUpdate{
		{Name: SecretAIAPIKey, Value: strptr("sk-ant-api03-SECRETVALUE1234")},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sv := findSecret(v, SecretAIAPIKey)
	if !sv.Set {
		t.Fatal("secret must be reported as set")
	}
	// The view must never contain the plaintext.
	for _, s := range v.Secrets {
		if strings.Contains(s.Hint, "SECRETVALUE") {
			t.Errorf("plaintext leaked into hint: %q", s.Hint)
		}
	}
	if sv.Hint != "••••1234" {
		t.Errorf("hint = %q, want masked last-4", sv.Hint)
	}
	// Internal open returns the real value.
	got, ok, err := svc.OSINTKey("", SecretAIAPIKey)
	if err != nil || !ok {
		t.Fatalf("openSecret: ok=%v err=%v", ok, err)
	}
	if got != "sk-ant-api03-SECRETVALUE1234" {
		t.Errorf("opened secret = %q", got)
	}
}

func TestSecretUnchangedWhenValueNil(t *testing.T) {
	svc := newService(t)
	_, _ = svc.Apply("", Update{Secrets: []SecretUpdate{{Name: SecretShodanKey, Value: strptr("shodan-key-abcd")}}})
	// A later update with a nil value must leave it intact.
	_, err := svc.Apply("", Update{AI: &AIConfig{Provider: "openai"}, Secrets: []SecretUpdate{{Name: SecretShodanKey, Value: nil}}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, ok, _ := svc.OSINTKey("", SecretShodanKey)
	if !ok || got != "shodan-key-abcd" {
		t.Errorf("secret should survive nil-value update, got ok=%v val=%q", ok, got)
	}
}

func TestSecretClear(t *testing.T) {
	svc := newService(t)
	_, _ = svc.Apply("", Update{Secrets: []SecretUpdate{{Name: SecretHIBPKey, Value: strptr("hibp-xyz")}}})
	v, err := svc.Apply("", Update{Secrets: []SecretUpdate{{Name: SecretHIBPKey, Clear: true}}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if findSecret(v, SecretHIBPKey).Set {
		t.Error("secret must be cleared")
	}
	if _, ok, _ := svc.OSINTKey("", SecretHIBPKey); ok {
		t.Error("cleared secret must not open")
	}
}

func TestEmptyStringClears(t *testing.T) {
	svc := newService(t)
	_, _ = svc.Apply("", Update{Secrets: []SecretUpdate{{Name: SecretCensysID, Value: strptr("id-1")}}})
	v, _ := svc.Apply("", Update{Secrets: []SecretUpdate{{Name: SecretCensysID, Value: strptr("  ")}}})
	if findSecret(v, SecretCensysID).Set {
		t.Error("whitespace value must clear the secret")
	}
}

func TestUnknownSecretRejected(t *testing.T) {
	svc := newService(t)
	_, err := svc.Apply("", Update{Secrets: []SecretUpdate{{Name: "evil.key", Value: strptr("x")}}})
	if err == nil {
		t.Error("unknown secret name must be rejected")
	}
}

func TestAIConfigMergesSecret(t *testing.T) {
	svc := newService(t)
	ai := AIConfig{Provider: "anthropic", Model: "claude-opus-5-5"}
	_, _ = svc.Apply("", Update{AI: &ai, Secrets: []SecretUpdate{{Name: SecretAIAPIKey, Value: strptr("key-123")}}})
	cfg, err := svc.AIConfig("")
	if err != nil {
		t.Fatalf("AIConfig: %v", err)
	}
	if cfg.Provider != "anthropic" || cfg.Model != "claude-opus-5-5" {
		t.Errorf("merged non-secret wrong: %+v", cfg)
	}
	if cfg.APIKey != "key-123" {
		t.Errorf("merged API key wrong: %q", cfg.APIKey)
	}
}

func TestPerTenantIsolation(t *testing.T) {
	svc := newService(t)
	_, _ = svc.Apply("tenant-a", Update{Secrets: []SecretUpdate{{Name: SecretShodanKey, Value: strptr("a-key")}}})
	_, _ = svc.Apply("tenant-b", Update{Secrets: []SecretUpdate{{Name: SecretShodanKey, Value: strptr("b-key")}}})
	a, _, _ := svc.OSINTKey("tenant-a", SecretShodanKey)
	b, _, _ := svc.OSINTKey("tenant-b", SecretShodanKey)
	if a != "a-key" || b != "b-key" {
		t.Errorf("workspace isolation broken: a=%q b=%q", a, b)
	}
	// tenant-a must not see tenant-b's secret as set.
	va, _ := svc.View("tenant-a")
	if findSecret(va, SecretHIBPKey).Set {
		t.Error("unset secret must not be reported set")
	}
}
