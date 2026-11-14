// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvProvider, "OpenAI") // case-insensitive
	t.Setenv(EnvModel, "gpt-x")
	t.Setenv(EnvAPIKey, "sk-123")
	t.Setenv(EnvMaxTokens, "777")
	t.Setenv(EnvTemperature, "0.5")

	cfg := ConfigFromEnv()
	if cfg.Provider != "openai" {
		t.Errorf("provider = %q, want openai (lowercased)", cfg.Provider)
	}
	if cfg.Model != "gpt-x" || cfg.APIKey != "sk-123" {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.MaxTokens != 777 || cfg.Temperature != 0.5 {
		t.Errorf("numeric envs not parsed: %+v", cfg)
	}
	if !cfg.Enabled() {
		t.Error("Enabled() should be true when provider set")
	}
}

func TestConfigVendorKeyFallback(t *testing.T) {
	t.Setenv(EnvProvider, "anthropic")
	t.Setenv(EnvAPIKey, "")
	t.Setenv("ANTHROPIC_API_KEY", "ant-key")
	cfg := ConfigFromEnv()
	if cfg.APIKey != "ant-key" {
		t.Errorf("vendor key fallback failed: %q", cfg.APIKey)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("empty config should be ErrNotConfigured, got %v", err)
	}
	if _, err := New(Config{Provider: "anthropic"}); !errors.Is(err, ErrNoAPIKey) {
		t.Errorf("anthropic without key should be ErrNoAPIKey, got %v", err)
	}
	if _, err := New(Config{Provider: "openai", APIKey: "k"}); !errors.Is(err, ErrNoModel) {
		t.Errorf("openai without model should be ErrNoModel, got %v", err)
	}
	if _, err := New(Config{Provider: "gemini", APIKey: "k"}); !errors.Is(err, ErrNoModel) {
		t.Errorf("gemini without model should be ErrNoModel, got %v", err)
	}
	if _, err := New(Config{Provider: "whatever", APIKey: "k", Model: "m"}); err == nil {
		t.Error("unknown provider should error")
	}
}

func TestRedactedHidesKey(t *testing.T) {
	cfg := Config{Provider: "openai", Model: "gpt-x", APIKey: "super-secret-key-value"}
	r := cfg.Redacted()
	if strings.Contains(r, "super-secret-key-value") {
		t.Fatalf("Redacted leaked the key: %s", r)
	}
	if !strings.Contains(r, "chars)") {
		t.Errorf("Redacted should report the key length: %s", r)
	}
}

func TestAnthropicDefaultModel(t *testing.T) {
	p, err := New(Config{Provider: "anthropic", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Model() != defaultAnthropicModel {
		t.Errorf("default model = %q, want %q", p.Model(), defaultAnthropicModel)
	}
}

func TestAdvisorFromEnvDisabled(t *testing.T) {
	t.Setenv(EnvProvider, "")
	t.Setenv(EnvAPIKey, "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	_, err := AdvisorFromEnv()
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("with no provider, AdvisorFromEnv should be ErrNotConfigured, got %v", err)
	}
}
