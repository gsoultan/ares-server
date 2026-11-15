// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config selects and configures one AI provider. It is assembled from
// environment variables (ConfigFromEnv) so the API key never has to be written
// into source, a config file, or a request log.
type Config struct {
	// Provider is one of: anthropic, openai, gemini, azure, openai-compatible.
	// Empty means the advisory layer is disabled.
	Provider string
	// Model is the model id to use (e.g. claude-opus-5-5, gpt-4o, gemini-2.5-pro,
	// or an Azure deployment name).
	Model string
	// APIKey authenticates to the provider. Read from the environment only.
	APIKey string
	// BaseURL overrides the default endpoint — required for openai-compatible and
	// azure, optional elsewhere (e.g. a gateway or proxy).
	BaseURL string
	// APIVersion is used only by the azure provider (its api-version query param).
	APIVersion string
	// MaxTokens caps a single completion (default 1024).
	MaxTokens int
	// Temperature controls determinism (default 0.2 — advisory text should be
	// stable and grounded, not creative).
	Temperature float64
	// Timeout bounds a single provider call (default 60s).
	Timeout time.Duration
	// RestrictPrivate refuses to connect to loopback, private, link-local and
	// other internal addresses. It is set whenever the endpoint came from a
	// workspace's settings rather than the operator's environment, so a tenant
	// cannot point the server at its own internal network or cloud metadata.
	RestrictPrivate bool
}

// Env var names. Keys are read only from the environment, never persisted.
const (
	EnvProvider    = "ARES_AI_PROVIDER"
	EnvModel       = "ARES_AI_MODEL"
	EnvAPIKey      = "ARES_AI_API_KEY"
	EnvBaseURL     = "ARES_AI_BASE_URL"
	EnvAPIVersion  = "ARES_AI_API_VERSION"
	EnvMaxTokens   = "ARES_AI_MAX_TOKENS"
	EnvTemperature = "ARES_AI_TEMPERATURE"
	EnvTimeout     = "ARES_AI_TIMEOUT_SECONDS"
)

// ConfigFromEnv builds a Config from the ARES_AI_* environment variables. A
// provider may also fall back to its own vendor key variable (ANTHROPIC_API_KEY,
// OPENAI_API_KEY, GEMINI_API_KEY / GOOGLE_API_KEY, AZURE_OPENAI_API_KEY) when
// ARES_AI_API_KEY is unset, so operators can reuse an existing key.
func ConfigFromEnv() Config {
	cfg := Config{
		Provider:    strings.ToLower(strings.TrimSpace(os.Getenv(EnvProvider))),
		Model:       strings.TrimSpace(os.Getenv(EnvModel)),
		APIKey:      os.Getenv(EnvAPIKey),
		BaseURL:     strings.TrimSpace(os.Getenv(EnvBaseURL)),
		APIVersion:  strings.TrimSpace(os.Getenv(EnvAPIVersion)),
		Temperature: 0.2,
		MaxTokens:   1024,
		Timeout:     60 * time.Second,
	}
	if cfg.APIKey == "" {
		cfg.APIKey = vendorKeyFallback(cfg.Provider)
	}
	if v := strings.TrimSpace(os.Getenv(EnvMaxTokens)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxTokens = n
		}
	}
	if v := strings.TrimSpace(os.Getenv(EnvTemperature)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			cfg.Temperature = f
		}
	}
	if v := strings.TrimSpace(os.Getenv(EnvTimeout)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Timeout = time.Duration(n) * time.Second
		}
	}
	return cfg
}

func vendorKeyFallback(provider string) string {
	switch provider {
	case "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	case "openai", "openai-compatible":
		return os.Getenv("OPENAI_API_KEY")
	case "gemini":
		if k := os.Getenv("GEMINI_API_KEY"); k != "" {
			return k
		}
		return os.Getenv("GOOGLE_API_KEY")
	case "azure":
		return os.Getenv("AZURE_OPENAI_API_KEY")
	}
	return ""
}

// Enabled reports whether a provider has been selected. It does not guarantee
// the key or model are present — New reports those with a specific error.
func (c Config) Enabled() bool { return c.Provider != "" }

// Redacted returns a log-safe description of the config: the API key is reduced
// to its length, never its value.
func (c Config) Redacted() string {
	key := "unset"
	if c.APIKey != "" {
		key = fmt.Sprintf("set (%d chars)", len(c.APIKey))
	}
	base := c.BaseURL
	if base == "" {
		base = "default"
	}
	return fmt.Sprintf("provider=%s model=%s baseURL=%s apiKey=%s",
		orNone(c.Provider), orNone(c.Model), base, key)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// New builds the Provider selected by the config. It returns ErrNotConfigured
// when no provider is set (the caller then hides the feature), ErrNoAPIKey when
// the key is missing, and ErrNoModel when a required model id is absent.
func New(cfg Config) (Provider, error) {
	if !cfg.Enabled() {
		return nil, ErrNotConfigured
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1024
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	switch cfg.Provider {
	case "anthropic":
		return newAnthropic(cfg)
	case "openai", "openai-compatible":
		return newOpenAI(cfg)
	case "gemini":
		return newGemini(cfg)
	case "azure":
		return newAzure(cfg)
	default:
		return nil, fmt.Errorf("ai: unknown provider %q (want anthropic, openai, openai-compatible, gemini or azure)", cfg.Provider)
	}
}

// Providers lists the provider identifiers New understands.
func Providers() []string {
	return []string{"anthropic", "openai", "openai-compatible", "gemini", "azure"}
}
