// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package ai is Ares's optional, multi-provider AI advisory layer. It defines a
// single internal Provider interface and ships implementations for Anthropic
// (Claude), OpenAI (GPT), Google (Gemini) and any OpenAI-compatible or
// self-hosted endpoint (Azure OpenAI, OpenRouter, Ollama, LM Studio, vLLM…).
// The operator chooses the provider, model and API key from configuration; no
// key is ever logged or hardcoded, and when no provider is configured the whole
// feature is simply absent (graceful fallback).
//
// The layer is strictly advisory. A Provider only turns a prompt into text — it
// cannot dispatch a job, add a target to scope, or bypass the authorization
// gate. Any action the AI suggests must be carried out by the operator through
// the normal, scope-gated control plane. Nothing in this package imports the
// module registry, the queue or the scope engine, so that boundary is
// structural, not merely a convention.
package ai

import (
	"context"
	"errors"
)

// Role is the author of a message in a completion request.
type Role string

const (
	// RoleUser is operator/Ares-supplied content (the grounded prompt).
	RoleUser Role = "user"
	// RoleAssistant is prior model output, for multi-turn advisory refinement.
	RoleAssistant Role = "assistant"
)

// Message is one turn in a completion request.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// Request is a provider-agnostic completion request. System is sent through
// each provider's native system-prompt channel (Anthropic's top-level system,
// OpenAI's system message, Gemini's systemInstruction…).
type Request struct {
	System      string    `json:"system,omitempty"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"maxTokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	// Model overrides the provider's configured model for this one request; most
	// callers leave it empty and let the configured model apply.
	Model string `json:"model,omitempty"`
}

// Usage reports the tokens a completion consumed, when the provider returns it.
type Usage struct {
	InputTokens  int `json:"inputTokens"`
	OutputTokens int `json:"outputTokens"`
}

// Response is a provider-agnostic completion result.
type Response struct {
	Text       string `json:"text"`
	Model      string `json:"model"`
	StopReason string `json:"stopReason,omitempty"`
	Usage      Usage  `json:"usage"`
}

// Provider turns a Request into a Response by calling one AI backend. An
// implementation never performs any action beyond that single call.
type Provider interface {
	// Name is the provider's stable identifier (anthropic, openai, gemini, azure,
	// openai-compatible).
	Name() string
	// Model is the model id this provider will use by default.
	Model() string
	// Complete sends one request and returns the model's text.
	Complete(ctx context.Context, req Request) (Response, error)
}

// Common errors.
var (
	// ErrNotConfigured is returned by New when no provider is configured — the
	// signal callers use to hide the advisory feature entirely.
	ErrNotConfigured = errors.New("ai: no provider configured")
	// ErrNoAPIKey is returned when a provider is named but its API key is absent.
	ErrNoAPIKey = errors.New("ai: API key not set")
	// ErrNoModel is returned when a provider needs an explicit model id and none
	// was configured.
	ErrNoModel = errors.New("ai: model id not set")
	// ErrEmptyResponse is returned when the backend returned no usable text.
	ErrEmptyResponse = errors.New("ai: provider returned an empty response")
)

// APIError is a non-2xx response from a provider. It deliberately carries only
// the status and the provider's own (already key-free) error body, never the
// request, headers or API key.
type APIError struct {
	Provider string
	Status   int
	Message  string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return e.Provider + ": API returned status " + itoa(e.Status)
	}
	return e.Provider + ": " + e.Message
}

// itoa avoids a strconv import in the hot error path and keeps this file
// dependency-light.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
