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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func readBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode request body: %v (%s)", err, b)
	}
	return m
}

func TestAnthropicProvider(t *testing.T) {
	var gotPath, gotKey, gotVersion string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		body = readBody(t, r)
		_, _ = w.Write([]byte(`{"model":"claude-x","stop_reason":"end_turn",
			"content":[{"type":"text","text":"hello from claude"}],
			"usage":{"input_tokens":12,"output_tokens":7}}`))
	}))
	defer srv.Close()

	p, err := New(Config{Provider: "anthropic", Model: "m1", APIKey: "secret-key", BaseURL: srv.URL, MaxTokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), Request{System: "sys", Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", gotPath)
	}
	if gotKey != "secret-key" {
		t.Errorf("x-api-key not sent correctly: %q", gotKey)
	}
	if gotVersion == "" {
		t.Error("anthropic-version header missing")
	}
	if body["model"] != "m1" || body["system"] != "sys" {
		t.Errorf("request body wrong: %+v", body)
	}
	if resp.Text != "hello from claude" || resp.Usage.InputTokens != 12 || resp.Usage.OutputTokens != 7 {
		t.Errorf("response parsed wrong: %+v", resp)
	}
}

func TestOpenAIProvider(t *testing.T) {
	var gotPath, gotAuth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body = readBody(t, r)
		_, _ = w.Write([]byte(`{"model":"gpt-x","choices":[{"message":{"content":"hi from gpt"},
			"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":9}}`))
	}))
	defer srv.Close()

	p, err := New(Config{Provider: "openai", Model: "gpt-x", APIKey: "sk-abc", BaseURL: srv.URL, MaxTokens: 50})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), Request{System: "sys", Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer sk-abc" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	// System must be the first message.
	msgs, _ := body["messages"].([]any)
	if len(msgs) < 1 {
		t.Fatalf("no messages in body: %+v", body)
	}
	first, _ := msgs[0].(map[string]any)
	if first["role"] != "system" {
		t.Errorf("first message role = %v, want system", first["role"])
	}
	if resp.Text != "hi from gpt" || resp.Usage.InputTokens != 5 || resp.Usage.OutputTokens != 9 {
		t.Errorf("response parsed wrong: %+v", resp)
	}
}

func TestOpenAICompatibleRequiresBaseURL(t *testing.T) {
	_, err := New(Config{Provider: "openai-compatible", Model: "llama"})
	if err == nil {
		t.Fatal("openai-compatible without base URL must error")
	}
}

func TestOpenAICompatibleNoKeyOK(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"model":"llama","choices":[{"message":{"content":"local ok"}}]}`))
	}))
	defer srv.Close()
	// A self-hosted endpoint needs no key.
	p, err := New(Config{Provider: "openai-compatible", Model: "llama", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Errorf("no Authorization header expected without a key, got %q", gotAuth)
	}
	if resp.Text != "local ok" {
		t.Errorf("response = %q", resp.Text)
	}
	if p.Name() != "openai-compatible" {
		t.Errorf("name = %q", p.Name())
	}
}

func TestGeminiProvider(t *testing.T) {
	var gotPath, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-goog-api-key")
		_, _ = w.Write([]byte(`{"modelVersion":"gemini-x","candidates":[{"content":{"parts":[{"text":"hi "},{"text":"from gemini"}]},
			"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":4}}`))
	}))
	defer srv.Close()

	p, err := New(Config{Provider: "gemini", Model: "gemini-2.5-pro", APIKey: "g-key", BaseURL: srv.URL, MaxTokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), Request{System: "sys", Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotPath, "/v1beta/models/gemini-2.5-pro:generateContent") {
		t.Errorf("path = %q", gotPath)
	}
	if gotKey != "g-key" {
		t.Errorf("x-goog-api-key = %q", gotKey)
	}
	if resp.Text != "hi from gemini" || resp.Usage.InputTokens != 3 || resp.Usage.OutputTokens != 4 {
		t.Errorf("response parsed wrong: %+v", resp)
	}
}

func TestAzureProvider(t *testing.T) {
	var gotPath, gotQuery, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotKey = r.Header.Get("api-key")
		_, _ = w.Write([]byte(`{"model":"dep","choices":[{"message":{"content":"azure ok"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":2,"completion_tokens":3}}`))
	}))
	defer srv.Close()

	p, err := New(Config{Provider: "azure", Model: "my-deploy", APIKey: "az-key", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/openai/deployments/my-deploy/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotQuery, "api-version=") {
		t.Errorf("query missing api-version: %q", gotQuery)
	}
	if gotKey != "az-key" {
		t.Errorf("api-key = %q", gotKey)
	}
	if resp.Text != "azure ok" {
		t.Errorf("response = %q", resp.Text)
	}
}

func TestAPIErrorDoesNotLeakKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key","type":"authentication_error"}}`))
	}))
	defer srv.Close()

	p, _ := New(Config{Provider: "anthropic", Model: "m", APIKey: "super-secret-value", BaseURL: srv.URL})
	_, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err == nil {
		t.Fatal("expected an error on 401")
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Fatalf("error leaked the API key: %v", err)
	}
	var apiErr *APIError
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("error should carry the provider message: %v", err)
	}
	_ = apiErr
}
