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
	"net/http"
	"strings"
)

// openAIProvider speaks the OpenAI Chat Completions wire format. The same
// implementation serves OpenAI itself and any OpenAI-compatible or self-hosted
// endpoint (OpenRouter, Ollama, LM Studio, vLLM, …) via a configured base URL;
// self-hosted endpoints that need no key run with an empty key.
type openAIProvider struct {
	name      string // "openai" or "openai-compatible"
	key       string
	model     string
	baseURL   string
	maxTokens int
	temp      float64
	client    *http.Client
}

func newOpenAI(cfg Config) (Provider, error) {
	compatible := cfg.Provider == "openai-compatible"
	if cfg.Model == "" {
		return nil, ErrNoModel
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		if compatible {
			// A compatible/self-hosted endpoint has no default host.
			return nil, &APIError{Provider: cfg.Provider, Status: 0,
				Message: "openai-compatible requires " + EnvBaseURL + " (e.g. https://openrouter.ai/api/v1 or http://localhost:11434/v1)"}
		}
		base = "https://api.openai.com/v1"
	}
	// OpenAI itself requires a key; a self-hosted compatible endpoint may not.
	if !compatible && cfg.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	name := "openai"
	if compatible {
		name = "openai-compatible"
	}
	return &openAIProvider{
		name:      name,
		key:       cfg.APIKey,
		model:     cfg.Model,
		baseURL:   base,
		maxTokens: cfg.MaxTokens,
		temp:      cfg.Temperature,
		client:    newHTTPClient(cfg.Timeout, cfg.RestrictPrivate),
	}, nil
}

func (p *openAIProvider) Name() string  { return p.name }
func (p *openAIProvider) Model() string { return p.model }

type openAIReq struct {
	Model       string      `json:"model"`
	Messages    []openAIMsg `json:"messages"`
	MaxTokens   int         `json:"max_tokens,omitempty"`
	Temperature float64     `json:"temperature,omitempty"`
}

type openAIMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResp struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (p *openAIProvider) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = p.model
	}
	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = p.maxTokens
	}
	msgs := make([]openAIMsg, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, openAIMsg{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, openAIMsg{Role: string(m.Role), Content: m.Content})
	}
	body := openAIReq{
		Model:       model,
		Messages:    msgs,
		MaxTokens:   maxTok,
		Temperature: temperatureOf(req, p.temp),
	}
	headers := map[string]string{}
	if p.key != "" {
		headers["Authorization"] = "Bearer " + p.key
	}
	data, err := postJSON(ctx, p.client, p.name, p.baseURL+"/chat/completions", headers, body)
	if err != nil {
		return Response{}, err
	}
	var or openAIResp
	if err := json.Unmarshal(data, &or); err != nil {
		return Response{}, err
	}
	if len(or.Choices) == 0 {
		return Response{}, ErrEmptyResponse
	}
	out := strings.TrimSpace(or.Choices[0].Message.Content)
	if out == "" {
		return Response{}, ErrEmptyResponse
	}
	return Response{
		Text:       out,
		Model:      or.Model,
		StopReason: or.Choices[0].FinishReason,
		Usage:      Usage{InputTokens: or.Usage.PromptTokens, OutputTokens: or.Usage.CompletionTokens},
	}, nil
}
