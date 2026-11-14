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

// anthropicVersion is the Messages API version header value.
const anthropicVersion = "2023-06-01"

// defaultAnthropicModel is used when the operator sets no model id.
const defaultAnthropicModel = "claude-opus-5-5"

type anthropicProvider struct {
	key       string
	model     string
	baseURL   string
	maxTokens int
	temp      float64
	client    *http.Client
}

func newAnthropic(cfg Config) (Provider, error) {
	if cfg.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	model := cfg.Model
	if model == "" {
		model = defaultAnthropicModel
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.anthropic.com"
	}
	return &anthropicProvider{
		key:       cfg.APIKey,
		model:     model,
		baseURL:   strings.TrimRight(base, "/"),
		maxTokens: cfg.MaxTokens,
		temp:      cfg.Temperature,
		client:    newHTTPClient(cfg.Timeout),
	}, nil
}

func (p *anthropicProvider) Name() string  { return "anthropic" }
func (p *anthropicProvider) Model() string { return p.model }

type anthropicReq struct {
	Model       string         `json:"model"`
	MaxTokens   int            `json:"max_tokens"`
	System      string         `json:"system,omitempty"`
	Temperature float64        `json:"temperature,omitempty"`
	Messages    []anthropicMsg `json:"messages"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResp struct {
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (p *anthropicProvider) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = p.model
	}
	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = p.maxTokens
	}
	body := anthropicReq{
		Model:       model,
		MaxTokens:   maxTok,
		System:      req.System,
		Temperature: temperatureOf(req, p.temp),
		Messages:    make([]anthropicMsg, 0, len(req.Messages)),
	}
	for _, m := range req.Messages {
		body.Messages = append(body.Messages, anthropicMsg{Role: string(m.Role), Content: m.Content})
	}
	headers := map[string]string{
		"x-api-key":         p.key,
		"anthropic-version": anthropicVersion,
	}
	data, err := postJSON(ctx, p.client, "anthropic", p.baseURL+"/v1/messages", headers, body)
	if err != nil {
		return Response{}, err
	}
	var ar anthropicResp
	if err := json.Unmarshal(data, &ar); err != nil {
		return Response{}, err
	}
	var text strings.Builder
	for _, c := range ar.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	out := strings.TrimSpace(text.String())
	if out == "" {
		return Response{}, ErrEmptyResponse
	}
	return Response{
		Text:       out,
		Model:      ar.Model,
		StopReason: ar.StopReason,
		Usage:      Usage{InputTokens: ar.Usage.InputTokens, OutputTokens: ar.Usage.OutputTokens},
	}, nil
}

// temperatureOf returns the request temperature when set, else the provider
// default. A zero request temperature falls back to the configured value so a
// per-request override is only applied when explicitly non-zero.
func temperatureOf(req Request, def float64) float64 {
	if req.Temperature > 0 {
		return req.Temperature
	}
	return def
}
