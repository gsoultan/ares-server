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
	"net/url"
	"strings"
)

// geminiProvider speaks Google's Generative Language (Gemini) generateContent
// API. The key is sent in the x-goog-api-key header, never in the URL, so it
// does not land in a request log or proxy trace.
type geminiProvider struct {
	key       string
	model     string
	baseURL   string
	maxTokens int
	temp      float64
	client    *http.Client
}

func newGemini(cfg Config) (Provider, error) {
	if cfg.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	if cfg.Model == "" {
		return nil, ErrNoModel
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://generativelanguage.googleapis.com"
	}
	return &geminiProvider{
		key:       cfg.APIKey,
		model:     cfg.Model,
		baseURL:   base,
		maxTokens: cfg.MaxTokens,
		temp:      cfg.Temperature,
		client:    newHTTPClient(cfg.Timeout, cfg.RestrictPrivate),
	}, nil
}

func (p *geminiProvider) Name() string  { return "gemini" }
func (p *geminiProvider) Model() string { return p.model }

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiReq struct {
	SystemInstruction *geminiContent  `json:"system_instruction,omitempty"`
	Contents          []geminiContent `json:"contents"`
	GenerationConfig  struct {
		MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
		Temperature     float64 `json:"temperature,omitempty"`
	} `json:"generationConfig"`
}

type geminiResp struct {
	ModelVersion string `json:"modelVersion"`
	Candidates   []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

func (p *geminiProvider) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = p.model
	}
	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = p.maxTokens
	}
	body := geminiReq{}
	if req.System != "" {
		body.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: req.System}}}
	}
	for _, m := range req.Messages {
		role := "user"
		if m.Role == RoleAssistant {
			role = "model"
		}
		body.Contents = append(body.Contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
	}
	body.GenerationConfig.MaxOutputTokens = maxTok
	body.GenerationConfig.Temperature = temperatureOf(req, p.temp)

	endpoint := p.baseURL + "/v1beta/models/" + url.PathEscape(model) + ":generateContent"
	headers := map[string]string{"x-goog-api-key": p.key}
	data, err := postJSON(ctx, p.client, "gemini", endpoint, headers, body)
	if err != nil {
		return Response{}, err
	}
	var gr geminiResp
	if err := json.Unmarshal(data, &gr); err != nil {
		return Response{}, err
	}
	if len(gr.Candidates) == 0 {
		return Response{}, ErrEmptyResponse
	}
	var text strings.Builder
	for _, part := range gr.Candidates[0].Content.Parts {
		text.WriteString(part.Text)
	}
	out := strings.TrimSpace(text.String())
	if out == "" {
		return Response{}, ErrEmptyResponse
	}
	return Response{
		Text:       out,
		Model:      gr.ModelVersion,
		StopReason: gr.Candidates[0].FinishReason,
		Usage:      Usage{InputTokens: gr.UsageMetadata.PromptTokenCount, OutputTokens: gr.UsageMetadata.CandidatesTokenCount},
	}, nil
}
