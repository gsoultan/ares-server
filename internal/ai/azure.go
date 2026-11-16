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

// defaultAzureAPIVersion is a recent GA api-version used when the operator does
// not pin one.
const defaultAzureAPIVersion = "2024-10-21"

// azureProvider speaks Azure OpenAI's chat completions API. Azure differs from
// OpenAI in two ways this handles: the deployment is named in the URL (not the
// body), and the key is sent in the api-key header (not Authorization: Bearer).
// The response body is the same chat-completions shape, so it reuses openAIResp.
type azureProvider struct {
	key        string
	deployment string // the Azure deployment name (cfg.Model)
	baseURL    string // the resource endpoint, e.g. https://res.openai.azure.com
	apiVersion string
	maxTokens  int
	temp       float64
	client     *http.Client
}

func newAzure(cfg Config) (Provider, error) {
	if cfg.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	if cfg.Model == "" {
		return nil, ErrNoModel // the Azure deployment name
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		return nil, &APIError{Provider: "azure", Status: 0,
			Message: "azure requires " + EnvBaseURL + " (your resource endpoint, e.g. https://my-resource.openai.azure.com)"}
	}
	ver := cfg.APIVersion
	if ver == "" {
		ver = defaultAzureAPIVersion
	}
	return &azureProvider{
		key:        cfg.APIKey,
		deployment: cfg.Model,
		baseURL:    base,
		apiVersion: ver,
		maxTokens:  cfg.MaxTokens,
		temp:       cfg.Temperature,
		client:     newHTTPClient(cfg.Timeout, cfg.RestrictPrivate),
	}, nil
}

func (p *azureProvider) Name() string  { return "azure" }
func (p *azureProvider) Model() string { return p.deployment }

// azureReq is the chat-completions body without a model field (the deployment
// carries it in the URL).
type azureReq struct {
	Messages    []openAIMsg `json:"messages"`
	MaxTokens   int         `json:"max_tokens,omitempty"`
	Temperature float64     `json:"temperature,omitempty"`
}

func (p *azureProvider) Complete(ctx context.Context, req Request) (Response, error) {
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
	body := azureReq{
		Messages:    msgs,
		MaxTokens:   maxTok,
		Temperature: temperatureOf(req, p.temp),
	}
	endpoint := p.baseURL + "/openai/deployments/" + url.PathEscape(p.deployment) +
		"/chat/completions?api-version=" + url.QueryEscape(p.apiVersion)
	headers := map[string]string{"api-key": p.key}
	data, err := postJSON(ctx, p.client, "azure", endpoint, headers, body)
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
		Model:      p.deployment,
		StopReason: or.Choices[0].FinishReason,
		Usage:      Usage{InputTokens: or.Usage.PromptTokens, OutputTokens: or.Usage.CompletionTokens},
	}, nil
}
