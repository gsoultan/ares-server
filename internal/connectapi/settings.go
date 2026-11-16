// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/ai"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/settings"
)

// GetSettings returns the effective, masked settings for a workspace. Secret
// values are never returned — only whether each is set and a masked hint.
func (h *Handler) GetSettings(_ context.Context, req *connect.Request[aresv1.GetSettingsRequest]) (*connect.Response[aresv1.SettingsView], error) {
	if h.settings == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("settings store not configured (complete first-run setup)"))
	}
	v, err := h.settings.View(req.Msg.GetTenantId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(settingsViewProto(v)), nil
}

// requireSettingsManager allows a workspace's provider settings and keys to be
// changed or exercised only by an owner, admin or super-admin. A call with no
// session got past the interceptor only because auth is not enforced yet
// (first-run setup, or ARES_REQUIRE_AUTH=off).
func requireSettingsManager(ctx context.Context) error {
	if sess, ok := SessionFromContext(ctx); ok && !sess.Role.IsManager() {
		return connect.NewError(connect.CodePermissionDenied, errors.New("only a workspace owner or admin may change settings"))
	}
	return nil
}

// UpdateSettings applies a settings patch. Secret values are write-only: they
// are sealed and stored, never echoed back. The response is the masked view.
func (h *Handler) UpdateSettings(ctx context.Context, req *connect.Request[aresv1.UpdateSettingsRequest]) (*connect.Response[aresv1.SettingsView], error) {
	if err := requireSettingsManager(ctx); err != nil {
		return nil, err
	}
	if h.settings == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("settings store not configured (complete first-run setup)"))
	}
	msg := req.Msg
	upd := settings.Update{}
	if msg.GetAiPresent() {
		ai := msg.GetAi()
		upd.AI = &settings.AIConfig{
			Provider:    ai.GetProvider(),
			Model:       ai.GetModel(),
			BaseURL:     ai.GetBaseUrl(),
			APIVersion:  ai.GetApiVersion(),
			MaxTokens:   int(ai.GetMaxTokens()),
			Temperature: ai.GetTemperature(),
		}
	}
	for _, su := range msg.GetSecrets() {
		s := settings.SecretUpdate{Name: su.GetName(), Clear: su.GetClear()}
		if su.GetValuePresent() {
			v := su.GetValue()
			s.Value = &v
		}
		upd.Secrets = append(upd.Secrets, s)
	}
	v, err := h.settings.Apply(msg.GetTenantId(), upd)
	if err != nil {
		// Unknown-secret and similar validation errors are the caller's fault.
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(settingsViewProto(v)), nil
}

// settingsViewProto maps the service view (already masked) onto the wire type.
func settingsViewProto(v settings.View) *aresv1.SettingsView {
	out := &aresv1.SettingsView{
		TenantId: v.TenantID,
		Ai: &aresv1.AISettings{
			Provider:    v.AI.Provider,
			Model:       v.AI.Model,
			BaseUrl:     v.AI.BaseURL,
			ApiVersion:  v.AI.APIVersion,
			MaxTokens:   int32(v.AI.MaxTokens),
			Temperature: v.AI.Temperature,
		},
	}
	out.AiConfigured = v.AIReady
	for _, s := range v.Secrets {
		ss := &aresv1.SecretStatus{Name: s.Name, Set: s.Set, Hint: s.Hint}
		if !s.UpdatedAt.IsZero() {
			ss.UpdatedAt = s.UpdatedAt.UTC().Format(time.RFC3339)
		}
		out.Secrets = append(out.Secrets, ss)
	}
	return out
}

// TestAIProvider verifies an AI provider configuration with a minimal probe. It
// can test the saved settings or unsaved form values (including a one-off API
// key that is never stored). No engagement data is sent — only a tiny ping — so
// it needs no opt-in. Any failure is surfaced as a key-free error.
func (h *Handler) TestAIProvider(ctx context.Context, req *connect.Request[aresv1.TestAIProviderRequest]) (*connect.Response[aresv1.TestAIProviderResponse], error) {
	if err := requireSettingsManager(ctx); err != nil {
		return nil, err
	}
	if h.settings == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("settings store not configured (complete first-run setup)"))
	}
	msg := req.Msg

	// Start from the saved, effective config (sealed key opened), then layer any
	// unsaved form overrides on top for the test only.
	cfg, err := h.settings.AIConfig(msg.GetTenantId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if msg.GetAiPresent() {
		a := msg.GetAi()
		// Testing against a different provider or URL must never carry the saved
		// key there: an unsaved endpoint is tested only with a one-off key.
		endpointChanged := (a.GetProvider() != "" && a.GetProvider() != cfg.Provider) ||
			(a.GetBaseUrl() != "" && a.GetBaseUrl() != cfg.BaseURL)
		if endpointChanged {
			cfg.APIKey = ""
		}
		if a.GetBaseUrl() != "" && a.GetBaseUrl() != cfg.BaseURL {
			if err := ai.CheckTenantEndpoint(a.GetBaseUrl()); err != nil {
				return connect.NewResponse(&aresv1.TestAIProviderResponse{Provider: cfg.Provider, Model: cfg.Model, Error: err.Error()}), nil
			}
			cfg.RestrictPrivate = true
		}
		if a.GetProvider() != "" {
			cfg.Provider = a.GetProvider()
		}
		if a.GetModel() != "" {
			cfg.Model = a.GetModel()
		}
		if a.GetBaseUrl() != "" {
			cfg.BaseURL = a.GetBaseUrl()
		}
		if a.GetApiVersion() != "" {
			cfg.APIVersion = a.GetApiVersion()
		}
		if a.GetMaxTokens() > 0 {
			cfg.MaxTokens = int(a.GetMaxTokens())
		}
		if a.GetTemperature() != 0 {
			cfg.Temperature = a.GetTemperature()
		}
	}
	if msg.GetApiKeyPresent() && msg.GetApiKey() != "" {
		cfg.APIKey = msg.GetApiKey() // test-only; never persisted
	}

	resp := &aresv1.TestAIProviderResponse{Provider: cfg.Provider, Model: cfg.Model}
	provider, err := ai.New(cfg)
	if err != nil {
		resp.Error = err.Error() // key-free by construction
		return connect.NewResponse(resp), nil
	}
	resp.Provider = provider.Name()
	resp.Model = provider.Model()

	// Minimal probe: a one-token completion verifies auth, model and endpoint.
	start := time.Now()
	_, err = provider.Complete(ctx, ai.Request{
		Messages:  []ai.Message{{Role: ai.RoleUser, Content: "ping"}},
		MaxTokens: 1,
	})
	resp.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		resp.Error = err.Error() // provider errors never carry the key
		return connect.NewResponse(resp), nil
	}
	resp.Ok = true
	return connect.NewResponse(resp), nil
}
