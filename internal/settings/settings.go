// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package settings is Ares's in-app configuration store: the AI advisory
// provider and the OSINT provider credentials are configured here, at runtime,
// per workspace — not through environment variables. Secrets (API keys, client
// secrets) are sealed at rest with internal/secret and are never returned in
// plaintext over the API; a caller asking to read settings gets only whether a
// secret is set and a short masked hint. The AI and OSINT layers read their
// effective configuration through this service, which layers stored settings
// over environment-variable fallbacks so an existing env-based deployment keeps
// working.
package settings

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/ai"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/tenant"
)

// Secret names. These are the keys under which sealed credentials are stored and
// referenced; they are stable identifiers, safe to expose (the values are not).
const (
	SecretAIAPIKey     = "ai.api_key"
	SecretShodanKey    = "osint.shodan.api_key"
	SecretCensysID     = "osint.censys.api_id"
	SecretCensysSecret = "osint.censys.api_secret"
	SecretHIBPKey      = "osint.hibp.api_key"
)

// knownSecrets is the set of secret names the store accepts, so a client cannot
// stuff arbitrary keys into the sealed store.
var knownSecrets = map[string]bool{
	SecretAIAPIKey:     true,
	SecretShodanKey:    true,
	SecretCensysID:     true,
	SecretCensysSecret: true,
	SecretHIBPKey:      true,
}

// KnownSecretNames returns the accepted secret names (sorted callers may rely on
// a stable set; order here is not guaranteed).
func KnownSecretNames() []string {
	out := make([]string, 0, len(knownSecrets))
	for k := range knownSecrets {
		out = append(out, k)
	}
	return out
}

// AIConfig is the non-secret portion of the AI advisory configuration.
type AIConfig struct {
	Provider    string  `json:"provider"`
	Model       string  `json:"model"`
	BaseURL     string  `json:"baseUrl"`
	APIVersion  string  `json:"apiVersion"`
	MaxTokens   int     `json:"maxTokens"`
	Temperature float64 `json:"temperature"`
}

// SealedSecret is the stored form of a secret: the ciphertext plus a short,
// non-reversible hint and a timestamp for display. The plaintext is never here.
type SealedSecret struct {
	Ciphertext string    `json:"ciphertext"`
	Hint       string    `json:"hint"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Stored is the persisted record for one workspace. Repos serialize this shape.
type Stored struct {
	TenantID string                  `json:"tenantId"`
	AI       AIConfig                `json:"ai"`
	Secrets  map[string]SealedSecret `json:"secrets"`
}

// Repo persists Stored records. A memory implementation ships here; stormstore
// provides the durable one. Implementations must be safe for concurrent use.
type Repo interface {
	// Get returns the stored settings for a workspace, or ok=false if none.
	Get(tenantID string) (Stored, bool, error)
	// Put writes the stored settings for a workspace.
	Put(Stored) error
}

// SecretView is the read-only, safe projection of a secret: whether it is set
// and a masked hint, never the value.
type SecretView struct {
	Name      string    `json:"name"`
	Set       bool      `json:"set"`
	Hint      string    `json:"hint,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// View is what GetSettings returns: non-secret config plus the masked secret
// status for every known secret. It never carries a plaintext secret.
type View struct {
	TenantID string       `json:"tenantId"`
	AI       AIConfig     `json:"ai"`
	Secrets  []SecretView `json:"secrets"`
	// AIReady is true when the effective AI configuration (provider, model, key,
	// endpoint) is complete enough to build a provider — i.e. the advisor is on.
	AIReady bool `json:"aiReady"`
}

// SecretUpdate is a requested change to one secret. A nil Value leaves the
// secret unchanged; Clear removes it; otherwise the value is sealed and stored.
type SecretUpdate struct {
	Name  string
	Value *string
	Clear bool
}

// Update is a patch to a workspace's settings. Nil AI pointer fields leave the
// corresponding field unchanged.
type Update struct {
	AI      *AIConfig
	Secrets []SecretUpdate
}

// Service applies masking, sealing and env-fallback logic over a Repo.
type Service struct {
	sealer *secret.Sealer
	repo   Repo
	mu     sync.Mutex
}

// NewService builds a settings service over a sealer and a repo.
func NewService(sealer *secret.Sealer, repo Repo) *Service {
	return &Service{sealer: sealer, repo: repo}
}

// View returns the masked settings for a workspace, merged over environment
// fallbacks for the non-secret AI fields so the UI shows the effective config.
func (s *Service) View(tenantID string) (View, error) {
	tenantID = tenant.Resolve(tenantID)
	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return View{}, err
	}
	eff := s.effectiveAINonSecret(st.AI)
	v := View{TenantID: tenantID, AI: eff}
	for _, name := range []string{SecretAIAPIKey, SecretShodanKey, SecretCensysID, SecretCensysSecret, SecretHIBPKey} {
		sv := SecretView{Name: name}
		if sec, ok := st.Secrets[name]; ok {
			sv.Set = true
			sv.Hint = sec.Hint
			sv.UpdatedAt = sec.UpdatedAt
		} else if envSecretFallback(name) != "" {
			// A secret supplied via environment counts as set, masked.
			sv.Set = true
			sv.Hint = mask(envSecretFallback(name))
		}
		v.Secrets = append(v.Secrets, sv)
	}
	// AI is "ready" when a provider can actually be built from the effective
	// config (with the sealed key opened) — no network call is made here.
	if cfg, cerr := s.AIConfig(tenantID); cerr == nil && cfg.Enabled() {
		if _, perr := ai.New(cfg); perr == nil {
			v.AIReady = true
		}
	}
	return v, nil
}

// Apply applies a patch and persists it. Secrets are sealed; a secret value is
// never logged or echoed back.
func (s *Service) Apply(tenantID string, u Update) (View, error) {
	tenantID = tenant.Resolve(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()

	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return View{}, err
	}
	st.TenantID = tenantID
	if st.Secrets == nil {
		st.Secrets = map[string]SealedSecret{}
	}
	if u.AI != nil {
		// A workspace-chosen endpoint must be a public https URL, so a member
		// cannot aim the server at its internal network or cloud metadata.
		if err := ai.CheckTenantEndpoint(u.AI.BaseURL); err != nil {
			return View{}, err
		}
		st.AI = *u.AI
	}
	for _, su := range u.Secrets {
		if !knownSecrets[su.Name] {
			return View{}, fmt.Errorf("settings: unknown secret %q", su.Name)
		}
		switch {
		case su.Clear:
			delete(st.Secrets, su.Name)
		case su.Value == nil:
			// unchanged
		case strings.TrimSpace(*su.Value) == "":
			// An explicit empty string clears, matching a "remove" gesture.
			delete(st.Secrets, su.Name)
		default:
			ct, err := s.sealer.SealString(*su.Value)
			if err != nil {
				return View{}, fmt.Errorf("settings: seal %s: %w", su.Name, err)
			}
			st.Secrets[su.Name] = SealedSecret{
				Ciphertext: ct,
				Hint:       mask(*su.Value),
				UpdatedAt:  time.Now().UTC(),
			}
		}
	}
	if err := s.repo.Put(st); err != nil {
		return View{}, err
	}
	return s.View(tenantID)
}

// openSecret returns the plaintext of a stored secret for internal use (never
// over the API), falling back to the environment. ok is false when unset.
func (s *Service) openSecret(tenantID, name string) (string, bool, error) {
	tenantID = tenant.Resolve(tenantID)
	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return "", false, err
	}
	if sec, ok := st.Secrets[name]; ok {
		pt, err := s.sealer.OpenString(sec.Ciphertext)
		if err != nil {
			return "", false, fmt.Errorf("settings: open %s: %w", name, err)
		}
		return pt, true, nil
	}
	if env := envSecretFallback(name); env != "" {
		return env, true, nil
	}
	return "", false, nil
}

// OSINTKey returns the plaintext of an OSINT provider secret for a module to
// use, or ok=false when it is not configured. The value is never returned over
// the API or logged.
func (s *Service) OSINTKey(tenantID, name string) (string, bool, error) {
	return s.openSecret(tenantID, name)
}

// AIConfig returns the effective ai.Config for a workspace: stored settings over
// environment fallback, with the sealed API key opened for use. The returned
// config is for constructing a provider, not for display.
func (s *Service) AIConfig(tenantID string) (ai.Config, error) {
	cfg := ai.ConfigFromEnv() // environment fallback baseline
	tenantID = tenant.Resolve(tenantID)
	st, ok, err := s.repo.Get(tenantID)
	if err != nil {
		return ai.Config{}, err
	}
	if ok {
		if st.AI.Provider != "" {
			cfg.Provider = st.AI.Provider
		}
		if st.AI.Model != "" {
			cfg.Model = st.AI.Model
		}
		if st.AI.BaseURL != "" {
			cfg.BaseURL = st.AI.BaseURL
		}
		if st.AI.APIVersion != "" {
			cfg.APIVersion = st.AI.APIVersion
		}
		if st.AI.MaxTokens > 0 {
			cfg.MaxTokens = st.AI.MaxTokens
		}
		if st.AI.Temperature != 0 {
			cfg.Temperature = st.AI.Temperature
		}
	}
	// The operator's environment key belongs to the operator's endpoint. When a
	// workspace points the advisor at a different provider or URL, the
	// environment key is never sent there: the workspace must bring its own.
	env := ai.ConfigFromEnv()
	overridden := ok && ((st.AI.Provider != "" && st.AI.Provider != env.Provider) ||
		(st.AI.BaseURL != "" && st.AI.BaseURL != env.BaseURL))
	if overridden {
		cfg.APIKey = ""
	}
	if ok && st.AI.BaseURL != "" && st.AI.BaseURL != env.BaseURL {
		cfg.RestrictPrivate = true
	}
	if sec, has := st.Secrets[SecretAIAPIKey]; has {
		key, err := s.sealer.OpenString(sec.Ciphertext)
		if err != nil {
			return ai.Config{}, fmt.Errorf("settings: open %s: %w", SecretAIAPIKey, err)
		}
		cfg.APIKey = key
	}
	return cfg, nil
}

// effectiveAINonSecret layers stored non-secret AI fields over the environment
// baseline, for display.
func (s *Service) effectiveAINonSecret(stored AIConfig) AIConfig {
	env := ai.ConfigFromEnv()
	eff := AIConfig{
		Provider:    env.Provider,
		Model:       env.Model,
		BaseURL:     env.BaseURL,
		APIVersion:  env.APIVersion,
		MaxTokens:   env.MaxTokens,
		Temperature: env.Temperature,
	}
	if stored.Provider != "" {
		eff.Provider = stored.Provider
	}
	if stored.Model != "" {
		eff.Model = stored.Model
	}
	if stored.BaseURL != "" {
		eff.BaseURL = stored.BaseURL
	}
	if stored.APIVersion != "" {
		eff.APIVersion = stored.APIVersion
	}
	if stored.MaxTokens > 0 {
		eff.MaxTokens = stored.MaxTokens
	}
	if stored.Temperature != 0 {
		eff.Temperature = stored.Temperature
	}
	return eff
}

// mask renders a short, non-reversible hint of a secret for display: the last
// up-to-4 characters, the rest elided. A short secret is fully elided.
func mask(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 4 {
		return "••••"
	}
	return "••••" + v[len(v)-4:]
}

// MemRepo is an in-memory Repo for tests and ephemeral runs.
type MemRepo struct {
	mu sync.Mutex
	m  map[string]Stored
}

// NewMemRepo builds an empty in-memory repo.
func NewMemRepo() *MemRepo { return &MemRepo{m: map[string]Stored{}} }

// Get implements Repo.
func (r *MemRepo) Get(tenantID string) (Stored, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.m[tenantID]
	return st, ok, nil
}

// Put implements Repo.
func (r *MemRepo) Put(st Stored) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[st.TenantID] = st
	return nil
}
