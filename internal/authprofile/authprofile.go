// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package authprofile stores, per engagement, the credential that lets Ares test
// behind a login — a form login, a captured session cookie, or a bearer token —
// and turns it into the scoped websession.Session the engine runs probes under.
//
// The credential is sensitive, so it is treated exactly like the OSINT/AI
// provider keys in package settings: it is sealed at rest per workspace with
// internal/secret (AES-256-GCM), the plaintext never leaves this package except
// to build a Session, and it is never returned over the API or written to a log
// or report. A caller reading a profile gets only whether one is set, which
// mechanism, the hosts it covers and a short masked hint — never the value.
//
// Isolation holds: a profile is keyed by (workspace, engagement) and the store
// never serves one workspace's profile to another. Scope holds: a Session is
// built only for the hosts the engagement's own scope gate admits, so a stored
// credential cannot be carried to any host outside the authorized target.
package authprofile

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares/websession"
)

// Profile is the plaintext credential for one engagement. It mirrors
// websession.Credential plus the in-scope Hosts the credential applies to. It
// exists in memory only while a profile is being set or a Session built; the
// stored form is sealed.
type Profile struct {
	// Hosts are the hostnames this credential authenticates. Each is checked
	// against the engagement scope before a Session is built, so a host that is
	// not in scope is dropped rather than trusted.
	Hosts      []string              `json:"hosts,omitempty"`
	Credential websession.Credential `json:"credential"`
}

// Mechanism names the kind of credential a profile carries, for display.
func (p Profile) Mechanism() string {
	switch {
	case p.Credential.Form != nil:
		return "form-login"
	case p.Credential.Cookie != "":
		return "cookie"
	case p.Credential.Bearer != "":
		return "bearer"
	case len(p.Credential.Headers) > 0:
		return "headers"
	default:
		return "none"
	}
}

// hint returns a short, non-reversible description of the secret, so the UI can
// show that a credential is set without ever revealing it.
func (p Profile) hint() string {
	switch {
	case p.Credential.Form != nil:
		return "form login at " + p.Credential.Form.URL
	case p.Credential.Bearer != "":
		return "bearer " + mask(p.Credential.Bearer)
	case p.Credential.Cookie != "":
		return "cookie " + mask(p.Credential.Cookie)
	case len(p.Credential.Headers) > 0:
		return fmt.Sprintf("%d header(s)", len(p.Credential.Headers))
	default:
		return ""
	}
}

// Sealed is the stored form of a profile: the sealed credential plus
// non-sensitive display fields. The plaintext credential is never here.
type Sealed struct {
	Ciphertext string    `json:"ciphertext"`
	Mechanism  string    `json:"mechanism"`
	Hosts      []string  `json:"hosts,omitempty"`
	Hint       string    `json:"hint"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// View is the read-only, safe projection of a profile: whether it is set, which
// mechanism, the hosts and a masked hint — never the credential value.
type View struct {
	TenantID     string    `json:"tenantId"`
	EngagementID string    `json:"engagementId"`
	Set          bool      `json:"set"`
	Mechanism    string    `json:"mechanism,omitempty"`
	Hosts        []string  `json:"hosts,omitempty"`
	Hint         string    `json:"hint,omitempty"`
	UpdatedAt    time.Time `json:"updatedAt,omitempty"`
}

// Stored is the persisted record for one workspace: its engagements' sealed
// auth profiles, keyed by engagement id.
type Stored struct {
	TenantID string            `json:"tenantId"`
	Profiles map[string]Sealed `json:"profiles"`
}

// Repo persists Stored records. A memory implementation ships here; a durable
// one lives alongside the other stores. Implementations must be safe for
// concurrent use.
type Repo interface {
	Get(tenantID string) (Stored, bool, error)
	Put(Stored) error
}

// Service seals, opens and masks engagement auth profiles over a Repo.
type Service struct {
	sealer *secret.Sealer
	repo   Repo
	mu     sync.Mutex
}

// NewService builds a profile service over a sealer and a repo.
func NewService(sealer *secret.Sealer, repo Repo) *Service {
	return &Service{sealer: sealer, repo: repo}
}

// Set seals and stores an engagement's credential. An empty credential clears
// it, matching a "remove" gesture. The value is never logged or echoed back.
func (s *Service) Set(tenantID, engagementID string, p Profile) (View, error) {
	tenantID = tenant.Resolve(tenantID)
	if engagementID == "" {
		return View{}, fmt.Errorf("authprofile: engagement id required")
	}
	if p.Credential.IsZero() {
		return s.Clear(tenantID, engagementID)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return View{}, fmt.Errorf("authprofile: marshal: %w", err)
	}
	ct, err := s.sealer.Seal(raw)
	if err != nil {
		return View{}, fmt.Errorf("authprofile: seal: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return View{}, err
	}
	st.TenantID = tenantID
	if st.Profiles == nil {
		st.Profiles = map[string]Sealed{}
	}
	st.Profiles[engagementID] = Sealed{
		Ciphertext: ct,
		Mechanism:  p.Mechanism(),
		Hosts:      normHosts(p.Hosts),
		Hint:       p.hint(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := s.repo.Put(st); err != nil {
		return View{}, err
	}
	return s.view(tenantID, engagementID, st)
}

// Clear removes an engagement's credential, if any.
func (s *Service) Clear(tenantID, engagementID string) (View, error) {
	tenantID = tenant.Resolve(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return View{}, err
	}
	if st.Profiles != nil {
		delete(st.Profiles, engagementID)
		st.TenantID = tenantID
		if err := s.repo.Put(st); err != nil {
			return View{}, err
		}
	}
	return View{TenantID: tenantID, EngagementID: engagementID, Set: false}, nil
}

// ViewFor returns the masked status of an engagement's credential.
func (s *Service) ViewFor(tenantID, engagementID string) (View, error) {
	tenantID = tenant.Resolve(tenantID)
	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return View{}, err
	}
	return s.view(tenantID, engagementID, st)
}

func (s *Service) view(tenantID, engagementID string, st Stored) (View, error) {
	v := View{TenantID: tenantID, EngagementID: engagementID}
	if sec, ok := st.Profiles[engagementID]; ok {
		v.Set = true
		v.Mechanism = sec.Mechanism
		v.Hosts = sec.Hosts
		v.Hint = sec.Hint
		v.UpdatedAt = sec.UpdatedAt
	}
	return v, nil
}

// open returns the plaintext profile for internal use (never over the API),
// or ok=false when none is set.
func (s *Service) open(tenantID, engagementID string) (Profile, bool, error) {
	tenantID = tenant.Resolve(tenantID)
	st, _, err := s.repo.Get(tenantID)
	if err != nil {
		return Profile{}, false, err
	}
	sec, ok := st.Profiles[engagementID]
	if !ok {
		return Profile{}, false, nil
	}
	raw, err := s.sealer.Open(sec.Ciphertext)
	if err != nil {
		return Profile{}, false, fmt.Errorf("authprofile: open: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return Profile{}, false, fmt.Errorf("authprofile: unmarshal: %w", err)
	}
	return p, true, nil
}

func normHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

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
