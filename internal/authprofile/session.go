// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package authprofile

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/websession"
)

// sessionTimeout bounds the login round-trip a Session may make.
const sessionTimeout = 15 * time.Second

// Provider turns an engagement's stored, sealed credential into the scoped
// Session the engine runs probes under. It is the seam the worker depends on;
// the worker needs to know nothing about sealing or credentials.
type Provider struct {
	svc *Service
}

// NewProvider wires a Provider over the profile service.
func NewProvider(svc *Service) *Provider { return &Provider{svc: svc} }

// SessionFor returns the authenticated Session for an engagement's probing, or
// nil when the engagement has no stored credential or none of its hosts are in
// scope. The Session authenticates only the hosts the engagement's own scope
// gate admits, so a stored credential is never carried to a host outside the
// authorized target — and a form login is refused unless its own URL is in
// scope, so the credential is never posted off-target.
//
// A non-nil error means a stored credential could not be turned into a session
// (for example a login that failed); it never contains the credential value.
// The caller decides whether to proceed unauthenticated.
func (p *Provider) SessionFor(ctx context.Context, eng *engagement.Engagement) (*websession.Session, error) {
	if p == nil || p.svc == nil || eng == nil || eng.Scope == nil {
		return nil, nil
	}
	prof, ok, err := p.svc.open(eng.TenantID, eng.ID)
	if err != nil {
		return nil, err
	}
	if !ok || prof.Credential.IsZero() {
		return nil, nil
	}

	// A form login posts the credential to its own URL; refuse unless that URL
	// is itself in scope, so the credential is never sent off-target.
	if f := prof.Credential.Form; f != nil {
		h, herr := hostOf(f.URL)
		if herr != nil {
			return nil, fmt.Errorf("authprofile: login URL: %w", herr)
		}
		if allowed, _ := eng.Scope.Allow(module.Target{Host: h}); !allowed {
			return nil, fmt.Errorf("authprofile: login host %q is out of scope", h)
		}
	}

	hosts := p.inScopeHosts(eng, prof)
	if len(hosts) == 0 {
		// Nothing the credential names is in scope: build no session rather than
		// authenticate a host the engagement does not cover.
		return nil, nil
	}
	return websession.NewSession(ctx, prof.Credential, hosts, sessionTimeout)
}

// inScopeHosts returns the hosts the session may authenticate: the profile's own
// hosts when it names any, else the engagement's in-scope hostnames — in both
// cases kept only where the scope gate still admits them.
func (p *Provider) inScopeHosts(eng *engagement.Engagement, prof Profile) []string {
	candidates := prof.Hosts
	if len(candidates) == 0 {
		candidates = scopeHostnames(eng)
	}
	out := make([]string, 0, len(candidates))
	for _, h := range candidates {
		if h == "" {
			continue
		}
		if allowed, _ := eng.Scope.Allow(module.Target{Host: h}); allowed {
			out = append(out, h)
		}
	}
	return out
}

// scopeHostnames lists the plain hostnames/domains an engagement's scope admits,
// skipping CIDR ranges (a credential is bound to a named host, not a subnet).
func scopeHostnames(eng *engagement.Engagement) []string {
	snap := eng.Scope.Snapshot()
	out := make([]string, 0, len(snap.InScope))
	for _, e := range snap.InScope {
		if e == "" || containsAny(e, "/") { // CIDR or path-like entry
			continue
		}
		out = append(out, e)
	}
	return out
}

func containsAny(s, chars string) bool {
	for _, c := range chars {
		for _, sc := range s {
			if sc == c {
				return true
			}
		}
	}
	return false
}

func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	return u.Hostname(), nil
}
