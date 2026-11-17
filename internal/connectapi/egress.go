// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"strings"

	"github.com/gsoultan/ares-server/internal/egresscheck"
	"github.com/gsoultan/ares/canary"
)

// egressMinter issues the one-time canary tokens an agent's egresscheck task
// sends (M-25). The tokens live in the shared canary store, so the ares
// egressproof module (check-only mode, given the same tokens) reports which
// channels reached the collaborator.
type egressMinter struct {
	store                 *canary.Store
	base, domain          string
	altPortBase, highBase string
}

// WithEgressCanary enables the egresscheck capability's token minting. Without
// it, egresscheck tasks are refused at dispatch.
func (h *Handler) WithEgressCanary(store *canary.Store, base, domain, altPortBase, highPortBase string) *Handler {
	if store != nil {
		h.egress = &egressMinter{store: store, base: strings.TrimRight(base, "/"), domain: strings.TrimSuffix(strings.ToLower(domain), "."),
			altPortBase: strings.TrimRight(altPortBase, "/"), highBase: strings.TrimRight(highPortBase, "/")}
	}
	return h
}

// plan mints one token per channel that has a collaborator listener.
func (e *egressMinter) plan(engagementID string) []egresscheck.Token {
	var out []egresscheck.Token
	mint := func(ch string) egresscheck.Token {
		return egresscheck.Token{Channel: ch, Token: e.store.Mint(engagementID)}
	}
	if e.domain != "" {
		for _, ch := range []string{egresscheck.DNSDirect, egresscheck.DoH} {
			t := mint(ch)
			t.Name = t.Token + "." + e.domain
			out = append(out, t)
		}
	}
	if strings.HasPrefix(e.base, "https://") {
		t := mint(egresscheck.HTTPSDirect)
		t.URL = canary.URL(e.base, t.Token)
		out = append(out, t)
	}
	if e.altPortBase != "" {
		t := mint(egresscheck.HTTPSAltPort)
		t.URL = canary.URL(e.altPortBase, t.Token)
		out = append(out, t)
	}
	if e.highBase != "" {
		t := mint(egresscheck.TCPHigh)
		t.URL = canary.URL(e.highBase, t.Token)
		out = append(out, t)
	}
	return out
}
