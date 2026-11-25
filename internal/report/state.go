// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/gsoultan/ares-server/internal/worker"
)

// FindingKey is a finding's stable identity across runs: the engagement, the
// module that raised it, its technique, title and target. The findings API and
// the report share it, so a finding has the same id in the app and on paper.
func FindingKey(engID, module, technique, title, target string) string {
	sum := sha256.Sum256([]byte(engID + "\x00" + module + "\x00" + technique + "\x00" + title + "\x00" + target))
	return hex.EncodeToString(sum[:16]) // 128-bit id
}

// RanModuleTargets returns the set of "module\x00target" pairs a job exercised,
// used to decide whether a later run re-checked a finding's module and target.
// It covers direct dispatch (the job's own module over its allowed targets),
// any module that produced a result, and — for an auto-run recon job — the
// sub-checks it ran, which recon records in its "planned" note even when they
// found nothing.
func RanModuleTargets(o worker.Outcome) map[string]bool {
	set := map[string]bool{}
	if o.Module != "" && o.Module != "recon" {
		for _, t := range o.Allowed {
			set[o.Module+"\x00"+t.String()] = true
		}
	}
	for _, r := range o.Results {
		set[r.Capability+"\x00"+r.Target.String()] = true
		if r.Capability == "recon" && r.Kind == "info" {
			planned, _ := r.Data["planned"].([]any)
			tgt := r.Target.String()
			for _, p := range planned {
				if name, ok := p.(string); ok {
					set[name+"\x00"+tgt] = true
				}
			}
		}
	}
	return set
}

// Recheck is one reproduce-on-demand run of a finding's proof.
type Recheck struct {
	At          time.Time
	Reproduced  bool
	Fingerprint string
	JobID       string
}

// FixState is where a finding stands, in the words an owner reads.
type FixState string

const (
	// StateOpen: found and not yet acted on.
	StateOpen FixState = "open"
	// StateInProgress: someone is working on it.
	StateInProgress FixState = "in_progress"
	// StateAwaitingRecheck: marked fixed, but no test has confirmed it yet.
	StateAwaitingRecheck FixState = "awaiting_recheck"
	// StateProvenFixed: a later test of the same check and target no longer
	// finds it, so the fix is proven, not just claimed.
	StateProvenFixed FixState = "proven_fixed"
)

// State is the finding's fix state. Proof outranks claims: a finding a later
// run no longer raised is proven fixed whatever its triage status says, and a
// finding still raised is open or in progress even when marked fixed — until a
// test agrees, "fixed" only means "awaiting re-check".
func (f Finding) State() FixState {
	if !f.StillPresent {
		return StateProvenFixed
	}
	switch f.Status {
	case "fixed":
		return StateAwaitingRecheck
	case "in_progress":
		return StateInProgress
	default:
		return StateOpen
	}
}

// Label is the fix state in plain words.
func (s FixState) Label() string {
	switch s {
	case StateProvenFixed:
		return "Fixed and proven"
	case StateAwaitingRecheck:
		return "Marked fixed, waiting for a re-check"
	case StateInProgress:
		return "Being fixed"
	default:
		return "Open"
	}
}

// FixProof explains, in one sentence, why a proven-fixed finding counts as
// fixed: the re-check that failed to reproduce it, or the later test that no
// longer found it. Empty for a finding that is not proven fixed.
func (f Finding) FixProof() string {
	if f.State() != StateProvenFixed {
		return ""
	}
	if rc, ok := f.LatestRecheck(); ok && !rc.Reproduced {
		s := "Re-checked " + day(rc.At) + ": Ares re-ran the exact test that proved this problem, and it no longer succeeds."
		if f.Proof != "" || f.ProofFingerprint != "" {
			s += " The original proof is kept on file below."
		}
		return s
	}
	if !f.ClearedAt.IsZero() {
		return "Tested again " + day(f.ClearedAt) + ": the same check on the same system no longer finds this problem."
	}
	return "A later test of the same check on the same system no longer finds this problem."
}

// LatestRecheck is the newest re-check of the finding, if any.
func (f Finding) LatestRecheck() (Recheck, bool) {
	if len(f.Rechecks) == 0 {
		return Recheck{}, false
	}
	return f.Rechecks[0], true
}

func day(t time.Time) string {
	if t.IsZero() {
		return "recently"
	}
	return t.UTC().Format("2 Jan 2006")
}
