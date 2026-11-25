// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"strings"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
)

// proofMod emits one finding per target whose proof carries a fixed claim.
type proofMod struct{ claim string }

func (proofMod) Name() string { return "proofmod" }
func (m proofMod) Run(_ context.Context, _ module.Scope, targets []module.Target, out chan<- module.Result) error {
	for _, t := range targets {
		out <- module.Result{Capability: "proofmod", Kind: "finding", Target: t,
			Data:  map[string]any{"title": "Proven"},
			Proof: &module.Proof{V: 1, Kind: "answer", Claim: m.claim, Fingerprint: "sha256:" + m.claim + "-fp"}}
	}
	return nil
}

func recheckSetup(t *testing.T, claim string) (*Processor, *engagement.Engagement) {
	t.Helper()
	reg := module.NewRegistry()
	if err := reg.Register(proofMod{claim: claim}); err != nil {
		t.Fatalf("register: %v", err)
	}
	store := engagement.NewMemStore()
	proc := NewProcessor(reg, store)
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	if err := eng.Authorize(engagement.Authorization{Document: "a.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return proc, eng
}

func recheckJob(engID, claim string, host string) queue.Job {
	return queue.Job{
		ID: "rc-1", EngagementID: engID, Module: "proofmod", Actor: "alice",
		Targets: []module.Target{{Host: host}},
		Recheck: &queue.Recheck{FindingID: "finding-1", Claim: claim},
	}
}

func TestRecheckRecordsReproduced(t *testing.T) {
	proc, eng := recheckSetup(t, "redis-noauth")
	out := proc.Process(context.Background(), recheckJob(eng.ID, "redis-noauth", "db.example.com"))
	if out.Error != "" {
		t.Fatalf("job errored: %s", out.Error)
	}
	rc := out.Recheck
	if rc == nil || !rc.Reproduced || rc.FindingID != "finding-1" || rc.Fingerprint != "sha256:redis-noauth-fp" {
		t.Fatalf("recheck = %+v, want reproduced with the new fingerprint", rc)
	}
	found := false
	for _, e := range eng.Audit.Entries() {
		if e.Action == "proof-rechecked" && e.Target == "finding-1" &&
			strings.Contains(e.Detail, "reproduced=true") && strings.Contains(e.Detail, "sha256:redis-noauth-fp") {
			found = true
		}
	}
	if !found {
		t.Error("a re-check must be anchored in the audit chain as proof-rechecked")
	}
	if err := eng.Audit.Verify(); err != nil {
		t.Fatalf("audit chain must stay valid: %v", err)
	}
}

func TestRecheckDifferentClaimIsNotReproduced(t *testing.T) {
	proc, eng := recheckSetup(t, "something-else")
	out := proc.Process(context.Background(), recheckJob(eng.ID, "redis-noauth", "db.example.com"))
	if out.Recheck == nil || out.Recheck.Reproduced || out.Recheck.Fingerprint != "" {
		t.Fatalf("recheck = %+v, want not reproduced and no fingerprint", out.Recheck)
	}
}

func TestRecheckWithEveryTargetRefusedRecordsNothing(t *testing.T) {
	proc, eng := recheckSetup(t, "redis-noauth")
	out := proc.Process(context.Background(), recheckJob(eng.ID, "redis-noauth", "outside.test"))
	if len(out.Allowed) != 0 {
		t.Fatalf("allowed = %+v, want none", out.Allowed)
	}
	if out.Recheck != nil {
		t.Fatalf("a run that touched no target proves nothing; recheck = %+v", out.Recheck)
	}
	for _, e := range eng.Audit.Entries() {
		if e.Action == "proof-rechecked" {
			t.Fatal("no proof-rechecked entry for a run that touched no target")
		}
	}
}

func TestPlainJobCarriesNoRecheck(t *testing.T) {
	proc, eng := recheckSetup(t, "redis-noauth")
	job := recheckJob(eng.ID, "redis-noauth", "db.example.com")
	job.Recheck = nil
	if out := proc.Process(context.Background(), job); out.Recheck != nil {
		t.Fatalf("a normal job must not record a re-check, got %+v", out.Recheck)
	}
}

func TestRecheckSurvivesOutcomeCodec(t *testing.T) {
	in := Outcome{JobID: "rc-1", Engagement: "e", Recheck: &RecheckResult{FindingID: "f", Claim: "c", Reproduced: true, Fingerprint: "sha256:x"}}
	b, err := EncodeOutcome(in, nil, "")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeOutcome(b, nil, "", "rc-1")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Recheck == nil || *got.Recheck != *in.Recheck {
		t.Fatalf("recheck after round trip = %+v, want %+v", got.Recheck, in.Recheck)
	}
}
