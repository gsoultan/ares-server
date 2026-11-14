// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/engine"
	"github.com/gsoultan/ares/module"
)

// engineModule returns one module from the engine's full registry, so a test
// can run it on its own.
func engineModule(t *testing.T, name string) module.Module {
	t.Helper()
	full, err := engine.New(engine.Options{})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	m, ok := full.Get(name)
	if !ok {
		t.Fatalf("engine has no module %q", name)
	}
	return m
}

func setup(t *testing.T) (*Processor, engagement.Store) {
	t.Helper()
	reg := module.NewRegistry()
	if err := reg.Register(engineModule(t, "noop")); err != nil {
		t.Fatalf("register: %v", err)
	}
	store := engagement.NewMemStore()
	return NewProcessor(reg, store), store
}

// mustCreate makes a draft engagement in the default workspace or fails the test.
func mustCreate(t *testing.T, store engagement.Store) *engagement.Engagement {
	t.Helper()
	eng, err := store.Create("", "test")
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	return eng
}

func TestRefusesUnauthorizedEngagement(t *testing.T) {
	proc, store := setup(t)
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")

	out := proc.Process(context.Background(), queue.Job{
		ID: "j1", EngagementID: eng.ID, Module: "noop", Actor: "op",
		Targets: []module.Target{{Host: "example.com"}},
	})
	if out.Error == "" {
		t.Fatal("an unauthorized engagement must refuse the job")
	}
	if len(out.Results) != 0 {
		t.Fatal("no results should be produced when refused")
	}
}

func TestScopeGateFiltersAndLogs(t *testing.T) {
	proc, store := setup(t)
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	_ = eng.Scope.AddExclusion("secret.example.com")
	if err := eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	out := proc.Process(context.Background(), queue.Job{
		ID: "j2", EngagementID: eng.ID, Module: "noop", Actor: "op",
		Targets: []module.Target{
			{Host: "www.example.com"},    // allowed
			{Host: "secret.example.com"}, // excluded
			{Host: "elsewhere.org"},      // not in scope
		},
	})
	if len(out.Allowed) != 1 {
		t.Fatalf("want 1 allowed target, got %d", len(out.Allowed))
	}
	if len(out.Denied) != 2 {
		t.Fatalf("want 2 denied targets, got %d", len(out.Denied))
	}
	if len(out.Results) != 1 {
		t.Fatalf("noop should emit 1 result for the allowed target, got %d", len(out.Results))
	}
	if err := eng.Audit.Verify(); err != nil {
		t.Fatalf("audit chain must stay valid: %v", err)
	}
	// The denials must appear in the audit trail.
	denied := 0
	for _, e := range eng.Audit.Entries() {
		if e.Action == "scope-denied" {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("want 2 scope-denied audit entries, got %d", denied)
	}
}

func TestUnknownModuleRefused(t *testing.T) {
	proc, store := setup(t)
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	_ = eng.Authorize(engagement.Authorization{Document: "a.pdf", ApprovedBy: "lead"})

	out := proc.Process(context.Background(), queue.Job{
		ID: "j3", EngagementID: eng.ID, Module: "does-not-exist", Actor: "op",
		Targets: []module.Target{{Host: "example.com"}},
	})
	if out.Error == "" {
		t.Fatal("an unknown module must be refused")
	}
}

// TestEvidenceAnchoredInAuditChain is the chain-of-custody guarantee: ingesting
// a forensic artifact records its SHA-256 as a distinct, hash-chained audit entry
// that cannot be altered without breaking the chain. A target-free module, it
// needs no scope — only the engagement's authorization.
func TestEvidenceAnchoredInAuditChain(t *testing.T) {
	reg := module.NewRegistry()
	if err := reg.Register(engineModule(t, "evidence")); err != nil {
		t.Fatalf("register evidence: %v", err)
	}
	store := engagement.NewMemStore()
	proc := NewProcessor(reg, store)
	eng := mustCreate(t, store)
	if err := eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	out := proc.Process(context.Background(), queue.Job{
		ID: "ev-1", EngagementID: eng.ID, Module: "evidence", Actor: "analyst",
		Params: json.RawMessage(`{"items":[{"name":"ransom-note.txt","text":"pay up","source":"host-07"}]}`),
	})
	if out.Error != "" {
		t.Fatalf("evidence job errored: %s", out.Error)
	}
	if len(out.Results) != 1 || out.Results[0].Kind != "evidence" {
		t.Fatalf("want 1 evidence result, got %+v", out.Results)
	}
	sha, _ := out.Results[0].Data["sha256"].(string)
	if sha == "" {
		t.Fatal("evidence result carries no sha256")
	}

	// A distinct evidence-ingested entry must carry the hash into the chain.
	found := false
	for _, e := range eng.Audit.Entries() {
		if e.Action == "evidence-ingested" && strings.Contains(e.Detail, sha) {
			found = true
		}
	}
	if !found {
		t.Error("evidence SHA-256 must be anchored into the audit chain as an evidence-ingested entry")
	}
	// The chain of custody is only meaningful if the chain itself verifies.
	if err := eng.Audit.Verify(); err != nil {
		t.Fatalf("audit chain must stay valid: %v", err)
	}
}

func TestPoolProcessesFromQueue(t *testing.T) {
	proc, store := setup(t)
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	_ = eng.Authorize(engagement.Authorization{Document: "a.pdf", ApprovedBy: "lead"})

	outcomes := NewMemOutcomes()
	pool := NewPool(proc, outcomes, 2)
	q := queue.New(4)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pool.Run(ctx, q.C()); close(done) }()

	q.Enqueue(queue.Job{
		ID: "job-a", EngagementID: eng.ID, Module: "noop", Actor: "op",
		Targets: []module.Target{{Host: "www.example.com"}},
	})

	// Wait briefly for the outcome to appear.
	deadline := time.After(2 * time.Second)
	for {
		if o, ok := outcomes.Get("job-a"); ok {
			if len(o.Results) != 1 {
				t.Fatalf("want 1 result, got %d", len(o.Results))
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the pool to process the job")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// multiMod emits a fixed number of results, one per capability name, so a
// progress test can observe snapshots accumulate.
type multiMod struct{ n int }

func (multiMod) Name() string { return "multi" }
func (m multiMod) Run(_ context.Context, _ module.Scope, targets []module.Target, out chan<- module.Result) error {
	for i := 0; i < m.n; i++ {
		t := module.Target{Host: "example.com"}
		if len(targets) > 0 {
			t = targets[0]
		}
		out <- module.Result{Capability: "multi", Kind: "info", Target: t,
			Data: map[string]any{"i": i}}
	}
	return nil
}

func TestProcessWithProgressPublishesPartials(t *testing.T) {
	reg := module.NewRegistry()
	if err := reg.Register(multiMod{n: 4}); err != nil {
		t.Fatalf("register: %v", err)
	}
	store := engagement.NewMemStore()
	proc := NewProcessor(reg, store)
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	if err := eng.Authorize(engagement.Authorization{Document: "a.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	var snaps []Outcome
	final := proc.ProcessWithProgress(context.Background(), queue.Job{
		ID: "jp", EngagementID: eng.ID, Module: "multi", Actor: "op",
		Targets: []module.Target{{Host: "www.example.com"}},
	}, func(o Outcome) { snaps = append(snaps, o) })

	// One snapshot at the gate (0 results) plus one per result (1..4).
	if len(snaps) != 5 {
		t.Fatalf("want 5 snapshots (gate + 4 results), got %d", len(snaps))
	}
	// Every snapshot must be in-flight (running) and show non-decreasing results.
	last := -1
	for i, s := range snaps {
		if !s.Running() {
			t.Errorf("snapshot %d must be running (FinishedAt zero)", i)
		}
		if len(s.Results) < last {
			t.Errorf("snapshot %d results went backwards: %d < %d", i, len(s.Results), last)
		}
		last = len(s.Results)
	}
	if snaps[0].Results != nil && len(snaps[0].Results) != 0 {
		t.Errorf("gate snapshot should have 0 results, got %d", len(snaps[0].Results))
	}
	if len(snaps[len(snaps)-1].Results) != 4 {
		t.Errorf("last snapshot should have 4 results, got %d", len(snaps[len(snaps)-1].Results))
	}
	// A partial snapshot must not mutate when the job continues: the stored copy
	// is independent of the final slice.
	if len(snaps[2].Results) == len(final.Results) {
		t.Errorf("an early snapshot should not equal the final result count")
	}
	// The final outcome is done (finished) with the current capability cleared.
	if final.Running() {
		t.Error("final outcome must be finished")
	}
	if final.CurrentCapability != "" {
		t.Errorf("final CurrentCapability should be cleared, got %q", final.CurrentCapability)
	}
	if len(final.Results) != 4 {
		t.Errorf("final should have 4 results, got %d", len(final.Results))
	}
}
