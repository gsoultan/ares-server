// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package worker runs jobs. It is the choke point where the permission gate is
// enforced: before any module sees a target, the worker checks it against the
// engagement's scope and records every denial. A module also re-checks the
// gate, so there are two independent barriers between a job and a target.
package worker

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/remediation"
)

// Denial records a target that the gate refused.
type Denial struct {
	Target module.Target `json:"target"`
	Reason string        `json:"reason"`
}

// Outcome is the full record of one processed job.
type Outcome struct {
	JobID      string          `json:"jobId"`
	Engagement string          `json:"engagement"`
	Module     string          `json:"module"`
	Allowed    []module.Target `json:"allowed"`
	Denied     []Denial        `json:"denied"`
	Results    []module.Result `json:"results"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt time.Time       `json:"finishedAt"`
	// CurrentCapability names the capability whose result was most recently
	// emitted while the job is still running; it is cleared when the job finishes.
	// It lets a live view show forward motion ("running headerprobe…").
	CurrentCapability string `json:"currentCapability,omitempty"`
}

// Running reports whether this outcome is an in-flight snapshot (the job has not
// finished yet). A live view uses it to distinguish partial from final results.
func (o Outcome) Running() bool { return o.FinishedAt.IsZero() }

// OutcomeStore keeps job outcomes for the API to read back.
type OutcomeStore interface {
	Save(Outcome)
	Get(jobID string) (Outcome, bool)
	// ByEngagement returns every recorded outcome for an engagement, so a report
	// can aggregate all of its findings.
	ByEngagement(engagementID string) []Outcome
}

// Processor runs a single job to completion. It holds no per-job state, so it
// is safe to share across worker goroutines.
type Processor struct {
	reg   *module.Registry
	store engagement.Store
}

// NewProcessor wires a processor to the module registry and engagement store.
func NewProcessor(reg *module.Registry, store engagement.Store) *Processor {
	return &Processor{reg: reg, store: store}
}

// Process runs one job: it loads the engagement, refuses if it cannot run,
// filters targets through the scope gate (logging each denial), runs the
// module on the survivors, and records results in the audit log.
func (p *Processor) Process(ctx context.Context, job queue.Job) Outcome {
	return p.ProcessWithProgress(ctx, job, nil)
}

// ProcessWithProgress runs one job and, if progress is non-nil, publishes an
// in-flight snapshot of the outcome as the gate decides and as each result is
// emitted. Each snapshot is an independent copy, safe to hand to a concurrent
// reader, so a client polling GetJob sees allowed/denied targets and results
// accumulate live. progress is never called with the final outcome — the caller
// records that itself.
func (p *Processor) ProcessWithProgress(ctx context.Context, job queue.Job, progress func(Outcome)) Outcome {
	out := Outcome{
		JobID:      job.ID,
		Engagement: job.EngagementID,
		Module:     job.Module,
		StartedAt:  time.Now(),
	}
	finish := func() Outcome {
		out.FinishedAt = time.Now()
		out.CurrentCapability = ""
		return out
	}
	// snapshot publishes an independent copy of the current (in-flight) outcome.
	snapshot := func() {
		if progress == nil {
			return
		}
		cp := out
		cp.Results = append([]module.Result(nil), out.Results...)
		cp.Allowed = append([]module.Target(nil), out.Allowed...)
		cp.Denied = append([]Denial(nil), out.Denied...)
		progress(cp)
	}

	eng, ok := p.store.Get(job.EngagementID)
	if !ok {
		out.Error = fmt.Sprintf("engagement %q not found", job.EngagementID)
		return finish()
	}
	// Persist the engagement's audit trail after the job: every path below
	// appends to eng.Audit, and a persistent store needs those flushed to disk.
	defer func() { _ = p.store.Save(eng) }()
	if ok, reason := eng.CanRun(); !ok {
		eng.Audit.Append(job.Actor, "job-refused", job.Module, reason)
		out.Error = reason
		return finish()
	}
	mod, ok := p.reg.Get(job.Module)
	if !ok {
		eng.Audit.Append(job.Actor, "job-refused", job.Module, "unknown module")
		out.Error = fmt.Sprintf("unknown module %q", job.Module)
		return finish()
	}
	// Apply per-job parameters to modules that accept them. The returned,
	// configured instance is used for this job only.
	if len(job.Params) > 0 {
		if cfg, isCfg := mod.(module.Configurable); isCfg {
			configured, err := cfg.WithParams(job.Params)
			if err != nil {
				eng.Audit.Append(job.Actor, "job-refused", job.Module, "bad params: "+err.Error())
				out.Error = fmt.Sprintf("bad params for %q: %v", job.Module, err)
				return finish()
			}
			mod = configured
		}
	}

	// The permission gate, enforced by the engine.
	now := time.Now()
	allowed := make([]module.Target, 0, len(job.Targets))
	for _, t := range job.Targets {
		if ok, reason := eng.Scope.AllowAt(t, now); ok {
			allowed = append(allowed, t)
		} else {
			out.Denied = append(out.Denied, Denial{Target: t, Reason: reason})
			eng.Audit.Append(job.Actor, "scope-denied", t.String(), reason)
		}
	}
	out.Allowed = allowed

	eng.Audit.Append(job.Actor, "job-started", job.Module,
		fmt.Sprintf("%d allowed, %d denied", len(allowed), len(out.Denied)))
	// Publish the gate decision immediately: a live view shows allowed/denied
	// targets before the first result lands.
	snapshot()

	// Run the module, collecting results off a channel.
	results := make(chan module.Result, 64)
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for r := range results {
			// Pair every finding with the blue team's structured answer (how to
			// fix / prevent / detect / verify + ATT&CK mitigations), derived from
			// its technique and issue key. One seam covers every module.
			if r.Kind == "finding" {
				remediation.Enrich(r.Data, r.Technique)
			}
			out.Results = append(out.Results, r)
			out.CurrentCapability = r.Capability
			// Publish partial results as they arrive. Only this goroutine mutates
			// out during the run, so the snapshot copy is race-free.
			snapshot()
		}
	}()

	err := mod.Run(ctx, eng.Scope, allowed, results)
	close(results)
	collectWG.Wait()

	if err != nil {
		out.Error = err.Error()
		eng.Audit.Append(job.Actor, "job-error", job.Module, err.Error())
	}
	for _, r := range out.Results {
		// Forensic evidence is anchored into the hash-chained audit trail with its
		// SHA-256 and a distinct action, which is what makes the chain of custody
		// tamper-evident: the ordered record of what was ingested cannot be altered
		// without breaking the chain.
		if r.Kind == "evidence" {
			sha, _ := r.Data["sha256"].(string)
			name, _ := r.Data["name"].(string)
			eng.Audit.Append(job.Actor, "evidence-ingested", r.Target.String(),
				fmt.Sprintf("name=%s sha256=%s", name, sha))
			continue
		}
		// A finding carrying structured proof anchors its fingerprint into the
		// hash-chained audit trail, so the recorded evidence cannot be altered
		// without breaking the chain. The downloadable proof artifact references
		// this entry's seq and hash.
		if r.Kind == "finding" && r.Proof != nil {
			eng.Audit.Append(job.Actor, "proof-recorded", r.Target.String(),
				fmt.Sprintf("kind=%s claim=%s %s", r.Proof.Kind, r.Proof.Claim, r.Proof.Fingerprint))
		}
		eng.Audit.Append(job.Actor, "result", r.Target.String(),
			fmt.Sprintf("%s/%s", r.Capability, r.Kind))
	}
	eng.Audit.Append(job.Actor, "job-finished", job.Module,
		fmt.Sprintf("%d results", len(out.Results)))
	return finish()
}

// Pool consumes jobs from a queue with a fixed number of workers and saves each
// outcome.
type Pool struct {
	proc     *Processor
	outcomes OutcomeStore
	workers  int
}

// NewPool builds a pool of n workers.
func NewPool(proc *Processor, outcomes OutcomeStore, n int) *Pool {
	if n < 1 {
		n = 1
	}
	return &Pool{proc: proc, outcomes: outcomes, workers: n}
}

// Run starts the workers and blocks until ctx is cancelled or jobs closes.
func (p *Pool) Run(ctx context.Context, jobs <-chan queue.Job) {
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					// Save in-flight snapshots so GetJob can serve live partial
					// results, then save the final outcome.
					p.outcomes.Save(p.proc.ProcessWithProgress(ctx, job, p.outcomes.Save))
				}
			}
		}()
	}
	wg.Wait()
}

// MemOutcomes is an in-memory OutcomeStore, safe for concurrent use.
type MemOutcomes struct {
	mu sync.Mutex
	m  map[string]Outcome
}

// NewMemOutcomes returns an empty outcome store.
func NewMemOutcomes() *MemOutcomes { return &MemOutcomes{m: make(map[string]Outcome)} }

// Save stores an outcome by job id.
func (s *MemOutcomes) Save(o Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[o.JobID] = o
}

// Get returns an outcome by job id.
func (s *MemOutcomes) Get(jobID string) (Outcome, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.m[jobID]
	return o, ok
}

// ByEngagement returns the outcomes for one engagement, newest first.
func (s *MemOutcomes) ByEngagement(engagementID string) []Outcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Outcome, 0)
	for _, o := range s.m {
		if o.Engagement == engagementID {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}
