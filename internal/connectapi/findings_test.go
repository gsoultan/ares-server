// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

func findingTitle(f *aresv1.Finding) string {
	return f.GetData().GetFields()["title"].GetStringValue()
}

func TestListJobs(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Jobs demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	tgt := module.Target{URL: "https://app.example/"}

	h.outcomes.Save(worker.Outcome{
		JobID: "j1", Engagement: id, Module: "webcheck",
		Allowed:    []module.Target{tgt},
		StartedAt:  time.Now().Add(-time.Hour),
		FinishedAt: time.Now().Add(-time.Hour),
		Results:    []module.Result{{Capability: "webcheck", Kind: "finding", Target: tgt, Data: map[string]any{"title": "x"}}},
	})
	h.outcomes.Save(worker.Outcome{
		JobID: "j2", Engagement: id, Module: "recon",
		Allowed:    []module.Target{tgt},
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Error:      "boom",
	})

	resp, err := h.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	jobs := resp.Msg.GetJobs()
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(jobs))
	}
	if jobs[0].GetJobId() != "j2" {
		t.Errorf("jobs must be newest first; got %q first", jobs[0].GetJobId())
	}
	if jobs[0].GetStatus() != "error" || jobs[0].GetError() != "boom" {
		t.Errorf("errored job: status=%q error=%q", jobs[0].GetStatus(), jobs[0].GetError())
	}
	if jobs[1].GetJobId() != "j1" || jobs[1].GetStatus() != "done" {
		t.Errorf("done job: id=%q status=%q", jobs[1].GetJobId(), jobs[1].GetStatus())
	}
	if jobs[1].GetFindings() != 1 || jobs[1].GetAllowed() != 1 {
		t.Errorf("job j1 counts: findings=%d allowed=%d, want 1/1", jobs[1].GetFindings(), jobs[1].GetAllowed())
	}

	// Tenant isolation: another workspace sees nothing of this engagement.
	if _, err := h.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: id, TenantId: "other"})); err == nil {
		t.Error("cross-tenant ListJobs should be refused")
	}
}

func TestListJobsShowsRunning(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Running demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()

	// A dispatched-but-not-yet-completed job shows as running (survives a reload).
	h.pending.add("run-1", id, "webcheck")
	resp, err := h.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(resp.Msg.GetJobs()) != 1 || resp.Msg.GetJobs()[0].GetStatus() != "running" {
		t.Fatalf("expected one running job, got %+v", resp.Msg.GetJobs())
	}

	// Once the outcome lands, the running row is replaced (and pruned), not doubled.
	h.outcomes.Save(worker.Outcome{JobID: "run-1", Engagement: id, Module: "webcheck", StartedAt: time.Now(), FinishedAt: time.Now()})
	resp2, _ := h.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: id}))
	jobs := resp2.Msg.GetJobs()
	if len(jobs) != 1 {
		t.Fatalf("completed job must replace the running row, not duplicate it; got %d", len(jobs))
	}
	if jobs[0].GetStatus() != "done" {
		t.Errorf("status = %q, want done", jobs[0].GetStatus())
	}
	if _, ok := h.pending.snapshot(id)["run-1"]; ok {
		t.Error("completed job should be pruned from the pending set")
	}
}

func TestListFindingsDedupPresenceAndStatus(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Findings demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()

	tgt := module.Target{URL: "https://app.example/"}
	t0 := time.Now().Add(-2 * time.Hour)
	t2 := time.Now()
	mk := func(title, issue string) module.Result {
		return module.Result{Capability: "webcheck", Kind: "finding", Technique: "T1592", Target: tgt,
			Data: map[string]any{"issueKey": issue, "severity": "medium", "title": title}}
	}

	// Run 1: HSTS + CSP. Run 2 (later, same module+target): only HSTS re-raised.
	h.outcomes.Save(worker.Outcome{JobID: "job-1", Engagement: id, Module: "webcheck", Allowed: []module.Target{tgt}, StartedAt: t0,
		Results: []module.Result{mk("Missing HSTS", "missing-hsts"), mk("Missing CSP", "missing-csp")}})
	h.outcomes.Save(worker.Outcome{JobID: "job-2", Engagement: id, Module: "webcheck", Allowed: []module.Target{tgt}, StartedAt: t2,
		Results: []module.Result{mk("Missing HSTS", "missing-hsts")}})

	resp, err := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	fs := resp.Msg.GetFindings()
	if len(fs) != 2 {
		t.Fatalf("HSTS seen twice must dedupe; expected 2 findings, got %d", len(fs))
	}

	var hsts, csp *aresv1.Finding
	for _, f := range fs {
		switch findingTitle(f) {
		case "Missing HSTS":
			hsts = f
		case "Missing CSP":
			csp = f
		}
	}
	if hsts == nil || csp == nil {
		t.Fatal("both findings should be listed")
	}
	if !hsts.GetStillPresent() {
		t.Error("HSTS re-raised in the latest run must be still_present")
	}
	if csp.GetStillPresent() {
		t.Error("CSP not re-raised in a later webcheck run must be marked no longer present")
	}
	if hsts.GetJobId() != "job-2" {
		t.Errorf("HSTS job_id should track the latest run (job-2), got %q", hsts.GetJobId())
	}
	if hsts.GetFoundAt() == "" || hsts.GetLastSeen() == "" || hsts.GetFoundAt() >= hsts.GetLastSeen() {
		t.Errorf("HSTS found_at (%q) must precede last_seen (%q)", hsts.GetFoundAt(), hsts.GetLastSeen())
	}
	if hsts.GetStatus() != "open" {
		t.Errorf("default status = %q, want open", hsts.GetStatus())
	}

	// SetFindingStatus persists.
	upd, err := h.SetFindingStatus(ctx, connect.NewRequest(&aresv1.SetFindingStatusRequest{Id: hsts.GetId(), Status: "fixed", Actor: "alice"}))
	if err != nil {
		t.Fatalf("SetFindingStatus: %v", err)
	}
	if upd.Msg.GetStatus() != "fixed" {
		t.Errorf("returned status = %q, want fixed", upd.Msg.GetStatus())
	}
	resp2, _ := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
	for _, f := range resp2.Msg.GetFindings() {
		if f.GetId() == hsts.GetId() && f.GetStatus() != "fixed" {
			t.Error("status must persist across ListFindings")
		}
	}

	// Validation + isolation.
	if _, err := h.SetFindingStatus(ctx, connect.NewRequest(&aresv1.SetFindingStatusRequest{Id: hsts.GetId(), Status: "bogus"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("invalid status: want InvalidArgument, got %v", err)
	}
	if _, err := h.SetFindingStatus(ctx, connect.NewRequest(&aresv1.SetFindingStatusRequest{Id: "does-not-exist", Status: "open"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("unknown finding: want NotFound, got %v", err)
	}
	// Another workspace cannot touch this finding.
	if _, err := h.SetFindingStatus(ctx, connect.NewRequest(&aresv1.SetFindingStatusRequest{Id: hsts.GetId(), Status: "open", TenantId: "other"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("cross-tenant status set: want NotFound, got %v", err)
	}
}

func TestEngagementCarriesScope(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Scope demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	if _, err := h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{
		Id: id, InScope: []string{"app.example.com"}, Exclude: []string{"10.0.0.0/8"},
	})); err != nil {
		t.Fatalf("SetScope: %v", err)
	}
	got, err := h.GetEngagement(ctx, connect.NewRequest(&aresv1.GetEngagementRequest{Id: id}))
	if err != nil {
		t.Fatalf("GetEngagement: %v", err)
	}
	if in := got.Msg.GetInScope(); len(in) != 1 || in[0] != "app.example.com" {
		t.Errorf("in_scope = %v, want [app.example.com]", in)
	}
	if ex := got.Msg.GetExclude(); len(ex) != 1 || ex[0] != "10.0.0.0/8" {
		t.Errorf("exclude = %v, want [10.0.0.0/8]", ex)
	}
}

// TestJobProgressAndTimeLeft checks that a started-but-unfinished job is listed
// as running with its step count and an honest "estimating" (no history yet),
// and that GetJob reports the same.
func TestJobProgressAndTimeLeft(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "ETA demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	tgt := module.Target{URL: "https://app.example/"}
	h.outcomes.Save(worker.Outcome{
		JobID: "jr", Engagement: id, Module: "recon",
		Allowed:   []module.Target{tgt},
		StartedAt: time.Now().Add(-30 * time.Second),
		Progress:  &module.Progress{Done: 1, Total: 1, TotalMayGrow: true, Step: "recon"},
	})

	resp, err := h.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	jobs := resp.Msg.GetJobs()
	if len(jobs) != 1 || jobs[0].GetStatus() != "running" {
		t.Fatalf("want one running job, got %+v", jobs)
	}
	p := jobs[0].GetProgress()
	if p.GetState() != "estimating" || p.GetRemainingHighSeconds() != 0 {
		t.Errorf("progress = %+v, want estimating with no number", p)
	}
	if p.GetDone() != 1 || !p.GetTotalMayGrow() || p.GetStep() != "recon" {
		t.Errorf("step count not carried: %+v", p)
	}
	if p.GetElapsedSeconds() < 29 {
		t.Errorf("elapsed = %d s, want about 30", p.GetElapsedSeconds())
	}

	got, err := h.GetJob(ctx, connect.NewRequest(&aresv1.GetJobRequest{JobId: "jr"}))
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.Msg.GetStatus() != "running" || got.Msg.GetProgress().GetState() != "estimating" {
		t.Errorf("GetJob status=%q progress=%+v", got.Msg.GetStatus(), got.Msg.GetProgress())
	}
}
