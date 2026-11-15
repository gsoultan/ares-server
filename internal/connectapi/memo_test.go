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

// TestCachedViewsFollowChanges checks that every memoized read path reflects a
// change on the very next call: a new outcome (findings, risk), a job's
// progress (GetJob) and an audit append (GetAudit).
func TestCachedViewsFollowChanges(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "cache"}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetId()
	tgt := module.Target{URL: "https://app.example/"}
	finding := func(title string) module.Result {
		return module.Result{Capability: "webcheck", Kind: "finding", Target: tgt, Technique: "T1190",
			Data: map[string]any{"title": title, "severity": "high"}}
	}
	count := func() int {
		r, err := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return len(r.Msg.GetFindings())
	}

	// A running job, seen twice (cached), then progressing.
	start := time.Now()
	h.outcomes.Save(worker.Outcome{JobID: "j1", Engagement: id, Module: "webcheck", Allowed: []module.Target{tgt},
		StartedAt: start, Results: []module.Result{finding("a")}})
	if n := count(); n != 1 {
		t.Fatalf("findings: want 1, got %d", n)
	}
	if n := count(); n != 1 {
		t.Fatalf("findings (cached): want 1, got %d", n)
	}
	job := func() *aresv1.JobOutcome {
		r, err := h.GetJob(ctx, connect.NewRequest(&aresv1.GetJobRequest{JobId: "j1"}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	if got := job(); got.GetStatus() != "running" || len(got.GetResults()) != 1 {
		t.Fatalf("job: want running with 1 result, got %s/%d", got.GetStatus(), len(got.GetResults()))
	}
	h.outcomes.Save(worker.Outcome{JobID: "j1", Engagement: id, Module: "webcheck", Allowed: []module.Target{tgt},
		StartedAt: start, FinishedAt: time.Now(), Results: []module.Result{finding("a"), finding("b")}})
	if got := job(); got.GetStatus() != "done" || len(got.GetResults()) != 2 {
		t.Fatalf("job after progress: want done with 2 results, got %s/%d", got.GetStatus(), len(got.GetResults()))
	}
	if n := count(); n != 2 {
		t.Fatalf("findings after a new result: want 2, got %d", n)
	}
	risk, err := h.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{Id: id}))
	if err != nil {
		t.Fatal(err)
	}
	h.outcomes.Save(worker.Outcome{JobID: "j2", Engagement: id, Module: "webcheck", Allowed: []module.Target{tgt},
		StartedAt: time.Now(), FinishedAt: time.Now(), Results: []module.Result{finding("c")}})
	risk2, err := h.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{Id: id}))
	if err != nil {
		t.Fatal(err)
	}
	if risk.Msg == risk2.Msg {
		t.Error("risk picture must be rebuilt after a new outcome")
	}

	audit := func() int {
		r, err := h.GetAudit(ctx, connect.NewRequest(&aresv1.GetAuditRequest{Id: id}))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Msg.GetValid() {
			t.Fatal("audit must verify")
		}
		return len(r.Msg.GetEntries())
	}
	before := audit()
	eng, _ := h.store.Get(id)
	eng.Audit.Append("op", "note", "", "")
	if after := audit(); after != before+1 {
		t.Fatalf("audit after append: want %d entries, got %d", before+1, after)
	}
}
