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

func findingByTitle(t *testing.T, fs []*aresv1.Finding, title string) *aresv1.Finding {
	t.Helper()
	for _, f := range fs {
		if findingTitle(f) == title {
			return f
		}
	}
	t.Fatalf("no finding titled %q", title)
	return nil
}

func TestListFindingsReturnsRecheckHistoryNewestFirst(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	mk := func(name string) string {
		created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: name}))
		if err != nil {
			t.Fatalf("CreateEngagement: %v", err)
		}
		return created.Msg.GetId()
	}
	id, other := mk("History"), mk("Other")

	tgt := module.Target{Host: "db.example"}
	t0 := time.Now().Add(-3 * time.Hour)
	res := module.Result{Capability: "datastoreexpose", Kind: "finding", Target: tgt,
		Data:  map[string]any{"title": "Redis answers without a password"},
		Proof: &module.Proof{V: 1, Kind: "answer", Claim: "redis-noauth", Fingerprint: "sha256:aaa"}}
	h.outcomes.Save(worker.Outcome{JobID: "job-1", Engagement: id, Module: "datastoreexpose",
		StartedAt: t0, FinishedAt: t0.Add(time.Minute), Results: []module.Result{res}})

	resp, err := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	f := findingByTitle(t, resp.Msg.GetFindings(), "Redis answers without a password")
	if len(f.GetRechecks()) != 0 {
		t.Fatalf("no re-check ran yet, got %d", len(f.GetRechecks()))
	}
	fid := f.GetId()

	t1 := time.Now().Add(-2 * time.Hour)
	t2 := time.Now().Add(-1 * time.Hour)
	h.outcomes.Save(worker.Outcome{JobID: "rc-1", Engagement: id, Module: "datastoreexpose",
		StartedAt: t1, FinishedAt: t1.Add(time.Second),
		Recheck: &worker.RecheckResult{FindingID: fid, Claim: "redis-noauth", Reproduced: true, Fingerprint: "sha256:bbb"}})
	h.outcomes.Save(worker.Outcome{JobID: "rc-2", Engagement: id, Module: "datastoreexpose",
		StartedAt: t2, FinishedAt: t2.Add(time.Second),
		Recheck: &worker.RecheckResult{FindingID: fid, Claim: "redis-noauth", Reproduced: false}})
	// Still running: not part of the history yet.
	h.outcomes.Save(worker.Outcome{JobID: "rc-3", Engagement: id, Module: "datastoreexpose", StartedAt: time.Now(),
		Recheck: &worker.RecheckResult{FindingID: fid, Claim: "redis-noauth", Reproduced: true}})
	// Another engagement naming the same finding id must not attach to it.
	h.outcomes.Save(worker.Outcome{JobID: "rc-x", Engagement: other, Module: "datastoreexpose",
		StartedAt: t2, FinishedAt: t2.Add(time.Second),
		Recheck: &worker.RecheckResult{FindingID: fid, Claim: "redis-noauth", Reproduced: true, Fingerprint: "sha256:evil"}})

	// Both the one-engagement and the whole-workspace views carry the history.
	for _, engID := range []string{id, ""} {
		resp, err = h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: engID}))
		if err != nil {
			t.Fatalf("ListFindings(%q): %v", engID, err)
		}
		f = findingByTitle(t, resp.Msg.GetFindings(), "Redis answers without a password")
		got := f.GetRechecks()
		if len(got) != 2 {
			t.Fatalf("ListFindings(%q): want 2 finished re-checks from this engagement, got %+v", engID, got)
		}
		if got[0].GetJobId() != "rc-2" || got[0].GetReproduced() || got[0].GetFingerprint() != "" {
			t.Errorf("newest re-check = %+v, want rc-2 not reproduced", got[0])
		}
		if got[1].GetJobId() != "rc-1" || !got[1].GetReproduced() || got[1].GetFingerprint() != "sha256:bbb" {
			t.Errorf("older re-check = %+v, want rc-1 reproduced with sha256:bbb", got[1])
		}
		if got[0].GetAt() == "" || got[0].GetAt() <= got[1].GetAt() {
			t.Errorf("re-checks must be newest first with times, got %q then %q", got[0].GetAt(), got[1].GetAt())
		}
	}

	// Another workspace sees none of it.
	resp, err = h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{TenantId: "other"}))
	if err != nil {
		t.Fatalf("ListFindings(other tenant): %v", err)
	}
	if n := len(resp.Msg.GetFindings()); n != 0 {
		t.Fatalf("another workspace must see no findings, got %d", n)
	}
}

// TestRecheckFindingRecordsHistory runs a real re-check through the worker pool
// and checks the finding's history picks it up.
func TestRecheckFindingRecordsHistory(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Recheck"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	if _, err := h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{Id: id, InScope: []string{"127.0.0.1"}})); err != nil {
		t.Fatalf("SetScope: %v", err)
	}
	if _, err := h.Authorize(ctx, connect.NewRequest(&aresv1.AuthorizeRequest{Id: id, Document: "auth.pdf", ApprovedBy: "lead"})); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	tgt := module.Target{Host: "127.0.0.1"}
	t0 := time.Now().Add(-time.Hour)
	h.outcomes.Save(worker.Outcome{JobID: "job-1", Engagement: id, Module: "echo", StartedAt: t0, FinishedAt: t0,
		Results: []module.Result{{Capability: "echo", Kind: "finding", Target: tgt,
			Data: map[string]any{"title": "Echo proven"},
			Proof: &module.Proof{V: 1, Kind: "answer", Claim: "echo-claim", Fingerprint: "sha256:aaa",
				Recheck: &module.Recheck{Module: "echo", Target: tgt}}}}})

	list, err := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	fid := findingByTitle(t, list.Msg.GetFindings(), "Echo proven").GetId()

	rc, err := h.RecheckFinding(ctx, connect.NewRequest(&aresv1.RecheckFindingRequest{FindingId: fid}))
	if err != nil {
		t.Fatalf("RecheckFinding: %v", err)
	}
	if !rc.Msg.GetRechecked() || rc.Msg.GetJobId() == "" {
		t.Fatalf("re-check did not start: %+v", rc.Msg)
	}

	var checks []*aresv1.ProofCheck
	for i := 0; i < 200 && len(checks) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
		list, err = h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
		if err != nil {
			t.Fatalf("ListFindings: %v", err)
		}
		checks = findingByTitle(t, list.Msg.GetFindings(), "Echo proven").GetRechecks()
	}
	if len(checks) != 1 {
		t.Fatalf("want the re-check in the finding's history, got %+v", checks)
	}
	// echo raises a finding without the proof's claim, so it did not reproduce.
	if checks[0].GetJobId() != rc.Msg.GetJobId() || checks[0].GetReproduced() {
		t.Errorf("re-check = %+v, want job %s not reproduced", checks[0], rc.Msg.GetJobId())
	}
}
