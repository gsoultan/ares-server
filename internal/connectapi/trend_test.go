// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

func TestGetRiskTrendFallsWhenAFixIsProven(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Trend"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()

	empty, err := h.GetRiskTrend(ctx, connect.NewRequest(&aresv1.GetRiskTrendRequest{}))
	if err != nil {
		t.Fatalf("GetRiskTrend (empty): %v", err)
	}
	if len(empty.Msg.GetPoints()) != 0 || empty.Msg.GetRating() != "none" {
		t.Fatalf("no runs yet: %+v", empty.Msg)
	}

	tgt := module.Target{Host: "db.example"}
	t0 := time.Now().Add(-2 * time.Hour)
	h.outcomes.Save(worker.Outcome{JobID: "j1", Engagement: id, Module: "datastoreexpose", Allowed: []module.Target{tgt},
		StartedAt: t0, FinishedAt: t0.Add(time.Minute),
		Results: []module.Result{{Capability: "datastoreexpose", Kind: "finding", Target: tgt,
			Data: map[string]any{"severity": "critical", "title": "Redis answers without a password"}}}})
	// The same check on the same target, later, no longer raises it.
	h.outcomes.Save(worker.Outcome{JobID: "j2", Engagement: id, Module: "datastoreexpose", Allowed: []module.Target{tgt},
		StartedAt: t0.Add(time.Hour), FinishedAt: t0.Add(time.Hour + time.Minute)})

	tr, err := h.GetRiskTrend(ctx, connect.NewRequest(&aresv1.GetRiskTrendRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("GetRiskTrend: %v", err)
	}
	pts := tr.Msg.GetPoints()
	if len(pts) != 2 {
		t.Fatalf("points = %d, want 2", len(pts))
	}
	if pts[0].GetCritical() != 1 || pts[0].GetScore() == 0 || pts[0].GetEngagementName() != "Trend" {
		t.Errorf("first point = %+v", pts[0])
	}
	if pts[1].GetScore() != 0 || pts[1].GetFixedFindings() != 1 {
		t.Errorf("second point = %+v, want score 0 with one proven fix", pts[1])
	}
	if tr.Msg.GetScore() != 0 || tr.Msg.GetFirstScore() != pts[0].GetScore() || tr.Msg.GetRating() != "none" {
		t.Errorf("summary = score %d first %d rating %q", tr.Msg.GetScore(), tr.Msg.GetFirstScore(), tr.Msg.GetRating())
	}

	// Tenant isolation: another workspace sees none of it.
	if _, err := h.GetRiskTrend(ctx, connect.NewRequest(&aresv1.GetRiskTrendRequest{
		EngagementId: id, TenantId: "someone-else",
	})); err == nil {
		t.Error("cross-tenant GetRiskTrend on an engagement should be refused")
	}
	other, err := h.GetRiskTrend(ctx, connect.NewRequest(&aresv1.GetRiskTrendRequest{TenantId: "someone-else"}))
	if err != nil {
		t.Fatalf("GetRiskTrend (other workspace): %v", err)
	}
	if len(other.Msg.GetPoints()) != 0 {
		t.Errorf("another workspace's trend leaked %d point(s)", len(other.Msg.GetPoints()))
	}
}

func TestGenerateReportShowsTriageStatus(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Report"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	tgt := module.Target{URL: "https://shop.example"}
	h.outcomes.Save(worker.Outcome{JobID: "j1", Engagement: id, Module: "headerprobe", Allowed: []module.Target{tgt},
		StartedAt: time.Now().Add(-time.Hour), FinishedAt: time.Now(),
		Results: []module.Result{{Capability: "headerprobe", Kind: "finding", Target: tgt,
			Data: map[string]any{"severity": "medium", "title": "Missing security headers"}}}})

	list, err := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{EngagementId: id}))
	if err != nil || len(list.Msg.GetFindings()) != 1 {
		t.Fatalf("ListFindings: %v (%d)", err, len(list.Msg.GetFindings()))
	}
	if _, err := h.SetFindingStatus(ctx, connect.NewRequest(&aresv1.SetFindingStatusRequest{
		Id: list.Msg.GetFindings()[0].GetId(), Status: "fixed",
	})); err != nil {
		t.Fatalf("SetFindingStatus: %v", err)
	}

	rep, err := h.GenerateReport(ctx, connect.NewRequest(&aresv1.GenerateReportRequest{Id: id, Format: "md"}))
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	if md := string(rep.Msg.GetData()); !strings.Contains(md, "Marked fixed, waiting for a re-check") {
		t.Errorf("the report should carry the finding's triage status:\n%s", md)
	}
}
