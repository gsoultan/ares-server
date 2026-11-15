// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

// seedOutcomes gives one workspace `engs` engagements, each with `jobs`
// finished jobs of `results` findings, plus `noise` jobs in other engagements
// of another workspace, so a lookup that scans every outcome pays for them.
func seedOutcomes(b *testing.B, h *Handler, engs, jobs, results, noise int) string {
	b.Helper()
	ctx := context.Background()
	var first string
	for e := 0; e < engs; e++ {
		created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: fmt.Sprintf("e%d", e)}))
		if err != nil {
			b.Fatal(err)
		}
		id := created.Msg.GetId()
		if first == "" {
			first = id
		}
		for j := 0; j < jobs; j++ {
			o := worker.Outcome{JobID: fmt.Sprintf("%s-%d", id, j), Engagement: id, Module: "webcheck",
				StartedAt: time.Now().Add(-time.Duration(j) * time.Minute), FinishedAt: time.Now()}
			for r := 0; r < results; r++ {
				tgt := module.Target{URL: fmt.Sprintf("https://app.example/p%d", r)}
				o.Allowed = append(o.Allowed, tgt)
				o.Results = append(o.Results, module.Result{Capability: "webcheck", Kind: "finding", Target: tgt,
					Technique: "T1190", Data: map[string]any{"title": "Missing header", "severity": "medium", "evidence": "x-frame-options absent"}})
			}
			h.outcomes.Save(o)
		}
	}
	for n := 0; n < noise; n++ {
		h.outcomes.Save(worker.Outcome{JobID: fmt.Sprintf("noise-%d", n), Engagement: "other", Module: "webcheck", StartedAt: time.Now()})
	}
	return first
}

// BenchmarkListFindingsWorkspace is the findings page for a workspace with 10
// engagements x 10 jobs x 50 findings, on a server holding 10k other outcomes.
func BenchmarkListFindingsWorkspace(b *testing.B) {
	h := newTestHandler(b)
	seedOutcomes(b, h, 10, 10, 50, 10000)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{})); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetRiskPicture is one engagement's risk card, which looks up that
// engagement's outcomes among every outcome the server holds.
func BenchmarkGetRiskPicture(b *testing.B) {
	h := newTestHandler(b)
	id := seedOutcomes(b, h, 1, 5, 20, 10000)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{Id: id})); err != nil {
			b.Fatal(err)
		}
	}
}
