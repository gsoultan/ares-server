// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/report"
	"github.com/gsoultan/ares-server/internal/worker"
)

// GetRiskTrend returns the risk score after each finished run, oldest first,
// for one engagement or the whole workspace. Only the caller's engagements are
// read, so a trend never includes another workspace's runs.
func (h *Handler) GetRiskTrend(_ context.Context, req *connect.Request[aresv1.GetRiskTrendRequest]) (*connect.Response[aresv1.RiskTrend], error) {
	engIDs, engName, err := h.workspaceEngagements(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	// A pure function of the engagements' outcomes: rebuilt only when one changes.
	fp := newFingerprint()
	for _, id := range engIDs {
		fp.str(id).str(engName[id]).num(h.outcomes.Version(id))
	}
	key := "trend|" + engagement.ResolveTenant(req.Msg.GetTenantId()) + "|" + req.Msg.GetEngagementId()
	rt := h.memo.get(key, fp.sum(), func() any {
		var outcomes []worker.Outcome
		for _, id := range engIDs {
			outcomes = append(outcomes, h.outcomes.ByEngagement(id)...)
		}
		return riskTrendProto(report.RiskTrend(outcomes), engName)
	}).(*aresv1.RiskTrend)
	return connect.NewResponse(rt), nil
}

func riskTrendProto(points []report.TrendPoint, engName map[string]string) *aresv1.RiskTrend {
	out := &aresv1.RiskTrend{Rating: report.RiskRating(0)}
	for _, p := range points {
		out.Points = append(out.Points, &aresv1.RiskTrendPoint{
			At:             rfc(p.At),
			EngagementId:   p.EngagementID,
			EngagementName: engName[p.EngagementID],
			JobId:          p.JobID,
			Score:          int32(p.Score),
			Critical:       int32(p.Critical),
			High:           int32(p.High),
			Medium:         int32(p.Medium),
			Low:            int32(p.Low),
			NewFindings:    int32(p.New),
			FixedFindings:  int32(p.Fixed),
		})
	}
	if n := len(points); n > 0 {
		out.Score = int32(points[n-1].Score)
		out.Rating = report.RiskRating(points[n-1].Score)
		out.FirstScore = int32(points[0].Score)
	}
	return out
}
