// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"time"

	"github.com/gsoultan/ares-server/internal/eta"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/worker"
)

// progressProto is a job's step count and time-left estimate at now. The
// estimate comes from the outcome store when it can give one; otherwise a
// running job is reported as "estimating", never as a made-up number.
func progressProto(o worker.Outcome, store worker.OutcomeStore, now time.Time) *aresv1.JobProgress {
	var e eta.Estimate
	switch est, ok := store.(worker.Estimator); {
	case ok:
		e = est.Estimate(o, now)
	case o.Running():
		e = eta.Estimate{State: eta.Estimating}
	default:
		e = eta.Estimate{State: eta.Done}
	}
	end := now
	if !o.Running() {
		end = o.FinishedAt
	}
	jp := &aresv1.JobProgress{
		State:                e.State,
		Basis:                e.Basis,
		RemainingLowSeconds:  e.LowSeconds,
		RemainingHighSeconds: e.HighSeconds,
		ElapsedSeconds:       int64(max(0, end.Sub(o.StartedAt).Seconds())),
		StartedAt:            rfc(o.StartedAt),
	}
	if p := o.Progress; p != nil {
		jp.Done = int32(p.Done)
		jp.Total = int32(p.Total)
		jp.TotalMayGrow = p.TotalMayGrow
		jp.Step = p.Step
	}
	return jp
}
