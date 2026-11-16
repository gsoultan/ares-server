// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package eta

import (
	"testing"
	"time"

	"github.com/gsoultan/ares/module"
)

func TestNoSignalSaysEstimating(t *testing.T) {
	h := NewHistory()
	if e := h.Estimate("webcheck", 1, 10*time.Second, nil); e.State != Estimating {
		t.Fatalf("got %+v, want estimating", e)
	}
	// Two runs are not enough history.
	h.Record("webcheck", 1, 30*time.Second)
	h.Record("webcheck", 1, 30*time.Second)
	if e := h.Estimate("webcheck", 1, 10*time.Second, nil); e.State != Estimating {
		t.Fatalf("got %+v after 2 runs, want estimating", e)
	}
}

func TestHistoryRangeScalesWithTargetsAndElapsed(t *testing.T) {
	h := NewHistory()
	for _, s := range []int{20, 30, 40} {
		h.Record("webcheck", 2, time.Duration(s)*time.Second) // 10, 15, 20 s per target
	}
	e := h.Estimate("webcheck", 4, 10*time.Second, nil)
	if e.State != Running || e.Basis != BasisHistory {
		t.Fatalf("got %+v, want a history estimate", e)
	}
	// p25 = 12.5 s, p90 = 19 s per target; ×4 targets − 10 s elapsed.
	if e.LowSeconds != 40 || e.HighSeconds != 66 {
		t.Fatalf("range = %d..%d s, want 40..66", e.LowSeconds, e.HighSeconds)
	}
}

func TestPastTheUsualRangeIsOverdue(t *testing.T) {
	h := NewHistory()
	for i := 0; i < 3; i++ {
		h.Record("tlscheck", 1, 10*time.Second)
	}
	if e := h.Estimate("tlscheck", 1, 30*time.Second, nil); e.State != Overdue {
		t.Fatalf("got %+v, want overdue", e)
	}
}

func TestProgressExtrapolatesAndNarrows(t *testing.T) {
	h := NewHistory()
	early := h.Estimate("portscan", 1, 10*time.Second, &module.Progress{Done: 1, Total: 5})
	if early.State != Running || early.Basis != BasisProgress {
		t.Fatalf("got %+v, want a progress estimate", early)
	}
	// 10 s per step, 4 steps left = 40 s, inside the range.
	if early.LowSeconds > 40 || early.HighSeconds < 40 {
		t.Fatalf("early range %d..%d s should contain 40", early.LowSeconds, early.HighSeconds)
	}
	late := h.Estimate("portscan", 1, 40*time.Second, &module.Progress{Done: 4, Total: 5})
	if late.LowSeconds > 10 || late.HighSeconds < 10 {
		t.Fatalf("late range %d..%d s should contain 10", late.LowSeconds, late.HighSeconds)
	}
	earlyWidth := float64(early.HighSeconds-early.LowSeconds) / 40
	lateWidth := float64(late.HighSeconds-late.LowSeconds) / 10
	if lateWidth >= earlyWidth {
		t.Fatalf("relative width should narrow: early %.2f, late %.2f", earlyWidth, lateWidth)
	}
}

func TestGrowingTotalIsNotTrusted(t *testing.T) {
	h := NewHistory()
	e := h.Estimate("recon", 1, 10*time.Second, &module.Progress{Done: 1, Total: 1, TotalMayGrow: true})
	if e.State != Estimating {
		t.Fatalf("got %+v, want estimating while recon's total may still grow", e)
	}
}

func TestEarlyProgressDefersToHistory(t *testing.T) {
	h := NewHistory()
	for i := 0; i < 3; i++ {
		h.Record("recon", 1, 100*time.Second)
	}
	// 1 of 10 steps done: a slow profile step would make the pace misleading.
	e := h.Estimate("recon", 1, 20*time.Second, &module.Progress{Done: 1, Total: 10})
	if e.Basis != BasisHistory {
		t.Fatalf("got %+v, want history while the run is under a quarter through", e)
	}
	e = h.Estimate("recon", 1, 50*time.Second, &module.Progress{Done: 5, Total: 10})
	if e.Basis != BasisProgress {
		t.Fatalf("got %+v, want progress once the run is well under way", e)
	}
}

func TestAllStepsDoneIsFinishing(t *testing.T) {
	e := NewHistory().Estimate("portscan", 1, 5*time.Second, &module.Progress{Done: 3, Total: 3})
	if e.State != Finishing {
		t.Fatalf("got %+v, want finishing", e)
	}
}

func TestRingKeepsOnlyRecentRuns(t *testing.T) {
	h := NewHistory()
	for i := 0; i < ringSize; i++ {
		h.Record("m", 1, 100*time.Second)
	}
	for i := 0; i < ringSize; i++ {
		h.Record("m", 1, 10*time.Second)
	}
	lo, hi, _ := h.typical("m")
	if lo != 10 || hi != 10 {
		t.Fatalf("typical = %v..%v, want only the recent 10 s runs", lo, hi)
	}
}

func TestEmptyRunsAreNotRecorded(t *testing.T) {
	h := NewHistory()
	for i := 0; i < 5; i++ {
		h.Record("m", 0, time.Millisecond)
	}
	if _, _, ok := h.typical("m"); ok {
		t.Fatal("runs that touched no target must not count as history")
	}
}
