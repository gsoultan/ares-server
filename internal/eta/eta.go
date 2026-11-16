// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package eta estimates how long a running job has left. It is deliberately
// honest: it gives a range, not a single number, and says "estimating" rather
// than guess when it has no signal.
//
// Two signals feed it, best first:
//
//  1. The module's own progress (done of total steps), when the module reports
//     one and its total is settled: the pace so far is extrapolated to the
//     steps left, with a range that narrows as the run goes on.
//  2. History: how long recent finished runs of the same module took per
//     approved target. The typical range for this many targets, minus the time
//     already spent.
//
// History is a small ring per module, so the bookkeeping is a few hundred bytes
// per module and no I/O.
package eta

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/gsoultan/ares/module"
)

// States of an estimate.
const (
	// Estimating: not enough signal yet; show no number.
	Estimating = "estimating"
	// Running: LowSeconds..HighSeconds is the time left.
	Running = "estimate"
	// Finishing: every step is done; the job is wrapping up.
	Finishing = "finishing"
	// Overdue: the run has gone past the top of its usual range.
	Overdue = "overdue"
	// Done: the job has finished.
	Done = "done"
)

// Bases name the signal an estimate came from.
const (
	BasisProgress = "progress"
	BasisHistory  = "history"
)

const (
	// ringSize is how many recent runs per module the history keeps.
	ringSize = 20
	// minSamples is how many finished runs history needs before it is trusted.
	minSamples = 3
	// minElapsed is how long a run must have gone before its pace is used: the
	// first second is dominated by setup.
	minElapsed = 2 * time.Second
	// earlyFraction is how far through a run its own pace has to be before it
	// beats history; before that, a slow first step (recon's profile) would
	// skew it. With no history, the pace is used from the first step.
	earlyFraction = 0.25
)

// Estimate is the time a job has left, as a range.
type Estimate struct {
	State string `json:"state"`
	// Basis is the signal the range came from; empty while estimating.
	Basis string `json:"basis,omitempty"`
	// LowSeconds and HighSeconds bound the time left. Zero unless State is
	// Running.
	LowSeconds  int64 `json:"remainingLowSeconds,omitempty"`
	HighSeconds int64 `json:"remainingHighSeconds,omitempty"`
}

// History keeps how long recent runs of each module took per approved target.
// It is safe for concurrent use.
type History struct {
	mu sync.Mutex
	m  map[string]*ring
}

type ring struct {
	secsPerTarget [ringSize]float64
	n, next       int
}

// NewHistory returns an empty history.
func NewHistory() *History { return &History{m: make(map[string]*ring)} }

// Record notes that a run of mod over targets approved targets took d. Runs
// that touched nothing are skipped: they finish instantly and would drag the
// typical duration down.
func (h *History) Record(mod string, targets int, d time.Duration) {
	if h == nil || targets <= 0 || d <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.m[mod]
	if r == nil {
		r = &ring{}
		h.m[mod] = r
	}
	r.secsPerTarget[r.next] = d.Seconds() / float64(targets)
	r.next = (r.next + 1) % ringSize
	if r.n < ringSize {
		r.n++
	}
}

// typical returns the 25th and 90th percentile of seconds per target for mod,
// and false when there are too few runs to say.
func (h *History) typical(mod string) (low, high float64, ok bool) {
	if h == nil {
		return 0, 0, false
	}
	h.mu.Lock()
	r := h.m[mod]
	var s []float64
	if r != nil {
		s = append(s, r.secsPerTarget[:r.n]...)
	}
	h.mu.Unlock()
	if len(s) < minSamples {
		return 0, 0, false
	}
	sort.Float64s(s)
	return quantile(s, 0.25), quantile(s, 0.90), true
}

func quantile(sorted []float64, q float64) float64 {
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	return sorted[lo] + (sorted[hi]-sorted[lo])*(pos-float64(lo))
}

// Estimate returns the time left for a run of mod over targets approved
// targets that has been going for elapsed, with the module's latest progress
// (nil when it reports none).
func (h *History) Estimate(mod string, targets int, elapsed time.Duration, p *module.Progress) Estimate {
	histLow, histHigh, haveHist := h.typical(mod)

	if p != nil && !p.TotalMayGrow && p.Total > 0 && p.Done >= p.Total {
		return Estimate{State: Finishing, Basis: BasisProgress}
	}
	if p != nil && !p.TotalMayGrow && p.Total > 0 && p.Done >= 1 && elapsed >= minElapsed {
		f := float64(p.Done) / float64(p.Total)
		if f >= earlyFraction || !haveHist {
			left := elapsed.Seconds() / float64(p.Done) * float64(p.Total-p.Done)
			// The range is wide early and narrows to ±10% near the end.
			spread := 0.1 + 0.5*(1-f)
			return running(BasisProgress, left*(1-spread/2), left*(1+spread))
		}
	}
	if haveHist {
		n := float64(max(targets, 1))
		low := histLow*n - elapsed.Seconds()
		high := histHigh*n - elapsed.Seconds()
		if high <= 0 {
			return Estimate{State: Overdue, Basis: BasisHistory}
		}
		return running(BasisHistory, math.Max(0, low), high)
	}
	return Estimate{State: Estimating}
}

func running(basis string, low, high float64) Estimate {
	lo := int64(math.Floor(low))
	hi := int64(math.Ceil(high))
	if hi < 1 {
		hi = 1
	}
	if lo > hi {
		lo = hi
	}
	return Estimate{State: Running, Basis: basis, LowSeconds: max(lo, 0), HighSeconds: hi}
}
