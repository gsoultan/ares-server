// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/gsoultan/ares-server/internal/worker"
)

// TrendPoint is the risk score right after one finished run: what was still
// open at that moment, weighted by how serious it is.
type TrendPoint struct {
	At           time.Time
	EngagementID string
	JobID        string
	Module       string
	Score        int // 0-100; 0 means nothing open
	Critical     int
	High         int
	Medium       int
	Low          int
	// Fixed is how many findings this run proved fixed (a re-check that did not
	// reproduce, or a re-run that no longer raised them).
	Fixed int
	// New is how many findings this run raised that were not open before.
	New int
}

// Open is the number of findings open at this point.
func (p TrendPoint) Open() int { return p.Critical + p.High + p.Medium + p.Low }

// MaxTrendPoints caps a trend to the most recent runs, enough for a chart.
const MaxTrendPoints = 60

// severityWeight is how much one open finding of a severity adds to the risk
// score before it is scaled to 0-100. Notes add nothing.
var severityWeight = map[string]float64{"critical": 25, "high": 10, "medium": 4, "low": 1}

// riskHalf is the weighted total that scores 50: one open critical, or two
// and a half open highs. One open low scores 4, two criticals score 67.
const riskHalf = 25.0

// RiskScore turns open-finding counts into a 0-99 score: 100 * w / (w + 25),
// where w is the severity-weighted count of open findings. It rises with every
// open finding but never reaches 100, so even with many findings open each fix
// still moves it visibly, and 0 means nothing is open.
func RiskScore(critical, high, medium, low int) int {
	w := severityWeight["critical"]*float64(critical) + severityWeight["high"]*float64(high) +
		severityWeight["medium"]*float64(medium) + severityWeight["low"]*float64(low)
	if w <= 0 {
		return 0
	}
	s := int(math.Round(100 * w / (w + riskHalf)))
	switch {
	case s < 1:
		s = 1 // something is open: never report a clean 0
	case s > 99:
		s = 99
	}
	return s
}

// RiskRating is the plain-word band for a score: one open high is already
// medium, two open criticals are high.
func RiskRating(score int) string {
	switch {
	case score == 0:
		return "none"
	case score >= 60:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// RiskTrend replays finished runs in the order they finished and returns the
// risk score after each one, oldest first and capped to MaxTrendPoints. The
// rules match the findings view: a run opens what it raises, and closes any
// open finding whose check and target it ran without raising it again. The
// outcomes may span several engagements of one workspace; callers pass only
// that workspace's outcomes, so a trend never mixes tenants.
func RiskTrend(outcomes []worker.Outcome) []TrendPoint {
	done := make([]worker.Outcome, 0, len(outcomes))
	for _, o := range outcomes {
		if !o.Running() {
			done = append(done, o)
		}
	}
	sort.SliceStable(done, func(i, j int) bool { return finishedAt(done[i]).Before(finishedAt(done[j])) })

	type open struct {
		sev string
		mt  string
	}
	openByID := map[string]open{}
	var points []TrendPoint
	for _, o := range done {
		raised := map[string]open{}
		for _, res := range o.Results {
			if res.Kind != "finding" {
				continue
			}
			sev, _ := res.Data["severity"].(string)
			sev = strings.ToLower(sev)
			if severityWeight[sev] == 0 {
				continue
			}
			title, _ := res.Data["title"].(string)
			target := res.Target.String()
			id := FindingKey(o.Engagement, res.Capability, res.Technique, title, target)
			raised[id] = open{sev: sev, mt: res.Capability + "\x00" + target}
		}
		ran := RanModuleTargets(o)
		p := TrendPoint{At: finishedAt(o), EngagementID: o.Engagement, JobID: o.JobID, Module: o.Module}
		for id, f := range openByID {
			if _, again := raised[id]; !again && ran[f.mt] {
				delete(openByID, id)
				p.Fixed++
			}
		}
		for id, f := range raised {
			if _, was := openByID[id]; !was {
				p.New++
			}
			openByID[id] = f
		}
		for _, f := range openByID {
			switch f.sev {
			case "critical":
				p.Critical++
			case "high":
				p.High++
			case "medium":
				p.Medium++
			case "low":
				p.Low++
			}
		}
		p.Score = RiskScore(p.Critical, p.High, p.Medium, p.Low)
		points = append(points, p)
	}
	if len(points) > MaxTrendPoints {
		points = points[len(points)-MaxTrendPoints:]
	}
	return points
}

func finishedAt(o worker.Outcome) time.Time {
	if !o.FinishedAt.IsZero() {
		return o.FinishedAt
	}
	return o.StartedAt
}
