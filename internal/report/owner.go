// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import (
	"fmt"
	"strings"
	"time"
)

// The owner-facing front of the report: a summary in plain words, what to fix
// first, what is proven fixed, and how the risk score moved across runs. It is
// built once as a list of simple blocks so PDF, Word and Markdown say exactly
// the same thing.

type blockKind int

const (
	bH2     blockKind = iota // section heading
	bH3                      // item heading
	bPara                    // paragraph
	bLabel                   // bold label, then value
	bBullet                  // one list item
)

type block struct {
	kind  blockKind
	text  string
	label string // bLabel only
}

// topFixes is how many open findings "Fix these first" lists.
const topFixes = 5

// trendRows is how many of the most recent runs the "Risk over time" table shows.
const trendRows = 12

// ownerBlocks builds the owner-facing sections.
func (r Report) ownerBlocks() []block {
	var bs []block
	add := func(k blockKind, text string) { bs = append(bs, block{kind: k, text: text}) }
	label := func(l, v string) { bs = append(bs, block{kind: bLabel, label: l, text: v}) }

	open, fixed := r.Open(), r.ProvenFixed()
	real := 0 // open findings that are more than a note
	for _, f := range open {
		if severityRank(f.Severity) < severityRank("info") {
			real++
		}
	}

	add(bH2, "Summary")
	if tested := r.testedLine(); tested != "" {
		add(bPara, tested)
	}
	switch {
	case real == 0 && len(fixed) == 0:
		add(bPara, "Ares found no security problems in what it tested.")
	case real == 0:
		add(bPara, fmt.Sprintf("Every problem Ares found has been fixed and proven fixed: Ares tested again and no longer finds %s.", itOrThem(len(fixed))))
	default:
		add(bPara, fmt.Sprintf("%s still open: %s.", countPhrase(real, "problem is", "problems are"), severityPhrase(open)))
		if len(fixed) > 0 {
			add(bPara, fmt.Sprintf("%s fixed and proven fixed: Ares tested again and no longer finds %s.",
				countPhrase(len(fixed), "problem has been", "problems have been"), itOrThem(len(fixed))))
		}
	}
	if n := len(r.Trend); n > 0 {
		now := r.Trend[n-1]
		if was := r.Trend[0].Score; n > 1 && was != now.Score {
			dir := "down"
			if now.Score > was {
				dir = "up"
			}
			label("Risk score", fmt.Sprintf("%d out of 100 now (%s), %s from %d after the first test.",
				now.Score, RiskRating(now.Score), dir, was))
		} else {
			label("Risk score", fmt.Sprintf("%d out of 100 (%s).", now.Score, RiskRating(now.Score)))
		}
		add(bPara, "The risk score counts what is still open, weighted by how serious each problem is. 0 means nothing is open. A fix lowers it only once a test proves the fix worked.")
	}

	if real > 0 {
		add(bH2, "Fix these first")
		n := 0
		for _, f := range open {
			if n == topFixes || severityRank(f.Severity) >= severityRank("info") {
				break
			}
			n++
			add(bH3, fmt.Sprintf("%d. %s (%s)", n, f.Title, severityWord(f.Severity)))
			if f.Plain != "" {
				add(bPara, f.Plain)
			} else if f.Remediation != "" {
				add(bPara, f.Remediation)
			}
			if f.URL != "" {
				label("Where", f.URL)
			}
			if steps := f.Guidance.Fix; len(steps) > 0 {
				label("First step", steps[0].Text)
			}
			if s := f.State(); s != StateOpen {
				label("Status", s.Label())
			}
		}
		if real > n {
			add(bPara, fmt.Sprintf("%s more %s listed under Findings, with full fix steps.", plainCount(real-n), isAre(real-n)))
		}
	}

	if len(fixed) > 0 {
		add(bH2, "Proven fixed")
		add(bPara, "Each of these was found, fixed, and then tested again. The test no longer finds the problem, so the fix is proven, not just reported.")
		for _, f := range fixed {
			add(bH3, fmt.Sprintf("%s (was %s)", f.Title, severityWord(f.Severity)))
			add(bPara, f.FixProof())
			if f.URL != "" {
				label("Where", f.URL)
			}
			label("Found", day(f.FirstSeen))
			if len(f.Rechecks) > 1 { // the sentence above already covers a single re-check
				for _, rc := range f.Rechecks {
					add(bBullet, recheckLine(rc))
				}
			}
		}
	}

	if len(r.Trend) > 1 {
		add(bH2, "Risk over time")
		add(bPara, "The risk score after each test, oldest first.")
		rows := r.Trend
		if len(rows) > trendRows {
			add(bPara, fmt.Sprintf("Showing the latest %d of %d tests.", trendRows, len(rows)))
			rows = rows[len(rows)-trendRows:]
		}
		for _, p := range rows {
			add(bBullet, trendLine(p))
		}
	}
	return bs
}

// testedLine says what was tested and over which period.
func (r Report) testedLine() string {
	if len(r.Trend) == 0 {
		return ""
	}
	first, last := r.Trend[0].At, r.Trend[len(r.Trend)-1].At
	what := "the approved systems"
	if len(r.Scope.InScope) > 0 {
		what = strings.Join(r.Scope.InScope, ", ")
	}
	tests := plainCount(len(r.Trend)) + " " + pluralWord(len(r.Trend), "test", "tests")
	if day(first) == day(last) {
		return fmt.Sprintf("Ares ran %s against %s on %s.", tests, what, day(first))
	}
	return fmt.Sprintf("Ares ran %s against %s between %s and %s.", tests, what, day(first), day(last))
}

// recheckLine is one re-check in plain words.
func recheckLine(rc Recheck) string {
	verdict := "the problem could not be reproduced"
	if rc.Reproduced {
		verdict = "the problem was still there"
	}
	s := fmt.Sprintf("Re-checked %s: %s.", day(rc.At), verdict)
	if rc.Fingerprint != "" {
		s += " Proof fingerprint " + shortFP(rc.Fingerprint) + "."
	}
	return s
}

// trendLine is one row of the risk-over-time table.
func trendLine(p TrendPoint) string {
	s := fmt.Sprintf("%s: risk score %d, %s open", p.At.UTC().Format(time.DateOnly), p.Score, plainCount(p.Open()))
	var changes []string
	if p.New > 0 {
		changes = append(changes, fmt.Sprintf("%d new", p.New))
	}
	if p.Fixed > 0 {
		changes = append(changes, fmt.Sprintf("%d proven fixed", p.Fixed))
	}
	if len(changes) > 0 {
		s += " (" + strings.Join(changes, ", ") + ")"
	}
	return s + "."
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

// severityPhrase tallies the open findings that are more than notes, most
// serious first: "1 critical, 2 medium".
func severityPhrase(fs []Finding) string {
	counts := map[string]int{}
	for _, f := range fs {
		counts[strings.ToLower(f.Severity)]++
	}
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func severityWord(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "note"
	}
}

func countPhrase(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func plainCount(n int) string { return fmt.Sprintf("%d", n) }

func itOrThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

func isAre(n int) string {
	if n == 1 {
		return "problem is"
	}
	return "problems are"
}

// findingBlocks is the plain-language part of one finding's detail: the
// headline, where it stands, when it was seen and every re-check.
func (f Finding) findingBlocks() []block {
	var bs []block
	if f.Plain != "" {
		bs = append(bs, block{kind: bLabel, label: "In plain words", text: f.Plain})
	}
	status := f.State().Label()
	if p := f.FixProof(); p != "" {
		status += ". " + p
	}
	bs = append(bs, block{kind: bLabel, label: "Status", text: status})
	if !f.FirstSeen.IsZero() {
		seen := "First found " + day(f.FirstSeen)
		if day(f.LastSeen) != day(f.FirstSeen) {
			seen += ", last seen " + day(f.LastSeen)
		}
		bs = append(bs, block{kind: bLabel, label: "Seen", text: seen + "."})
	}
	for _, rc := range f.Rechecks {
		bs = append(bs, block{kind: bBullet, text: recheckLine(rc)})
	}
	return bs
}
