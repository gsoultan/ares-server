// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

var (
	tgtWeb = module.Target{URL: "https://shop.example"}
	tgtDB  = module.Target{Host: "db.example"}
)

func res(capability, sev, title string, tgt module.Target) module.Result {
	return module.Result{
		Capability: capability, Kind: "finding", Technique: "T1190", Target: tgt,
		Data: map[string]any{"severity": sev, "title": title, "remediationPlain": "Plain words for " + title + "."},
	}
}

// history is three runs: the first raises a critical and a medium, a re-check
// of the critical fails to reproduce it, and the last run re-raises only the
// medium.
func history(engID string) []worker.Outcome {
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	crit := res("datastoreexpose", "critical", "Database answers without a password", tgtDB)
	crit.Proof = &module.Proof{V: 1, Claim: "redis-noauth", Summary: "PING answered PONG", Fingerprint: "sha256:aaa"}
	med := res("headerprobe", "medium", "Missing security headers", tgtWeb)
	return []worker.Outcome{
		// ByEngagement order: newest first.
		{JobID: "job-3", Engagement: engID, Module: "headerprobe", Allowed: []module.Target{tgtWeb},
			StartedAt: t0.Add(48 * time.Hour), FinishedAt: t0.Add(48*time.Hour + time.Minute),
			Results: []module.Result{med}},
		{JobID: "job-2", Engagement: engID, Module: "datastoreexpose", Allowed: []module.Target{tgtDB},
			StartedAt: t0.Add(24 * time.Hour), FinishedAt: t0.Add(24*time.Hour + time.Minute),
			Recheck: &worker.RecheckResult{
				FindingID: FindingKey(engID, "datastoreexpose", "T1190", "Database answers without a password", tgtDB.String()),
				Claim:     "redis-noauth", Reproduced: false,
			}},
		{JobID: "job-1", Engagement: engID, Module: "recon",
			StartedAt: t0, FinishedAt: t0.Add(time.Minute),
			Results: []module.Result{crit, med}},
	}
}

func newEng(t *testing.T) *engagement.Engagement {
	t.Helper()
	eng, err := engagement.NewMemStore().Create("", "Shop")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return eng
}

func TestBuildDeduplicatesAndProvesFixes(t *testing.T) {
	eng := newEng(t)
	r := BuildWith(eng, "Shop Co", history(eng.ID), Options{Status: func(string) string { return "fixed" }})

	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (the medium is raised twice but is one finding)", len(r.Findings))
	}
	med, crit := r.Findings[0], r.Findings[1]
	if med.Title != "Missing security headers" || crit.Title != "Database answers without a password" {
		t.Fatalf("order = %q, %q; want open findings before proven fixes", med.Title, crit.Title)
	}
	if got := med.State(); got != StateAwaitingRecheck {
		t.Errorf("medium state = %s, want awaiting_recheck (marked fixed, still found)", got)
	}
	if !med.LastSeen.After(med.FirstSeen) {
		t.Errorf("medium should span two runs: first %v last %v", med.FirstSeen, med.LastSeen)
	}
	if got := crit.State(); got != StateProvenFixed {
		t.Fatalf("critical state = %s, want proven_fixed", got)
	}
	if len(crit.Rechecks) != 1 || crit.Rechecks[0].Reproduced {
		t.Fatalf("critical rechecks = %+v, want one that did not reproduce", crit.Rechecks)
	}
	if !strings.Contains(crit.FixProof(), "Re-checked 2 Nov 2026") {
		t.Errorf("fix proof = %q, want the re-check date", crit.FixProof())
	}
	if crit.Plain == "" || crit.ProofFingerprint != "sha256:aaa" {
		t.Errorf("plain/proof not carried: %+v", crit)
	}
	if len(r.ProvenFixed()) != 1 || len(r.Open()) != 1 {
		t.Errorf("open=%d proven=%d, want 1 and 1", len(r.Open()), len(r.ProvenFixed()))
	}
}

func TestRecheckOfAnotherEngagementIsIgnored(t *testing.T) {
	eng := newEng(t)
	outs := history(eng.ID)
	outs[1].Engagement = "someone-else" // the re-check ran elsewhere
	r := Build(eng, "", outs)
	for _, f := range r.Findings {
		if len(f.Rechecks) != 0 {
			t.Fatalf("a re-check from another engagement leaked onto %q", f.Title)
		}
	}
}

func TestRiskTrend(t *testing.T) {
	pts := RiskTrend(history("e1"))
	if len(pts) != 3 {
		t.Fatalf("points = %d, want one per finished run", len(pts))
	}
	if pts[0].Critical != 1 || pts[0].Medium != 1 || pts[0].New != 2 {
		t.Errorf("first point = %+v, want 1 critical + 1 medium, both new", pts[0])
	}
	if pts[1].Critical != 0 || pts[1].Fixed != 1 {
		t.Errorf("after the re-check = %+v, want the critical proven fixed", pts[1])
	}
	if pts[2].Fixed != 0 || pts[2].New != 0 || pts[2].Medium != 1 {
		t.Errorf("last point = %+v, want the medium still open and nothing new", pts[2])
	}
	if !(pts[0].Score > pts[1].Score && pts[1].Score == pts[2].Score && pts[2].Score > 0) {
		t.Errorf("scores = %d, %d, %d; want a drop after the fix and the medium still counting",
			pts[0].Score, pts[1].Score, pts[2].Score)
	}
}

func TestRiskTrendSkipsRunningAndCaps(t *testing.T) {
	var outs []worker.Outcome
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < MaxTrendPoints+5; i++ {
		outs = append(outs, worker.Outcome{Engagement: "e", Module: "headerprobe",
			StartedAt: t0.Add(time.Duration(i) * time.Hour), FinishedAt: t0.Add(time.Duration(i)*time.Hour + time.Minute)})
	}
	outs = append(outs, worker.Outcome{Engagement: "e", StartedAt: t0.Add(1000 * time.Hour)}) // still running
	pts := RiskTrend(outs)
	if len(pts) != MaxTrendPoints {
		t.Fatalf("points = %d, want capped to %d", len(pts), MaxTrendPoints)
	}
	if !pts[len(pts)-1].At.Equal(t0.Add(time.Duration(MaxTrendPoints+4)*time.Hour + time.Minute)) {
		t.Errorf("cap should keep the most recent runs, last = %v", pts[len(pts)-1].At)
	}
}

func TestRiskScore(t *testing.T) {
	if RiskScore(0, 0, 0, 0) != 0 {
		t.Error("nothing open must score 0")
	}
	if s := RiskScore(0, 0, 0, 1); s < 1 {
		t.Errorf("one low = %d, want at least 1", s)
	}
	one, two := RiskScore(1, 0, 0, 0), RiskScore(2, 0, 0, 0)
	if !(one < two && two < 100) {
		t.Errorf("criticals: one=%d two=%d, want rising and below 100", one, two)
	}
	if s := RiskScore(50, 50, 50, 50); s > 99 {
		t.Errorf("score = %d, must stay below 100", s)
	}
	// With many findings open, fixing one still moves the score.
	if RiskScore(2, 15, 9, 10) == RiskScore(1, 15, 9, 10) {
		t.Error("fixing a critical among many findings should lower the score")
	}
	if RiskRating(RiskScore(0, 1, 0, 0)) != "medium" {
		t.Errorf("one open high = %d (%s), want medium", RiskScore(0, 1, 0, 0), RiskRating(RiskScore(0, 1, 0, 0)))
	}
	if RiskRating(0) != "none" || RiskRating(one) != "medium" || RiskRating(two) != "high" {
		t.Errorf("ratings: %s %s %s", RiskRating(0), RiskRating(one), RiskRating(two))
	}
}

func TestOwnerSectionsInEveryFormat(t *testing.T) {
	eng := newEng(t)
	r := Build(eng, "Shop Co", history(eng.ID))

	md := string(r.Markdown())
	for _, want := range []string{
		"## Summary", "1 problem is still open: 1 medium.",
		"1 problem has been fixed and proven fixed",
		"**Risk score:**", "down from",
		"## Fix these first", "### 1. Missing security headers (medium)", "Plain words for Missing security headers.",
		"## Proven fixed", "Database answers without a password (was critical)", "no longer succeeds",
		"## Risk over time", "(1 proven fixed)",
		"**In plain words:**", "**Status:** Fixed and proven",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Index(md, "## Summary") > strings.Index(md, "## Engagement") {
		t.Error("the owner summary must come before the engagement details")
	}

	pdf := string(r.PDF())
	for _, want := range []string{"(Summary)", "(Fix these first)", "(Proven fixed)", "(Risk over time)"} {
		if !strings.Contains(pdf, want) {
			t.Errorf("pdf missing %s", want)
		}
	}

	docx, err := r.DOCX()
	if err != nil {
		t.Fatalf("docx: %v", err)
	}
	doc := docxDocument(t, docx)
	for _, want := range []string{">Proven fixed<", ">Fix these first<", ">Risk over time<"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docx missing %s", want)
		}
	}
}

func TestOwnerSummaryWhenNothingFound(t *testing.T) {
	eng := newEng(t)
	r := Build(eng, "", nil)
	md := string(r.Markdown())
	if !strings.Contains(md, "Ares found no security problems") {
		t.Errorf("empty report should say nothing was found:\n%s", md)
	}
	if strings.Contains(md, "## Fix these first") || strings.Contains(md, "## Proven fixed") {
		t.Error("empty report should not show empty sections")
	}
}

func docxDocument(t *testing.T, data []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer rc.Close()
		b, _ := io.ReadAll(rc)
		return string(b)
	}
	t.Fatal("docx has no word/document.xml")
	return ""
}

func TestWrapWidthFitsAndKeepsEveryWord(t *testing.T) {
	measure := func(s string) float64 { return textWidth(fontRegular, 10, s) }
	text := "Ares re-ran the exact test that proved this problem https://very-long-host.example.com/" +
		strings.Repeat("a", 200) + " and it no longer succeeds."
	lines := wrapWidth(text, 200, measure)
	if len(lines) < 3 {
		t.Fatalf("expected wrapping, got %d line(s)", len(lines))
	}
	for _, ln := range lines {
		if measure(ln) > 200 {
			t.Errorf("line %q is %.1fpt, wider than 200", ln, measure(ln))
		}
	}
	if got := strings.ReplaceAll(strings.Join(lines, ""), " ", ""); got != strings.ReplaceAll(text, " ", "") {
		t.Error("wrapping lost or reordered text")
	}
	if w := textWidth(fontBold, 10, "M"); w != 8.33 {
		t.Errorf("Helvetica-Bold M at 10pt = %v, want 8.33", w)
	}
}
