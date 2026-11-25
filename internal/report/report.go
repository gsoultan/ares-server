// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package report turns a finished engagement into a client-ready document. It
// gathers the engagement's metadata, approved scope, findings and the state of
// its tamper-evident audit trail, and renders them to PDF, DOCX or Markdown.
//
// Rendering is self-contained: the PDF and DOCX writers are built from the
// standard library alone (no external toolchain or service), keeping Ares a
// single static binary.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/detection"
	"github.com/gsoultan/ares/intel"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/remediation"
	"github.com/gsoultan/ares/scope"
)

// Finding is one observation, flattened from a module result for the report.
type Finding struct {
	Severity    string
	Title       string
	URL         string
	Module      string
	Technique   string
	Description string
	Remediation string               // the plain-language "what to do" summary line
	Guidance    remediation.Guidance // the structured blue-team answer (fix/prevent/detect/verify + ATT&CK mitigations)
	IssueKey    string               // stable issue slug, used to correlate attack paths
	Proof       string
	Request     string

	// ID is the finding's stable id (see FindingKey), the same one the app shows.
	ID string
	// Plain is the one-sentence, jargon-free "what this means and what to do"
	// headline an owner reads first (the engine's PlainSummary).
	Plain string
	// Status is the triage status someone set: open | in_progress | fixed.
	Status string
	// FirstSeen and LastSeen bound the runs that raised it.
	FirstSeen time.Time
	LastSeen  time.Time
	// StillPresent is false once a later run of the same check and target did
	// not raise it again: the fix is proven by a test, not just claimed.
	StillPresent bool
	// ClearedAt is when the later run that no longer raised it started; zero
	// while the finding is still present.
	ClearedAt time.Time
	// ProofFingerprint is the sealed fingerprint of the newest proof.
	ProofFingerprint string
	// Rechecks is every reproduce-on-demand run of the proof, newest first.
	Rechecks []Recheck
}

// Meta is the engagement header of a report.
type Meta struct {
	EngagementID   string
	EngagementName string
	Workspace      string
	Status         string
	CreatedAt      time.Time
	Authorized     bool
	AuthDocument   string
	AuthApprovedBy string
	AuthApprovedAt time.Time
}

// ScopeSummary is the approved boundary, as shown in the report.
type ScopeSummary struct {
	InScope []string
	Exclude []string
	Window  string
}

// AuditSummary is the state of the engagement's tamper-evident log.
type AuditSummary struct {
	Entries int
	Valid   bool
}

// EvidenceItem is one forensic artifact ingested during the engagement, as it
// appears in the chain-of-custody section. Each item's SHA-256 is anchored in
// the tamper-evident audit trail, so the custody record is verifiable.
type EvidenceItem struct {
	Name        string
	SHA256      string
	SHA1        string
	Size        int
	ContentType string
	IngestedAt  string
	Source      string
}

// Report is the assembled, format-independent document.
type Report struct {
	Generated time.Time
	Meta      Meta
	Scope     ScopeSummary
	Findings  []Finding
	Audit     AuditSummary
	Evidence  []EvidenceItem // forensic artifacts ingested, for the chain-of-custody section
	Detection detection.Summary
	Risk      intel.RiskPicture // correlated, prioritized attack paths
	Trend     []TrendPoint      // the engagement's risk score after each run, oldest first
}

// Options carries what a report needs beyond the engagement's outcomes.
type Options struct {
	// Status returns the triage status someone set on a finding (open |
	// in_progress | fixed). Nil treats every finding as open.
	Status func(findingID string) string
}

// ExercisedTechniques tallies, across a set of outcomes, how many findings each
// ATT&CK technique was raised for. It is the basis of the detection-coverage
// score: the techniques a test actually exercised.
func ExercisedTechniques(outcomes []worker.Outcome) map[string]int {
	m := map[string]int{}
	for _, o := range outcomes {
		for _, res := range o.Results {
			if res.Kind == "finding" && res.Technique != "" {
				m[res.Technique]++
			}
		}
	}
	return m
}

// severityOrder ranks severities most to least serious; unknown sorts last.
var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func severityRank(s string) int {
	if n, ok := severityOrder[strings.ToLower(s)]; ok {
		return n
	}
	return 99
}

// SeverityCounts tallies findings by severity.
func (r Report) SeverityCounts() map[string]int {
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[strings.ToLower(f.Severity)]++
	}
	return counts
}

// SeveritySummary is a stable, human-readable tally line, most serious first.
func (r Report) SeveritySummary() string {
	counts := r.SeverityCounts()
	order := []string{"critical", "high", "medium", "low", "info"}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

// Build assembles a report from an engagement, its workspace name and the
// outcomes of every job it ran, treating every finding as open.
func Build(eng *engagement.Engagement, workspace string, outcomes []worker.Outcome) Report {
	return BuildWith(eng, workspace, outcomes, Options{})
}

// BuildWith assembles a report from an engagement, its workspace name, the
// outcomes of every job it ran and the triage state in opts. A finding raised by
// several runs appears once, with the newest run's details, the span of runs
// that raised it, its re-check history and whether a later run proved it fixed.
// Open findings come first, most serious first; proven fixes follow.
func BuildWith(eng *engagement.Engagement, workspace string, outcomes []worker.Outcome, opts Options) Report {
	r := Report{
		Generated: time.Now().UTC(),
		Meta: Meta{
			EngagementID:   eng.ID,
			EngagementName: eng.Name,
			Workspace:      workspace,
			Status:         string(eng.Status),
			CreatedAt:      eng.CreatedAt,
		},
		Scope: scopeSummary(eng.Scope.Snapshot()),
		Audit: AuditSummary{Entries: len(eng.Audit.Entries()), Valid: eng.Audit.Verify() == nil},
	}
	if eng.Authorization != nil {
		r.Meta.Authorized = true
		r.Meta.AuthDocument = eng.Authorization.Document
		r.Meta.AuthApprovedBy = eng.Authorization.ApprovedBy
		r.Meta.AuthApprovedAt = eng.Authorization.ApprovedAt
	}
	for _, o := range outcomes {
		for _, res := range o.Results {
			if res.Kind == "evidence" {
				r.Evidence = append(r.Evidence, evidenceFromResult(res))
			}
		}
	}
	r.Findings = collect(outcomes, opts)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if pa, pb := a.State() == StateProvenFixed, b.State() == StateProvenFixed; pa != pb {
			return !pa
		}
		return severityRank(a.Severity) < severityRank(b.Severity)
	})
	sort.SliceStable(r.Evidence, func(i, j int) bool {
		if r.Evidence[i].IngestedAt != r.Evidence[j].IngestedAt {
			return r.Evidence[i].IngestedAt < r.Evidence[j].IngestedAt
		}
		return r.Evidence[i].Name < r.Evidence[j].Name
	})
	r.Detection = detection.BuildSummary(ExercisedTechniques(outcomes), eng.Detections())
	// The attack-path picture is about what an attacker can still do, so it is
	// built from the findings that are not proven fixed.
	r.Risk = correlateFindings(r.Open())
	r.Trend = RiskTrend(outcomes)
	return r
}

// Open is the findings not yet proven fixed, in report order.
func (r Report) Open() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.State() != StateProvenFixed {
			out = append(out, f)
		}
	}
	return out
}

// ProvenFixed is the findings a later test proved fixed, in report order.
func (r Report) ProvenFixed() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.State() == StateProvenFixed {
			out = append(out, f)
		}
	}
	return out
}

// collect deduplicates the findings across outcomes by stable id, keeping the
// newest run's payload, and attaches each one's re-check history and whether a
// later run of its check and target no longer raised it.
func collect(outcomes []worker.Outcome, opts Options) []Finding {
	// When was each (module, target) last run?
	latestRun := map[string]time.Time{}
	for _, o := range outcomes {
		if o.Running() {
			continue
		}
		for mt := range RanModuleTargets(o) {
			if o.StartedAt.After(latestRun[mt]) {
				latestRun[mt] = o.StartedAt
			}
		}
	}

	type agg struct {
		f      Finding
		mt     string
		engID  string
		newest time.Time
		seen   bool
	}
	byID := map[string]*agg{}
	var order []string
	for _, o := range outcomes {
		for _, res := range o.Results {
			if res.Kind != "finding" && res.Kind != "info" {
				continue
			}
			title, _ := res.Data["title"].(string)
			target := res.Target.String()
			id := FindingKey(o.Engagement, res.Capability, res.Technique, title, target)
			a, ok := byID[id]
			if !ok {
				a = &agg{mt: res.Capability + "\x00" + target, engID: o.Engagement}
				byID[id] = a
				order = append(order, id)
			}
			if !a.seen || o.StartedAt.After(a.newest) {
				first, last := a.f.FirstSeen, a.f.LastSeen
				a.f = findingFromResult(res)
				a.f.ID = id
				a.f.FirstSeen, a.f.LastSeen = first, last
				a.newest = o.StartedAt
			}
			if !a.seen || o.StartedAt.Before(a.f.FirstSeen) {
				a.f.FirstSeen = o.StartedAt
			}
			if o.StartedAt.After(a.f.LastSeen) {
				a.f.LastSeen = o.StartedAt
			}
			a.seen = true
		}
	}

	// Re-checks attach only to a finding of the engagement they ran in.
	for _, o := range outcomes {
		rc := o.Recheck
		if rc == nil || o.Running() {
			continue
		}
		a, ok := byID[rc.FindingID]
		if !ok || a.engID != o.Engagement {
			continue
		}
		a.f.Rechecks = append(a.f.Rechecks, Recheck{
			At: o.FinishedAt, Reproduced: rc.Reproduced, Fingerprint: rc.Fingerprint, JobID: o.JobID,
		})
	}

	out := make([]Finding, 0, len(order))
	for _, id := range order {
		a := byID[id]
		f := a.f
		sort.SliceStable(f.Rechecks, func(i, j int) bool { return f.Rechecks[i].At.After(f.Rechecks[j].At) })
		f.StillPresent = true
		if lr, ok := latestRun[a.mt]; ok && lr.After(f.LastSeen) {
			f.StillPresent = false
			f.ClearedAt = lr
		}
		f.Status = "open"
		if opts.Status != nil {
			if s := opts.Status(id); s != "" {
				f.Status = s
			}
		}
		out = append(out, f)
	}
	return out
}

// RiskOf correlates the findings across a set of outcomes into a prioritized
// attack-path risk picture — the same correlation the full report uses, exposed
// for the API so the live UI can show it without rendering a document.
func RiskOf(outcomes []worker.Outcome) intel.RiskPicture {
	var findings []Finding
	for _, o := range outcomes {
		for _, res := range o.Results {
			if res.Kind != "finding" && res.Kind != "info" {
				continue
			}
			findings = append(findings, findingFromResult(res))
		}
	}
	return correlateFindings(findings)
}

// correlateFindings turns the report's findings into a prioritized attack-path
// picture. Pure info observations (no issue key or technique) are left out so
// the picture reflects real weaknesses, not notes.
func correlateFindings(findings []Finding) intel.RiskPicture {
	var fs []intel.Finding
	for _, f := range findings {
		if f.Severity == "info" || (f.IssueKey == "" && f.Technique == "") {
			continue
		}
		fs = append(fs, intel.Finding{
			Module:    f.Module,
			Technique: f.Technique,
			IssueKey:  f.IssueKey,
			Severity:  strings.ToLower(f.Severity),
			Title:     f.Title,
			URL:       f.URL,
		})
	}
	return intel.Correlate("", fs)
}

func scopeSummary(snap scope.Snapshot) ScopeSummary {
	ss := ScopeSummary{InScope: snap.InScope, Exclude: snap.Exclude}
	var parts []string
	if !snap.Start.IsZero() {
		parts = append(parts, "from "+snap.Start.UTC().Format(time.RFC3339))
	}
	if !snap.End.IsZero() {
		parts = append(parts, "until "+snap.End.UTC().Format(time.RFC3339))
	}
	if snap.HoursSet {
		parts = append(parts, fmt.Sprintf("hours %02d:00–%02d:00", snap.StartHour, snap.EndHour))
	}
	if len(snap.Days) > 0 {
		days := make([]string, 0, len(snap.Days))
		for _, d := range snap.Days {
			days = append(days, d.String()[:3])
		}
		parts = append(parts, "days "+strings.Join(days, ", "))
	}
	if len(parts) == 0 {
		ss.Window = "no time restriction"
	} else {
		ss.Window = strings.Join(parts, "; ")
	}
	return ss
}

// findingFromResult flattens a module result's data payload into a Finding.
func findingFromResult(res module.Result) Finding {
	f := Finding{
		Module:    res.Capability,
		Technique: res.Technique,
		Severity:  "info",
	}
	d := res.Data
	if s, ok := d["severity"].(string); ok && s != "" {
		f.Severity = s
	}
	f.Title = str(d["title"])
	f.URL = str(d["url"])
	f.Description = str(d["description"])
	f.Remediation = str(d["remediation"])
	// The structured blue-team answer, derived from the finding's issue key and
	// technique. Re-derived here so the report is correct whether or not the
	// stored payload was already enriched.
	f.IssueKey = str(d["issueKey"])
	f.Guidance = remediation.For(f.IssueKey, res.Technique, f.Remediation)
	if f.Remediation == "" {
		f.Remediation = f.Guidance.Summary
	}
	f.Plain = f.Guidance.PlainSummary
	if p, ok := d["remediationPlain"].(string); ok && p != "" {
		f.Plain = p
	}
	if ev, ok := d["evidence"].(map[string]any); ok {
		f.Proof = str(ev["proof"])
		f.Request = str(ev["request"])
	}
	if res.Proof != nil {
		if f.Proof == "" {
			f.Proof = res.Proof.Summary
		}
		f.ProofFingerprint = res.Proof.Fingerprint
	}
	if f.Title == "" {
		f.Title = "(untitled finding)"
	}
	if f.URL == "" {
		f.URL = targetLabel(res.Target)
	}
	return f
}

// evidenceFromResult flattens an evidence module result into an EvidenceItem for
// the chain-of-custody section.
func evidenceFromResult(res module.Result) EvidenceItem {
	d := res.Data
	e := EvidenceItem{
		Name:        str(d["name"]),
		SHA256:      str(d["sha256"]),
		SHA1:        str(d["sha1"]),
		Size:        intOf(d["size"]),
		ContentType: str(d["contentType"]),
		IngestedAt:  str(d["ingestedAt"]),
		Source:      str(d["source"]),
	}
	if e.Name == "" {
		e.Name = targetLabel(res.Target)
	}
	return e
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64: // JSON round-trip through structpb/maps lands here
		return int(n)
	default:
		return 0
	}
}

func targetLabel(t module.Target) string {
	if t.URL != "" {
		return t.URL
	}
	if t.Port != 0 {
		return fmt.Sprintf("%s:%d", t.Host, t.Port)
	}
	return t.Host
}
