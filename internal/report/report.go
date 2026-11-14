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
// outcomes of every job it ran. Findings are ordered most serious first.
func Build(eng *engagement.Engagement, workspace string, outcomes []worker.Outcome) Report {
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
			switch res.Kind {
			case "finding", "info":
				r.Findings = append(r.Findings, findingFromResult(res))
			case "evidence":
				r.Evidence = append(r.Evidence, evidenceFromResult(res))
			}
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return severityRank(r.Findings[i].Severity) < severityRank(r.Findings[j].Severity)
	})
	sort.SliceStable(r.Evidence, func(i, j int) bool {
		if r.Evidence[i].IngestedAt != r.Evidence[j].IngestedAt {
			return r.Evidence[i].IngestedAt < r.Evidence[j].IngestedAt
		}
		return r.Evidence[i].Name < r.Evidence[j].Name
	})
	r.Detection = detection.BuildSummary(ExercisedTechniques(outcomes), eng.Detections())
	r.Risk = correlateFindings(r.Findings)
	return r
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
	if ev, ok := d["evidence"].(map[string]any); ok {
		f.Proof = str(ev["proof"])
		f.Request = str(ev["request"])
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
