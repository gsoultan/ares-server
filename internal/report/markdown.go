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

	"github.com/gsoultan/ares/intel"
	"github.com/gsoultan/ares/remediation"
)

// Markdown renders the report as GitHub-flavored Markdown, handy for pasting
// into a ticket or a wiki.
func (r Report) Markdown() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security assessment — %s\n\n", r.Meta.EngagementName)
	fmt.Fprintf(&b, "_Generated %s_\n\n", r.Generated.Format(time.RFC3339))

	b.WriteString("## Engagement\n\n")
	fmt.Fprintf(&b, "- **Workspace:** %s\n", orNA(r.Meta.Workspace))
	fmt.Fprintf(&b, "- **Engagement:** %s (`%s`)\n", r.Meta.EngagementName, r.Meta.EngagementID)
	fmt.Fprintf(&b, "- **Status:** %s\n", r.Meta.Status)
	fmt.Fprintf(&b, "- **Created:** %s\n", r.Meta.CreatedAt.UTC().Format(time.RFC3339))
	if r.Meta.Authorized {
		fmt.Fprintf(&b, "- **Authorization:** %s — approved by %s on %s\n",
			r.Meta.AuthDocument, r.Meta.AuthApprovedBy, r.Meta.AuthApprovedAt.UTC().Format(time.RFC3339))
	} else {
		b.WriteString("- **Authorization:** not on file\n")
	}
	fmt.Fprintf(&b, "- **Audit trail:** %d entries, %s\n\n", r.Audit.Entries, validLabel(r.Audit.Valid))

	b.WriteString("## Scope (the permission gate)\n\n")
	fmt.Fprintf(&b, "- **In scope:** %s\n", listOrNone(r.Scope.InScope))
	fmt.Fprintf(&b, "- **Exclusions:** %s\n", listOrNone(r.Scope.Exclude))
	fmt.Fprintf(&b, "- **Window:** %s\n\n", r.Scope.Window)

	writeRiskMarkdown(&b, r.Risk)

	b.WriteString("## Findings\n\n")
	fmt.Fprintf(&b, "**Summary:** %s\n\n", r.SeveritySummary())
	if len(r.Findings) == 0 {
		b.WriteString("No findings were raised.\n\n")
	}
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(f.Severity), f.Title)
		if f.URL != "" {
			fmt.Fprintf(&b, "- **URL:** %s\n", f.URL)
		}
		if f.Module != "" {
			fmt.Fprintf(&b, "- **Module:** %s\n", f.Module)
		}
		if f.Technique != "" {
			fmt.Fprintf(&b, "- **ATT&CK:** %s\n", f.Technique)
		}
		b.WriteString("\n")
		if f.Description != "" {
			fmt.Fprintf(&b, "**What it means:** %s\n\n", f.Description)
		}
		writeGuidanceMarkdown(&b, f.Guidance, f.Remediation)
		if f.Proof != "" {
			fmt.Fprintf(&b, "**Proof:** %s\n\n", f.Proof)
		}
		if f.Request != "" {
			fmt.Fprintf(&b, "```\n%s\n```\n\n", f.Request)
		}
	}

	if r.Detection.Total > 0 {
		b.WriteString("## Detection coverage\n\n")
		fmt.Fprintf(&b, "**Coverage: %d%%** — defenders prevented or detected %d of %d techniques the test exercised.\n\n",
			r.Detection.CoveragePercent, r.Detection.Covered(), r.Detection.Total)
		b.WriteString("| Technique | Findings | Defender outcome |\n|---|---|---|\n")
		for _, t := range r.Detection.Techniques {
			fmt.Fprintf(&b, "| %s | %d | %s |\n", t.Technique, t.Findings, t.Outcome)
		}
		b.WriteString("\n")
	}

	writeEvidenceMarkdown(&b, r)

	return []byte(b.String())
}

// writeEvidenceMarkdown renders the forensic chain-of-custody section: the
// artifacts ingested, their hashes, and the integrity of the audit trail that
// anchors them. It renders only when evidence was ingested.
func writeEvidenceMarkdown(b *strings.Builder, r Report) {
	if len(r.Evidence) == 0 {
		return
	}
	b.WriteString("## Evidence & chain of custody\n\n")
	fmt.Fprintf(b, "%d artifact(s) were ingested for analysis. Each item's SHA-256 is anchored into the engagement's tamper-evident audit trail (%d entries, %s), so this custody record can be independently verified and cannot be altered without breaking the chain.\n\n",
		len(r.Evidence), r.Audit.Entries, validLabel(r.Audit.Valid))
	b.WriteString("| # | Artifact | SHA-256 | Size | Type | Ingested (UTC) | Source |\n|---|---|---|---|---|---|---|\n")
	for i, e := range r.Evidence {
		fmt.Fprintf(b, "| %d | %s | `%s` | %d | %s | %s | %s |\n",
			i+1, orNA(e.Name), orNA(e.SHA256), e.Size, orNA(e.ContentType), orNA(e.IngestedAt), orNA(e.Source))
	}
	b.WriteString("\n")
}

// writeRiskMarkdown renders the correlated, prioritized attack paths — the
// deliberate "risk picture" rather than a flat list of findings.
func writeRiskMarkdown(b *strings.Builder, risk intel.RiskPicture) {
	if len(risk.Paths) == 0 {
		return
	}
	b.WriteString("## Risk picture — prioritized attack paths\n\n")
	fmt.Fprintf(b, "**Overall risk: %s (score %d/100).** Ares correlated the findings into %d attack path(s), most urgent first — rather than a flat list.\n\n",
		strings.ToUpper(risk.Rating), risk.Score, len(risk.Paths))
	for i, p := range risk.Paths {
		fmt.Fprintf(b, "### %d. [%s] %s — priority %d/100\n\n", i+1, strings.ToUpper(p.Severity), p.Name, p.Priority)
		fmt.Fprintf(b, "**Outcome:** %s\n\n", p.Outcome)
		fmt.Fprintf(b, "**Why it matters:** %s\n\n", p.Why)
		if len(p.Steps) > 0 {
			b.WriteString("**Chain:**\n\n")
			for _, s := range p.Steps {
				tech := ""
				if s.Technique != "" {
					tech = " [" + s.Technique + "]"
				}
				fmt.Fprintf(b, "- _(%s)_ %s%s\n", s.Role, s.Title, tech)
			}
			b.WriteString("\n")
		}
	}
	if len(risk.Unchained) > 0 {
		fmt.Fprintf(b, "_Other findings not part of a chain:_ %s\n\n", strings.Join(risk.Unchained, ", "))
	}
}

// writeGuidanceMarkdown renders the structured blue-team remediation: a plain
// "how to fix it" summary, then the technical fix / prevent / detect / verify
// steps and the ATT&CK mitigations. Falls back to the summary line alone when no
// structured guidance is available.
func writeGuidanceMarkdown(b *strings.Builder, g remediation.Guidance, summary string) {
	if summary == "" {
		summary = g.Summary
	}
	if summary != "" {
		fmt.Fprintf(b, "**How to fix it:** %s\n\n", summary)
	}
	writeSteps(b, "Fix — technical steps", g.Fix)
	writeSteps(b, "Prevent it recurring", g.Prevent)
	writeSteps(b, "How it's detected", g.Detect)
	writeSteps(b, "Verify the fix", g.Verify)
	if len(g.Mitigations) > 0 {
		parts := make([]string, 0, len(g.Mitigations))
		for _, m := range g.Mitigations {
			parts = append(parts, fmt.Sprintf("%s (%s)", m.ID, m.Name))
		}
		fmt.Fprintf(b, "**ATT&CK mitigations:** %s\n\n", strings.Join(parts, ", "))
	}
	if len(g.References) > 0 {
		fmt.Fprintf(b, "**References:** %s\n\n", strings.Join(g.References, ", "))
	}
}

func writeSteps(b *strings.Builder, heading string, steps []remediation.Step) {
	if len(steps) == 0 {
		return
	}
	fmt.Fprintf(b, "_%s:_\n\n", heading)
	for _, s := range steps {
		fmt.Fprintf(b, "- %s\n", s.Text)
		if s.Code != "" {
			lang := s.Lang
			fmt.Fprintf(b, "  ```%s\n", lang)
			for _, line := range strings.Split(s.Code, "\n") {
				fmt.Fprintf(b, "  %s\n", line)
			}
			b.WriteString("  ```\n")
		}
	}
	b.WriteString("\n")
}

func orNA(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func listOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, ", ")
}

func validLabel(valid bool) string {
	if valid {
		return "verified intact"
	}
	return "VERIFICATION FAILED"
}
