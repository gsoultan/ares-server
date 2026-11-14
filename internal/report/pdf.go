// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/ares/intel"
	"github.com/gsoultan/ares/remediation"
)

// A minimal PDF writer. It lays text out in the three standard Courier fonts
// (no font embedding, so the file needs no external resources) and paginates
// Letter pages. Courier is monospaced, so line wrapping is exact from the
// character count — no font-metric tables required. This keeps report
// generation inside the standard library and the binary self-contained.

const (
	pdfPageW    = 612.0 // US Letter, points
	pdfPageH    = 792.0
	pdfMargin   = 54.0 // 0.75"
	pdfCharWMul = 0.6  // Courier advance width = 0.6em
)

// font references in the page resources.
const (
	fontRegular = "/F1"
	fontBold    = "/F2"
	fontOblique = "/F3"
)

type pline struct {
	font   string
	size   float64
	indent float64
	text   string
}

type pdfBuilder struct{ lines []pline }

func (b *pdfBuilder) contentWidth(indent float64) float64 { return pdfPageW - 2*pdfMargin - indent }

// push wraps text to the content width and appends one pline per physical line.
func (b *pdfBuilder) push(font string, size, indent float64, text string) {
	maxChars := int(b.contentWidth(indent) / (size * pdfCharWMul))
	if maxChars < 8 {
		maxChars = 8
	}
	for _, seg := range strings.Split(text, "\n") {
		for _, wrapped := range wrap(seg, maxChars) {
			b.lines = append(b.lines, pline{font: font, size: size, indent: indent, text: wrapped})
		}
	}
}

func (b *pdfBuilder) h1(text string)   { b.push(fontBold, 15, 0, text); b.spacer(6) }
func (b *pdfBuilder) h2(text string)   { b.spacer(6); b.push(fontBold, 12, 0, text); b.spacer(2) }
func (b *pdfBuilder) h3(text string)   { b.spacer(4); b.push(fontBold, 11, 0, text) }
func (b *pdfBuilder) body(text string) { b.push(fontRegular, 10, 0, text) }
func (b *pdfBuilder) label(k, v string) {
	b.push(fontBold, 10, 0, k)
	b.push(fontRegular, 10, 12, v)
}
func (b *pdfBuilder) code(text string) { b.push(fontOblique, 9, 12, text) }
func (b *pdfBuilder) spacer(h float64) { b.lines = append(b.lines, pline{size: h}) }

// writeRiskPDF renders the correlated, prioritized attack paths.
func (b *pdfBuilder) writeRiskPDF(risk intel.RiskPicture) {
	if len(risk.Paths) == 0 {
		return
	}
	b.h2("Risk picture — prioritized attack paths")
	b.body(fmt.Sprintf("Overall risk: %s (score %d/100). Ares correlated the findings into %d attack path(s), most urgent first.",
		strings.ToUpper(risk.Rating), risk.Score, len(risk.Paths)))
	for i, p := range risk.Paths {
		b.h3(fmt.Sprintf("%d. [%s] %s — priority %d/100", i+1, strings.ToUpper(p.Severity), p.Name, p.Priority))
		b.label("Outcome", p.Outcome)
		b.label("Why it matters", p.Why)
		for _, s := range p.Steps {
			tech := ""
			if s.Technique != "" {
				tech = " [" + s.Technique + "]"
			}
			b.push(fontRegular, 10, 12, fmt.Sprintf("- (%s) %s%s", s.Role, s.Title, tech))
		}
	}
}

// writeGuidancePDF renders the structured blue-team remediation: a plain "how to
// fix it" summary, then the technical fix / prevent / detect / verify steps and
// the ATT&CK mitigations.
func (b *pdfBuilder) writeGuidancePDF(g remediation.Guidance, summary string) {
	if summary == "" {
		summary = g.Summary
	}
	if summary != "" {
		b.label("How to fix it", summary)
	}
	b.guidanceSteps("Fix — technical steps", g.Fix)
	b.guidanceSteps("Prevent it recurring", g.Prevent)
	b.guidanceSteps("How it's detected", g.Detect)
	b.guidanceSteps("Verify the fix", g.Verify)
	if len(g.Mitigations) > 0 {
		parts := make([]string, 0, len(g.Mitigations))
		for _, m := range g.Mitigations {
			parts = append(parts, m.ID+" ("+m.Name+")")
		}
		b.label("ATT&CK mitigations", strings.Join(parts, ", "))
	}
}

func (b *pdfBuilder) guidanceSteps(heading string, steps []remediation.Step) {
	if len(steps) == 0 {
		return
	}
	b.push(fontBold, 10, 6, heading+":")
	for _, s := range steps {
		b.push(fontRegular, 10, 12, "- "+s.Text)
		if s.Code != "" {
			for _, line := range strings.Split(s.Code, "\n") {
				b.code(line)
			}
		}
	}
}

// placed is a line assigned to a page at an absolute baseline.
type placed struct {
	x, y float64
	pline
}

func (b *pdfBuilder) paginate() [][]placed {
	var pages [][]placed
	var cur []placed
	y := pdfPageH - pdfMargin
	for _, ln := range b.lines {
		lh := ln.size * 1.3
		if ln.text == "" { // spacer
			y -= lh
			continue
		}
		if y-lh < pdfMargin {
			pages = append(pages, cur)
			cur = nil
			y = pdfPageH - pdfMargin
		}
		y -= lh
		cur = append(cur, placed{x: pdfMargin + ln.indent, y: y, pline: ln})
	}
	pages = append(pages, cur)
	return pages
}

// PDF renders the report as a PDF document.
func (r Report) PDF() []byte {
	b := &pdfBuilder{}
	b.h1("Security assessment — " + r.Meta.EngagementName)
	b.body("Generated " + r.Generated.Format(time.RFC3339))

	b.h2("Engagement")
	b.label("Workspace", orNA(r.Meta.Workspace))
	b.label("Engagement", fmt.Sprintf("%s (%s)", r.Meta.EngagementName, r.Meta.EngagementID))
	b.label("Status", r.Meta.Status)
	b.label("Created", r.Meta.CreatedAt.UTC().Format(time.RFC3339))
	if r.Meta.Authorized {
		b.label("Authorization", fmt.Sprintf("%s — approved by %s on %s",
			r.Meta.AuthDocument, r.Meta.AuthApprovedBy, r.Meta.AuthApprovedAt.UTC().Format(time.RFC3339)))
	} else {
		b.label("Authorization", "not on file")
	}
	b.label("Audit trail", fmt.Sprintf("%d entries, %s", r.Audit.Entries, validLabel(r.Audit.Valid)))

	b.h2("Scope (the permission gate)")
	b.label("In scope", listOrNone(r.Scope.InScope))
	b.label("Exclusions", listOrNone(r.Scope.Exclude))
	b.label("Window", r.Scope.Window)

	b.writeRiskPDF(r.Risk)

	b.h2("Findings")
	b.label("Summary", r.SeveritySummary())
	if len(r.Findings) == 0 {
		b.body("No findings were raised.")
	}
	for i, f := range r.Findings {
		b.h3(fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title))
		if f.URL != "" {
			b.label("URL", f.URL)
		}
		if f.Module != "" {
			b.label("Module", f.Module)
		}
		if f.Technique != "" {
			b.label("ATT&CK", f.Technique)
		}
		if f.Description != "" {
			b.label("What it means", f.Description)
		}
		b.writeGuidancePDF(f.Guidance, f.Remediation)
		if f.Proof != "" {
			b.label("Proof", f.Proof)
		}
		if f.Request != "" {
			b.code(f.Request)
		}
	}

	if r.Detection.Total > 0 {
		b.h2("Detection coverage")
		b.label("Coverage", fmt.Sprintf("%d%% — defenders prevented or detected %d of %d techniques the test exercised",
			r.Detection.CoveragePercent, r.Detection.Covered(), r.Detection.Total))
		for _, t := range r.Detection.Techniques {
			b.body(fmt.Sprintf("%s — %d finding(s) — %s", t.Technique, t.Findings, t.Outcome))
		}
	}

	b.writeEvidencePDF(r)

	return assemblePDF(b.paginate())
}

// writeEvidencePDF renders the forensic chain-of-custody section: each ingested
// artifact and its hash, under the integrity of the audit trail that anchors
// them. It renders only when evidence was ingested.
func (b *pdfBuilder) writeEvidencePDF(r Report) {
	if len(r.Evidence) == 0 {
		return
	}
	b.h2("Evidence & chain of custody")
	b.body(fmt.Sprintf("%d artifact(s) were ingested for analysis. Each item's SHA-256 is anchored into the engagement's tamper-evident audit trail (%d entries, %s), so this custody record can be independently verified and cannot be altered without breaking the chain.",
		len(r.Evidence), r.Audit.Entries, validLabel(r.Audit.Valid)))
	for i, e := range r.Evidence {
		b.h3(fmt.Sprintf("%d. %s", i+1, orNA(e.Name)))
		b.label("SHA-256", orNA(e.SHA256))
		b.label("Size / type", fmt.Sprintf("%d bytes — %s", e.Size, orNA(e.ContentType)))
		b.label("Ingested (UTC)", orNA(e.IngestedAt))
		if e.Source != "" {
			b.label("Source", e.Source)
		}
	}
}

// assemblePDF writes the PDF object graph: catalog, page tree, three standard
// fonts, and a page + content-stream object per page.
func assemblePDF(pages [][]placed) []byte {
	const (
		objCatalog = 1
		objPages   = 2
		objF1      = 3
		objF2      = 4
		objF3      = 5
		firstPage  = 6 // page k: obj firstPage+2k, its content: firstPage+2k+1
	)
	totalObjs := 5 + 2*len(pages)

	offsets := make([]int, totalObjs+1) // 1-indexed
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	obj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}

	// Page kids list.
	kids := make([]string, len(pages))
	for k := range pages {
		kids[k] = fmt.Sprintf("%d 0 R", firstPage+2*k)
	}

	obj(objCatalog, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(objPages, fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] /MediaBox [0 0 %g %g] >>",
		len(pages), strings.Join(kids, " "), pdfPageW, pdfPageH))
	obj(objF1, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
	obj(objF2, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>")
	obj(objF3, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Oblique >>")

	for k, page := range pages {
		pageObj := firstPage + 2*k
		contentObj := pageObj + 1
		obj(pageObj, fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /Contents %d 0 R "+
				"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>", contentObj))

		var cs strings.Builder
		cs.WriteString("BT\n")
		for _, ln := range page {
			fmt.Fprintf(&cs, "%s %g Tf\n1 0 0 1 %g %g Tm\n(%s) Tj\n",
				ln.font, ln.size, ln.x, ln.y, escapePDFText(ln.text))
		}
		cs.WriteString("ET\n")
		stream := cs.String()
		obj(contentObj, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream))
	}

	// xref table.
	xrefPos := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", totalObjs+1)
	buf.WriteString("0000000000 65535 f \n")
	for n := 1; n <= totalObjs; n++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[n])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		totalObjs+1, xrefPos)
	return buf.Bytes()
}

// escapePDFText escapes PDF string delimiters and transliterates the few
// non-ASCII runes a report tends to carry (dashes, smart quotes, ellipsis) to
// ASCII, mapping anything else outside printable ASCII to '?', so arbitrary
// finding text cannot break the content stream.
func escapePDFText(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		case '\r', '\n', '\t':
			b.WriteByte(' ')
		case '–', '—':
			b.WriteByte('-')
		case '“', '”':
			b.WriteByte('"')
		case '‘', '’':
			b.WriteByte('\'')
		case '…':
			b.WriteString("...")
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.String()
}

// wrap breaks s into lines of at most maxChars characters, preferring to break
// on spaces and hard-splitting any single token longer than the width.
func wrap(s string, maxChars int) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for _, word := range splitKeepLong(strings.Fields(s), maxChars) {
		if len(out) == 0 {
			out = append(out, word)
			continue
		}
		last := out[len(out)-1]
		if len(last)+1+len(word) <= maxChars {
			out[len(out)-1] = last + " " + word
		} else {
			out = append(out, word)
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// splitKeepLong hard-splits any word longer than maxChars into chunks.
func splitKeepLong(words []string, maxChars int) []string {
	var out []string
	for _, w := range words {
		for len(w) > maxChars {
			out = append(out, w[:maxChars])
			w = w[maxChars:]
		}
		out = append(out, w)
	}
	return out
}
