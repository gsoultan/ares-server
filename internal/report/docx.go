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
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/ares/remediation"
)

// A .docx is an Open Packaging Convention zip of XML parts. The three parts
// below are the minimum Word opens: the content-type map, the package
// relationships, and the document body itself. Building them directly keeps the
// report writer dependency-free.

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const docxRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

// DOCX renders the report as a Word document.
func (r Report) DOCX() ([]byte, error) {
	var body strings.Builder

	heading := func(text string, sizeHalfPt int) {
		fmt.Fprintf(&body,
			`<w:p><w:pPr><w:spacing w:before="200" w:after="80"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="%d"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
			sizeHalfPt, xmlEscape(text))
	}
	// labelled renders "Label: value" with the label in bold.
	labelled := func(label, value string) {
		fmt.Fprintf(&body,
			`<w:p><w:r><w:rPr><w:b/><w:sz w:val="20"/></w:rPr><w:t xml:space="preserve">%s </w:t></w:r><w:r><w:rPr><w:sz w:val="20"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
			xmlEscape(label), xmlEscape(value))
	}
	para := func(text string) {
		if text == "" {
			body.WriteString(`<w:p/>`)
			return
		}
		fmt.Fprintf(&body,
			`<w:p><w:r><w:rPr><w:sz w:val="20"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
			xmlEscape(text))
	}
	mono := func(text string) {
		fmt.Fprintf(&body,
			`<w:p><w:r><w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
			xmlEscape(text))
	}

	heading(fmt.Sprintf("Security assessment — %s", r.Meta.EngagementName), 36)
	para(fmt.Sprintf("Generated %s", r.Generated.Format(time.RFC3339)))

	// renderBlocks writes the shared owner-facing blocks.
	renderBlocks := func(bs []block) {
		for _, bl := range bs {
			switch bl.kind {
			case bH2:
				heading(bl.text, 28)
			case bH3:
				heading(bl.text, 22)
			case bPara:
				para(bl.text)
			case bLabel:
				labelled(bl.label+":", bl.text)
			case bBullet:
				para("• " + bl.text)
			}
		}
	}
	renderBlocks(r.ownerBlocks())

	heading("Engagement", 28)
	labelled("Workspace:", orNA(r.Meta.Workspace))
	labelled("Engagement:", fmt.Sprintf("%s (%s)", r.Meta.EngagementName, r.Meta.EngagementID))
	labelled("Status:", r.Meta.Status)
	labelled("Created:", r.Meta.CreatedAt.UTC().Format(time.RFC3339))
	if r.Meta.Authorized {
		labelled("Authorization:", fmt.Sprintf("%s — approved by %s on %s",
			r.Meta.AuthDocument, r.Meta.AuthApprovedBy, r.Meta.AuthApprovedAt.UTC().Format(time.RFC3339)))
	} else {
		labelled("Authorization:", "not on file")
	}
	labelled("Audit trail:", fmt.Sprintf("%d entries, %s", r.Audit.Entries, validLabel(r.Audit.Valid)))

	heading("Scope (the permission gate)", 28)
	labelled("In scope:", listOrNone(r.Scope.InScope))
	labelled("Exclusions:", listOrNone(r.Scope.Exclude))
	labelled("Window:", r.Scope.Window)

	if len(r.Risk.Paths) > 0 {
		heading("Risk picture — prioritized attack paths", 28)
		para(fmt.Sprintf("Overall risk: %s (top path priority %d/100). Ares correlated the findings into %d attack path(s), most urgent first.",
			strings.ToUpper(r.Risk.Rating), r.Risk.Score, len(r.Risk.Paths)))
		for i, p := range r.Risk.Paths {
			heading(fmt.Sprintf("%d. [%s] %s — priority %d/100", i+1, strings.ToUpper(p.Severity), p.Name, p.Priority), 22)
			labelled("Outcome:", p.Outcome)
			labelled("Why it matters:", p.Why)
			for _, s := range p.Steps {
				tech := ""
				if s.Technique != "" {
					tech = " [" + s.Technique + "]"
				}
				para(fmt.Sprintf("• (%s) %s%s", s.Role, s.Title, tech))
			}
		}
	}

	heading("Findings", 28)
	labelled("Summary:", r.SeveritySummary())
	if len(r.Findings) == 0 {
		para("No findings were raised.")
	}
	for i, f := range r.Findings {
		heading(fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title), 24)
		renderBlocks(f.findingBlocks())
		if f.URL != "" {
			labelled("URL:", f.URL)
		}
		if f.Module != "" {
			labelled("Module:", f.Module)
		}
		if f.Technique != "" {
			labelled("ATT&CK:", f.Technique)
		}
		if f.Description != "" {
			labelled("What it means:", f.Description)
		}
		// Structured blue-team remediation: plain summary, then the technical
		// fix / prevent / detect / verify steps and the ATT&CK mitigations.
		g := f.Guidance
		summary := f.Remediation
		if summary == "" {
			summary = g.Summary
		}
		if summary != "" {
			labelled("How to fix it:", summary)
		}
		stepGroup := func(heading string, steps []remediation.Step) {
			if len(steps) == 0 {
				return
			}
			labelled(heading+":", "")
			for _, s := range steps {
				para("• " + s.Text)
				if s.Code != "" {
					for _, line := range strings.Split(s.Code, "\n") {
						mono(line)
					}
				}
			}
		}
		stepGroup("Fix — technical steps", g.Fix)
		stepGroup("Prevent it recurring", g.Prevent)
		stepGroup("How it's detected", g.Detect)
		stepGroup("Verify the fix", g.Verify)
		if len(g.Mitigations) > 0 {
			parts := make([]string, 0, len(g.Mitigations))
			for _, m := range g.Mitigations {
				parts = append(parts, m.ID+" ("+m.Name+")")
			}
			labelled("ATT&CK mitigations:", strings.Join(parts, ", "))
		}
		if f.Proof != "" {
			labelled("Proof:", f.Proof)
		}
		if f.Request != "" {
			mono(f.Request)
		}
	}

	if r.Detection.Total > 0 {
		heading("Detection coverage", 28)
		labelled("Coverage:", fmt.Sprintf("%d%% — defenders prevented or detected %d of %d techniques the test exercised",
			r.Detection.CoveragePercent, r.Detection.Covered(), r.Detection.Total))
		for _, t := range r.Detection.Techniques {
			para(fmt.Sprintf("%s — %d finding(s) — %s", t.Technique, t.Findings, t.Outcome))
		}
	}

	if len(r.Evidence) > 0 {
		heading("Evidence & chain of custody", 28)
		para(fmt.Sprintf("%d artifact(s) were ingested for analysis. Each item's SHA-256 is anchored into the engagement's tamper-evident audit trail (%d entries, %s), so this custody record can be independently verified and cannot be altered without breaking the chain.",
			len(r.Evidence), r.Audit.Entries, validLabel(r.Audit.Valid)))
		for i, e := range r.Evidence {
			heading(fmt.Sprintf("%d. %s", i+1, orNA(e.Name)), 22)
			labelled("SHA-256:", orNA(e.SHA256))
			labelled("Size / type:", fmt.Sprintf("%d bytes — %s", e.Size, orNA(e.ContentType)))
			labelled("Ingested (UTC):", orNA(e.IngestedAt))
			if e.Source != "" {
				labelled("Source:", e.Source)
			}
		}
	}

	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		body.String() +
		`<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr></w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := []struct{ name, content string }{
		{"[Content_Types].xml", docxContentTypes},
		{"_rels/.rels", docxRels},
		{"word/document.xml", doc},
	}
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			return nil, fmt.Errorf("docx: create %s: %w", p.name, err)
		}
		if _, err := w.Write([]byte(p.content)); err != nil {
			return nil, fmt.Errorf("docx: write %s: %w", p.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docx: finalize: %w", err)
	}
	return buf.Bytes(), nil
}

// xmlEscape escapes text for XML content and drops characters that are invalid
// in XML 1.0, so arbitrary finding text cannot corrupt the document.
func xmlEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\t', '\n', '\r':
			b.WriteRune(r)
		default:
			if r < 0x20 {
				continue // invalid XML 1.0 control char
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
