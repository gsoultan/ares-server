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

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

func sampleReport(t *testing.T) Report {
	t.Helper()
	store := engagement.NewMemStore()
	eng, err := store.Create("", "Acme external perimeter")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := eng.Scope.AddInScope("acme.example.com"); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if err := eng.Scope.AddExclusion("vip.acme.example.com"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	if err := eng.Authorize(engagement.Authorization{Document: "loa.pdf", ApprovedBy: "Lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	finding := func(sev, title string) module.Result {
		return module.Result{
			Capability: "webcheck", Kind: "finding", Technique: "T1190",
			Data: map[string]any{
				"severity": sev, "title": title,
				"url":         "https://acme.example.com/x",
				"description": "A weakness was observed.",
				"remediation": "Fix it.",
				"evidence":    map[string]any{"proof": "matched [core]", "request": "GET /x"},
			},
		}
	}
	outcomes := []worker.Outcome{{
		Engagement: eng.ID,
		Results: []module.Result{
			finding("low", "Low thing"),
			finding("critical", "Critical thing"),
			finding("medium", "Medium thing"),
			{Capability: "portscan", Kind: "asset", Data: map[string]any{"port": 443}}, // not a finding
		},
	}}

	return Build(eng, "Acme Corp", outcomes)
}

func TestBuildSortsAndCounts(t *testing.T) {
	r := sampleReport(t)

	if len(r.Findings) != 3 {
		t.Fatalf("findings = %d, want 3 (asset excluded)", len(r.Findings))
	}
	if r.Findings[0].Severity != "critical" || r.Findings[2].Severity != "low" {
		t.Fatalf("findings not sorted most-serious first: %v", []string{
			r.Findings[0].Severity, r.Findings[1].Severity, r.Findings[2].Severity})
	}
	if r.Meta.Workspace != "Acme Corp" || !r.Meta.Authorized {
		t.Fatalf("meta not populated: %+v", r.Meta)
	}
	if got := r.SeveritySummary(); got != "1 critical, 1 medium, 1 low" {
		t.Fatalf("severity summary = %q", got)
	}
	if len(r.Scope.InScope) != 1 || len(r.Scope.Exclude) != 1 {
		t.Fatalf("scope summary wrong: %+v", r.Scope)
	}
}

func TestChainOfCustodySection(t *testing.T) {
	store := engagement.NewMemStore()
	eng, _ := store.Create("", "IR-2026-07")
	_ = eng.Authorize(engagement.Authorization{Document: "ir.pdf", ApprovedBy: "DFIR Lead"})
	out := []worker.Outcome{{Engagement: eng.ID, Results: []module.Result{
		{Capability: "evidence", Kind: "evidence", Target: module.Target{URL: "evidence://disk.img"},
			Data: map[string]any{
				"name": "disk.img", "sha256": "abc123", "sha1": "def456",
				"size": 2048, "contentType": "application/octet-stream",
				"ingestedAt": "2026-11-14T03:00:00Z", "source": "host-07",
			}},
	}}}
	r := Build(eng, "Acme Corp", out)

	if len(r.Evidence) != 1 {
		t.Fatalf("evidence results must be collected, got %d", len(r.Evidence))
	}
	if r.Evidence[0].SHA256 != "abc123" || r.Evidence[0].Size != 2048 {
		t.Errorf("evidence item not flattened: %+v", r.Evidence[0])
	}
	// Evidence is not a finding.
	if len(r.Findings) != 0 {
		t.Errorf("evidence must not appear as a finding: %+v", r.Findings)
	}

	md := string(r.Markdown())
	for _, want := range []string{
		"## Evidence & chain of custody",
		"disk.img",
		"abc123",
		"host-07",
		"No findings were raised.", // forensic-only report still renders custody
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestMarkdown(t *testing.T) {
	md := string(sampleReport(t).Markdown())
	for _, want := range []string{
		"# Security assessment — Acme external perimeter",
		"## Findings",
		"[CRITICAL] Critical thing",
		"**What it means:** A weakness was observed.",
		"**How to fix it:** Fix it.",
		"Prevent it recurring",
		"How it's detected",
		"Verify the fix",
		"**ATT&CK mitigations:**", // T1190 contributes mitigations
		"acme.example.com",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestPDFStructure(t *testing.T) {
	pdf := sampleReport(t).PDF()
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Fatal("output is not a PDF")
	}
	if !bytes.Contains(pdf, []byte("%%EOF")) {
		t.Fatal("PDF has no EOF marker")
	}
	if !bytes.Contains(pdf, []byte("/Type /Catalog")) || !bytes.Contains(pdf, []byte("startxref")) {
		t.Fatal("PDF missing catalog or xref")
	}
	if !bytes.Contains(pdf, []byte("Critical thing")) {
		t.Fatal("PDF missing a finding title")
	}
	if len(pdf) < 1000 {
		t.Fatalf("PDF implausibly small: %d bytes", len(pdf))
	}
}

func TestPDFEscapesParens(t *testing.T) {
	// A title with unbalanced parens must not corrupt the content stream.
	store := engagement.NewMemStore()
	eng, _ := store.Create("", "Paren (test")
	out := []worker.Outcome{{Engagement: eng.ID, Results: []module.Result{{
		Capability: "webcheck", Kind: "finding",
		Data: map[string]any{"severity": "high", "title": "a ) b ( c \\ d"},
	}}}}
	pdf := Build(eng, "W", out).PDF()
	if !bytes.Contains(pdf, []byte(`a \) b \( c \\ d`)) {
		t.Fatal("PDF did not escape parens/backslash in finding title")
	}
}

func TestDOCXIsValidZip(t *testing.T) {
	data, err := sampleReport(t).DOCX()
	if err != nil {
		t.Fatalf("DOCX: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	parts := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		parts[f.Name] = string(b)
	}
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml"} {
		if _, ok := parts[name]; !ok {
			t.Fatalf("docx missing required part %s", name)
		}
	}
	doc := parts["word/document.xml"]
	if !strings.Contains(doc, "Acme external perimeter") {
		t.Error("document.xml missing engagement name")
	}
	if !strings.Contains(doc, "Critical thing") {
		t.Error("document.xml missing a finding title")
	}
	// ATT&CK label carries an ampersand; it must be XML-escaped.
	if !strings.Contains(doc, "ATT&amp;CK") {
		t.Error("document.xml did not XML-escape the ampersand")
	}
}
