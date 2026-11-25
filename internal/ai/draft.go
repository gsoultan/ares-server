// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gsoultan/ares/module/scaffold"
)

// FeatureDraftModule drafts a first-cut detection module from a CVE
// description or from what an engagement has observed. The draft is a
// proposal a person reviews and finishes; nothing here writes, compiles,
// registers or runs it.
const FeatureDraftModule = "draft-module"

// maxBrief bounds the operator's brief, so one request stays reviewable and
// within token limits.
const maxBrief = 8000

// draftMaxTokens is the floor on output tokens for a draft: a spec with its
// examples and remediation does not fit the default advisory budget.
const draftMaxTokens = 4096

// draftExample is the scaffold's own tested example spec, shown to the model
// as the shape to fill. Keep it in step with
// github.com/gsoultan/ares/cmd/aresmod/example.json.
//
//go:embed draft_example.json
var draftExample string

// draftSystem is the guardrail every draft call carries. On top of the
// advisory rules it fixes what a draft may be: a declarative spec for one
// level-1, read-only check, never code and never an exploit.
const draftSystem = `You are the module-drafting assistant inside Ares, an authorized security-testing platform. You draft a first-cut detection check that a security engineer will review, finish and test before it is ever used.

Strict rules you must always follow:
- You are advisory only. You do not and cannot run tools, dispatch jobs, change scope, or authorize testing. Your draft is never run as you write it: a person reviews it, and once merged it runs only under Ares's own scope and authorization gate.
- You never write code. You return one JSON object in the spec format shown, and Ares renders it into code from fixed templates.
- The check is level 1, safe proof: one read-only GET or HEAD request to a path on the target, or reading a service's greeting banner on a TCP port. It confirms the weakness by observation: a version string, an exposed page's own marker, a header. Never include an exploit, payload, injection string, credential, write, or step-by-step weaponization in any field.
- If the weakness cannot be observed safely with one read-only request (it can only be confirmed by exploiting it, or needs authentication, a write or a sequence of requests), do not draft a spec. Return {"refusal": "<one sentence on why, and what a person would have to build by hand>"} instead.
- Ground every statement in the brief and the observations you are given. Do not invent versions, paths, CVEs or product behavior. Where the brief does not say, choose the most conservative detection and say what must be verified in the summary.
- The regex must match a distinctive marker of the vulnerable or exposed state, and must not match a patched or unrelated answer. The example must be a realistic answer that matches; the negative must be a realistic answer that does not.
- Use intendedProof "version" when the check reads a version, and "detection-only" otherwise.
- References are https URLs from the brief or the authoritative advisory (for a CVE, https://nvd.nist.gov/vuln/detail/<CVE id>).
- The guidance plainSummary is one or two short sentences with no jargon a site owner can act on.
- The name must not be one of the existing module names you are given.
- Reply with the JSON object only: no prose, no markdown fence.`

// ModuleDraftInput is what grounds a draft: the operator's brief, and the
// engagement's observations when there are any.
type ModuleDraftInput struct {
	// Brief is the CVE id and description, or the weakness to check for, as the
	// operator wrote it.
	Brief string `json:"brief"`
	// Target, Signals and AlreadyRun describe the engagement the operator
	// drafts from, when there is one.
	Target     string   `json:"target,omitempty"`
	Signals    []string `json:"signals,omitempty"`
	AlreadyRun []string `json:"alreadyRun,omitempty"`
	// ExistingModules are the registered module names, so the draft does not
	// reuse one.
	ExistingModules []string `json:"existingModules,omitempty"`
}

// ModuleDraft is the reviewed-by-nobody-yet result of one draft call. When
// the model's spec fails validation, Problems lists why and Files is empty;
// the spec is still returned so a person can fix it and render it with
// cmd/aresmod.
type ModuleDraft struct {
	Name     string          `json:"name,omitempty"`
	Spec     *scaffold.Spec  `json:"spec,omitempty"`
	SpecJSON string          `json:"specJson,omitempty"`
	Files    []scaffold.File `json:"files,omitempty"`
	Notes    []string        `json:"notes,omitempty"`
	Problems []string        `json:"problems,omitempty"`
	Refusal  string          `json:"refusal,omitempty"`
}

// Rendered reports whether the draft passed validation and has files.
func (d ModuleDraft) Rendered() bool { return len(d.Files) > 0 }

var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// ErrEmptyBrief is returned when a draft is asked for with nothing to draft.
var ErrEmptyBrief = errors.New("ai: draft-module needs a brief: a CVE id and description, or the weakness to check for")

// DraftModule asks the model for a module spec, then validates and renders it
// with the module scaffold. The model's output is data: it is parsed strictly,
// its provenance is overwritten, and it reaches code only through the
// scaffold's fixed templates, which quote every value.
func (a *Advisor) DraftModule(ctx context.Context, in ModuleDraftInput) (ModuleDraft, Response, error) {
	in.Brief = strings.TrimSpace(in.Brief)
	if in.Brief == "" {
		return ModuleDraft{}, Response{}, ErrEmptyBrief
	}
	if len(in.Brief) > maxBrief {
		return ModuleDraft{}, Response{}, fmt.Errorf("ai: the brief is %d bytes; keep it under %d", len(in.Brief), maxBrief)
	}
	prompt := "Draft an Ares module spec for the brief below. Fill every field of the example spec's shape; " +
		"the example is about a different product and is only there to show the format.\n\n" +
		"Example spec:\n" + draftExample + "\n\n" +
		"Brief and observations:\n" + asJSON(in)
	maxTokens := a.maxTokens
	if maxTokens < draftMaxTokens {
		maxTokens = draftMaxTokens
	}
	resp, err := a.p.Complete(ctx, Request{
		System:    draftSystem,
		Messages:  []Message{{Role: RoleUser, Content: prompt}},
		MaxTokens: maxTokens,
	})
	if err != nil {
		return ModuleDraft{}, Response{}, err
	}
	model := resp.Model
	if model == "" {
		model = a.p.Model()
	}
	d := buildDraft(resp.Text, in, a.p.Name()+" "+model)
	resp.Text = d.Markdown()
	return d, resp, nil
}

// buildDraft turns the model's reply into a draft. It never fails: what goes
// wrong is recorded in Problems, so the operator sees why.
func buildDraft(reply string, in ModuleDraftInput, by string) ModuleDraft {
	var d ModuleDraft
	raw, ok := jsonObject(reply)
	if !ok {
		d.Problems = []string{"the model did not return a JSON spec"}
		return d
	}
	var refusal struct {
		Refusal string `json:"refusal"`
	}
	if json.Unmarshal([]byte(raw), &refusal) == nil && strings.TrimSpace(refusal.Refusal) != "" {
		d.Refusal = strings.TrimSpace(refusal.Refusal)
		return d
	}
	spec, err := scaffold.Parse([]byte(raw))
	if err != nil {
		d.Problems = []string{err.Error()}
		d.SpecJSON = raw
		return d
	}
	// Provenance is Ares's to state, not the model's.
	spec.V = scaffold.SpecVersion
	spec.Origin = scaffold.Origin{Source: "manual", By: "the Ares AI advisor (" + by + ")"}
	if id := cveRe.FindString(in.Brief); id != "" {
		spec.Origin.Source, spec.Origin.Ref = "cve", strings.ToUpper(id)
	} else if in.Target != "" {
		spec.Origin.Source, spec.Origin.Ref = "target", in.Target
	}
	d.Spec, d.Name = spec, spec.Name
	if b, err := json.MarshalIndent(spec, "", "  "); err == nil {
		d.SpecJSON = string(b)
	}
	for _, name := range in.ExistingModules {
		if name == spec.Name {
			d.Problems = append(d.Problems, fmt.Sprintf("name %q is already a registered module; pick another", spec.Name))
		}
	}
	if err := spec.Validate(); err != nil {
		d.Problems = append(d.Problems, strings.Split(err.Error(), "\n")...)
	}
	if len(d.Problems) > 0 {
		return d
	}
	files, err := scaffold.Render(spec)
	if err != nil {
		d.Problems = []string{err.Error()}
		return d
	}
	d.Files = files
	d.Notes = append([]string{
		"This is an AI draft. Nothing in it has run, and Ares has not written it anywhere: copy the files into an ares branch, or save the spec and run go run ./cmd/aresmod spec.json.",
	}, scaffold.ReviewNotes(spec)...)
	return d
}

// jsonObject returns the outermost JSON object in a reply, tolerating a
// markdown fence or a sentence around it.
func jsonObject(s string) (string, bool) {
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i < 0 || j < i {
		return "", false
	}
	raw := s[i : j+1]
	if !json.Valid([]byte(raw)) {
		return "", false
	}
	return raw, true
}

// Markdown renders the draft for the advisory text panel.
func (d ModuleDraft) Markdown() string {
	var b strings.Builder
	switch {
	case d.Refusal != "":
		b.WriteString("The advisor did not draft a module: " + d.Refusal + "\n")
		return b.String()
	case !d.Rendered():
		b.WriteString("The advisor's draft did not pass the scaffold's checks, so no files were rendered:\n\n")
		for _, p := range d.Problems {
			b.WriteString("- " + p + "\n")
		}
		if d.SpecJSON != "" {
			b.WriteString("\nThe spec it returned, to fix and render with `go run ./cmd/aresmod spec.json`:\n\n```json\n" + d.SpecJSON + "\n```\n")
		}
		return b.String()
	}
	fmt.Fprintf(&b, "Draft module **%s**: %s (%s, level 1 safe proof, %s).\n\n", d.Spec.Name, d.Spec.Title, d.Spec.Severity, d.Spec.Surface)
	b.WriteString("Before it merges:\n\n")
	for i, n := range d.Notes {
		fmt.Fprintf(&b, "%d. %s\n", i+1, n)
	}
	b.WriteString("\nFiles:\n\n")
	for _, f := range d.Files {
		b.WriteString("- `" + f.Path + "`\n")
	}
	b.WriteString("\nSpec:\n\n```json\n" + d.SpecJSON + "\n```\n")
	return b.String()
}
