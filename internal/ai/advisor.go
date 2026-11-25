// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Notice is the per-engagement data-sharing notice the UI must show before the
// advisory layer is enabled for an engagement. Enabling it sends engagement
// data (findings, the recon profile, target identifiers) to the operator's
// chosen AI provider.
const Notice = "Enabling the AI advisor sends this engagement's data — findings, the recon " +
	"profile and target identifiers — to the configured AI provider for analysis. " +
	"The advisor only explains and suggests; it never runs a test, changes scope, or " +
	"bypasses authorization. Any target it suggests must be added to scope and " +
	"authorized by you before Ares will touch it."

// advisorSystem is the guardrail every advisory call carries. It fixes the
// model's role as strictly advisory and grounds it in the supplied data.
const advisorSystem = `You are the advisory analyst inside Ares, an authorized security-testing platform. You help the operator understand and prioritize findings from an engagement they are authorized to test.

Strict rules you must always follow:
- You are advisory only. You do not and cannot run tools, dispatch jobs, change scope, or authorize testing. Ares performs every action through its own scope and authorization gate, controlled by the operator — never by you.
- When you suggest a further check or a target, state plainly that the operator must add any new target to scope and authorize it before Ares will test it. Never imply you can act.
- Ground every statement in the data you are given. Do not invent findings, versions, CVEs, hosts or evidence that are not present. If the data is insufficient, say so.
- Never provide a working exploit, payload, or step-by-step weaponization. Explain the weakness, its impact, and the safe way to confirm or remediate it — the blue-team framing Ares uses.
- Be concise, concrete and technical. Write for a security engineer.`

// Advisor turns Ares domain data into grounded advisory text using one Provider.
// It is the only type callers use; it holds no ability to act on a target.
type Advisor struct {
	p         Provider
	maxTokens int
}

// NewAdvisor wraps a Provider. maxTokens<=0 leaves the provider default.
func NewAdvisor(p Provider, maxTokens int) *Advisor {
	return &Advisor{p: p, maxTokens: maxTokens}
}

// AdvisorFromEnv builds an Advisor from the ARES_AI_* environment. It returns
// ErrNotConfigured when no provider is set, which callers treat as "feature off".
func AdvisorFromEnv() (*Advisor, error) {
	cfg := ConfigFromEnv()
	p, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return NewAdvisor(p, cfg.MaxTokens), nil
}

// Provider exposes the underlying provider (for reporting which model answered).
func (a *Advisor) Provider() Provider { return a.p }

// Feature identifiers.
const (
	FeatureExplainFinding = "explain-finding"
	FeatureSuggestChecks  = "suggest-checks"
	FeatureNarratePaths   = "narrate-paths"
	FeatureDraftReport    = "draft-report"
	FeaturePlanNext       = "plan-next"
)

// Features lists the advisory features this layer offers.
func Features() []string {
	return []string{FeatureExplainFinding, FeatureSuggestChecks, FeatureNarratePaths, FeatureDraftReport, FeaturePlanNext}
}

// ---- Input types (plain data; the API handler maps Ares types into these) ----

// FindingInput is one finding, flattened for the advisor.
type FindingInput struct {
	Title       string         `json:"title,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Technique   string         `json:"technique,omitempty"`
	Target      string         `json:"target,omitempty"`
	IssueKey    string         `json:"issueKey,omitempty"`
	Module      string         `json:"module,omitempty"`
	Description string         `json:"description,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

// RecInput is one recon recommendation.
type RecInput struct {
	Module     string   `json:"module"`
	Confidence string   `json:"confidence,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
}

// ProfileInput is the recon profile plus what has already run.
type ProfileInput struct {
	Target          string     `json:"target"`
	Summary         string     `json:"summary,omitempty"`
	Signals         []string   `json:"signals,omitempty"`
	AlreadyRun      []string   `json:"alreadyRun,omitempty"`
	Recommendations []RecInput `json:"recommendations,omitempty"`
}

// StepInput is one step in an attack path.
type StepInput struct {
	Title     string `json:"title"`
	Technique string `json:"technique,omitempty"`
	Role      string `json:"role,omitempty"`
}

// PathInput is one correlated attack path.
type PathInput struct {
	Name     string      `json:"name"`
	Outcome  string      `json:"outcome,omitempty"`
	Severity string      `json:"severity,omitempty"`
	Steps    []StepInput `json:"steps,omitempty"`
}

// RiskInput is the correlated risk picture.
type RiskInput struct {
	Target string      `json:"target"`
	Score  int         `json:"score"`
	Rating string      `json:"rating,omitempty"`
	Paths  []PathInput `json:"paths,omitempty"`
}

// ReportInput is the engagement-wide input for a report narrative.
type ReportInput struct {
	Engagement string         `json:"engagement,omitempty"`
	Target     string         `json:"target,omitempty"`
	Score      int            `json:"score,omitempty"`
	Rating     string         `json:"rating,omitempty"`
	Findings   []FindingInput `json:"findings,omitempty"`
}

// NextMoveInput is everything the advisor needs to reason about an attacker's
// next moves: what Ares has proven, what it only observed, the correlated attack
// paths, and what has already run. Proven findings are kept apart from observed
// ones so the advisor grounds the highest-priority moves in reproducible proof.
type NextMoveInput struct {
	Engagement string         `json:"engagement,omitempty"`
	Target     string         `json:"target,omitempty"`
	Score      int            `json:"score,omitempty"`
	Rating     string         `json:"rating,omitempty"`
	Proven     []FindingInput `json:"proven,omitempty"`
	Observed   []FindingInput `json:"observed,omitempty"`
	RanModules []string       `json:"ranModules,omitempty"`
	Techniques []string       `json:"techniques,omitempty"`
	Paths      []PathInput    `json:"paths,omitempty"`
}

// ---- Features ----

// ExplainFinding returns a plain-language explanation of one finding: what it
// is, why it matters, how it was confirmed, and how to remediate it.
func (a *Advisor) ExplainFinding(ctx context.Context, f FindingInput) (Response, error) {
	prompt := "Explain this single finding to the operator. Cover, in short paragraphs or tight bullets: " +
		"(1) what the weakness is in plain terms, (2) the concrete business/technical impact if left unfixed, " +
		"(3) how Ares confirmed it from the evidence shown (do not go beyond the evidence), and " +
		"(4) the most important remediation step. Keep it grounded in the data below.\n\n" +
		"Finding:\n" + asJSON(f)
	return a.complete(ctx, prompt)
}

// SuggestNextChecks reads the recon profile and recommends which checks to run
// next and why — always noting that any new target needs scope + authorization.
func (a *Advisor) SuggestNextChecks(ctx context.Context, p ProfileInput) (Response, error) {
	prompt := "Given this recon profile and the checks already run, recommend the most valuable checks to run next. " +
		"For each, give the Ares module name (from the recommendations when present), one sentence on why the profile warrants it, " +
		"and the ATT&CK technique it exercises. Prioritize by likely impact and by what the fingerprints actually support. " +
		"End with a one-line reminder that any target not already in scope must be added to scope and authorized before testing.\n\n" +
		"Profile:\n" + asJSON(p)
	return a.complete(ctx, prompt)
}

// NarrateAttackPaths turns the correlated risk picture into a prioritized
// narrative an operator (or a report reader) can follow.
func (a *Advisor) NarrateAttackPaths(ctx context.Context, r RiskInput) (Response, error) {
	prompt := "Narrate this correlated risk picture as a prioritized story. For each attack path, explain in plain language " +
		"how the chained findings lead to the stated outcome, which step is the linchpin to fix first, and why the priority is what it is. " +
		"Do not invent steps beyond those listed. Be concrete about the defender's highest-leverage fix.\n\n" +
		"Risk picture:\n" + asJSON(r)
	return a.complete(ctx, prompt)
}

// DraftReportNarrative drafts an executive-summary narrative for the engagement
// from its findings and overall rating.
func (a *Advisor) DraftReportNarrative(ctx context.Context, r ReportInput) (Response, error) {
	prompt := "Draft an executive summary for this engagement's report. Open with the overall risk posture and rating, " +
		"then summarize the most serious findings in order of severity and what they mean for the business, and close with the " +
		"priority remediation themes. Write for a mixed audience of executives and engineers. Ground everything in the findings below; " +
		"do not add findings or numbers that are not present.\n\n" +
		"Engagement data:\n" + asJSON(r)
	return a.complete(ctx, prompt)
}

// PlanNextMoves reasons over what Ares has proven, observed and already run and
// lays out the adversary's most likely next moves as a prioritized kill-chain,
// each mapped to an Ares module, an ATT&CK technique and the consent level it
// needs. It is strictly advisory: it proposes the plan, and the operator still
// adds any new target to scope, authorizes the level, and dispatches each step.
func (a *Advisor) PlanNextMoves(ctx context.Context, in NextMoveInput) (Response, error) {
	prompt := "You are given everything Ares has proven, only observed, and already run against this engagement. " +
		"Lay out the adversary's most likely next moves as a short, prioritized kill-chain of three to six steps. " +
		"For each step give, as a tight bullet: (1) the attacker's goal in one line; " +
		"(2) the specific weakness it builds on, citing the proven or observed finding by title — never rely on a finding that is not listed below; " +
		"(3) the single Ares module that would safely confirm the step and the ATT&CK technique it exercises; " +
		"(4) the consent level it needs — safe-proof, active-confirmation (per-engagement opt-in) or intrusive (a named per-target operator approval). " +
		"Order the steps so that moves unlocked by an already-proven finding come first. " +
		"When a step would need a host or target that is not already listed as in scope, say so plainly. " +
		"Close with one line making clear that Ares runs nothing from this plan on its own: the operator adds any new target to scope, authorizes the consent level, and dispatches each step.\n\n" +
		"Engagement data:\n" + asJSON(in)
	return a.complete(ctx, prompt)
}

func (a *Advisor) complete(ctx context.Context, prompt string) (Response, error) {
	return a.p.Complete(ctx, Request{
		System:    advisorSystem,
		Messages:  []Message{{Role: RoleUser, Content: prompt}},
		MaxTokens: a.maxTokens,
	})
}

// Advise dispatches by feature name, mapping the generic payload to the right
// input type. The payload is the feature's input marshaled as JSON.
func (a *Advisor) Advise(ctx context.Context, feature string, payload json.RawMessage) (Response, error) {
	switch feature {
	case FeatureExplainFinding:
		var f FindingInput
		if err := unmarshalPayload(payload, &f); err != nil {
			return Response{}, err
		}
		return a.ExplainFinding(ctx, f)
	case FeatureSuggestChecks:
		var p ProfileInput
		if err := unmarshalPayload(payload, &p); err != nil {
			return Response{}, err
		}
		return a.SuggestNextChecks(ctx, p)
	case FeatureNarratePaths:
		var r RiskInput
		if err := unmarshalPayload(payload, &r); err != nil {
			return Response{}, err
		}
		return a.NarrateAttackPaths(ctx, r)
	case FeatureDraftReport:
		var r ReportInput
		if err := unmarshalPayload(payload, &r); err != nil {
			return Response{}, err
		}
		return a.DraftReportNarrative(ctx, r)
	case FeaturePlanNext:
		var in NextMoveInput
		if err := unmarshalPayload(payload, &in); err != nil {
			return Response{}, err
		}
		return a.PlanNextMoves(ctx, in)
	default:
		return Response{}, fmt.Errorf("ai: unknown advisory feature %q (want %s)", feature, strings.Join(Features(), ", "))
	}
}

func unmarshalPayload(payload json.RawMessage, v any) error {
	if len(payload) == 0 {
		return nil
	}
	return json.Unmarshal(payload, v)
}

func asJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}
