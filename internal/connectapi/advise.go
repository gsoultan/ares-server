// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/ai"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/report"
	"github.com/gsoultan/ares/intel"
)

// maxReportFindings bounds how many findings a draft-report prompt carries, to
// keep the request within sensible token limits.
const maxReportFindings = 40

// Advise returns grounded AI advisory text. It is strictly advisory: it never
// dispatches a job, changes scope, or bypasses the authorization gate — it only
// turns the engagement's own data into an explanation or suggestion. When no
// provider is configured the feature is off; sending data to the provider
// requires the operator's per-engagement opt-in.
func (h *Handler) Advise(ctx context.Context, req *connect.Request[aresv1.AdviseRequest]) (*connect.Response[aresv1.AdviseResponse], error) {
	feature := req.Msg.GetFeature()
	resp := &aresv1.AdviseResponse{Feature: feature, Notice: ai.Notice}

	// The provider is resolved per workspace: in-app settings first, then the
	// environment. Graceful fallback: nothing configured → the feature is absent.
	advisor := h.advisorFor(req.Msg.GetTenantId())
	if advisor == nil {
		resp.Enabled = false
		return connect.NewResponse(resp), nil
	}
	resp.Enabled = true
	resp.Provider = advisor.Provider().Name()
	resp.Model = advisor.Provider().Model()

	if !validFeature(feature) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("feature must be one of: explain-finding, suggest-checks, narrate-paths, draft-report, draft-module"))
	}
	if feature == ai.FeatureDraftModule && strings.TrimSpace(req.Msg.GetBrief()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, ai.ErrEmptyBrief)
	}

	// The engagement is always resolved (tenant-checked) so the data is grounded
	// in something the caller is authorized to see.
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}

	// Opt-in gate: nothing is sent to the provider without the operator's consent.
	if !req.Msg.GetOptIn() {
		resp.OptInRequired = true
		return connect.NewResponse(resp), nil
	}

	if feature == ai.FeatureDraftModule {
		return h.draftModule(ctx, advisor, resp, eng.ID, eng.Name, req.Msg.GetBrief())
	}

	engName := map[string]string{eng.ID: eng.Name}
	payload, err := h.buildAdvicePayload(feature, eng.ID, eng.Name, engName, req.Msg.GetFindingId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	out, err := advisor.Advise(ctx, feature, payload)
	if err != nil {
		// A provider/transport failure is surfaced for the UI rather than failing
		// the RPC; the error text is provider-supplied and key-free by construction.
		resp.Error = err.Error()
		return connect.NewResponse(resp), nil
	}
	resp.Text = out.Text
	resp.InputTokens = int32(out.Usage.InputTokens)
	resp.OutputTokens = int32(out.Usage.OutputTokens)
	if out.Model != "" {
		resp.Model = out.Model
	}
	return connect.NewResponse(resp), nil
}

// advisorFor returns the AI advisor for a workspace: one built from the
// workspace's in-app settings when a provider is configured there, otherwise the
// environment-configured advisor. It returns nil when neither is available, so
// the advisory feature is simply off. Key material from settings is used only to
// construct the provider and never leaves this process.
func (h *Handler) advisorFor(tenantID string) *ai.Advisor {
	if h.settings != nil {
		if cfg, err := h.settings.AIConfig(tenantID); err == nil && cfg.Enabled() {
			if p, perr := ai.New(cfg); perr == nil {
				return ai.NewAdvisor(p, cfg.MaxTokens)
			}
		}
	}
	return h.advisor
}

// draftModule asks the advisor for a first-cut module, grounded in the
// operator's brief and the engagement's observations. The draft comes back as
// files and review notes for a person; nothing is written, compiled,
// registered or run here, and the registry is read only for its names.
func (h *Handler) draftModule(ctx context.Context, advisor *ai.Advisor, resp *aresv1.AdviseResponse, engID, engName, brief string) (*connect.Response[aresv1.AdviseResponse], error) {
	p := h.buildProfileInput(engID, engName)
	in := ai.ModuleDraftInput{Brief: brief, Target: p.Target, Signals: p.Signals, AlreadyRun: p.AlreadyRun}
	if h.reg != nil {
		in.ExistingModules = h.reg.Names()
	}
	d, out, err := advisor.DraftModule(ctx, in)
	if err != nil {
		if errors.Is(err, ai.ErrEmptyBrief) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		resp.Error = err.Error()
		return connect.NewResponse(resp), nil
	}
	resp.Text = out.Text
	resp.InputTokens = int32(out.Usage.InputTokens)
	resp.OutputTokens = int32(out.Usage.OutputTokens)
	if out.Model != "" {
		resp.Model = out.Model
	}
	resp.ModuleDraft = draftToProto(d)
	return connect.NewResponse(resp), nil
}

func draftToProto(d ai.ModuleDraft) *aresv1.ModuleDraft {
	pb := &aresv1.ModuleDraft{
		Name:        d.Name,
		SpecJson:    d.SpecJSON,
		ReviewNotes: d.Notes,
		Problems:    d.Problems,
		Refusal:     d.Refusal,
	}
	for _, f := range d.Files {
		pb.Files = append(pb.Files, &aresv1.DraftFile{Path: f.Path, Content: string(f.Content)})
	}
	return pb
}

func validFeature(f string) bool {
	switch f {
	case ai.FeatureExplainFinding, ai.FeatureSuggestChecks, ai.FeatureNarratePaths, ai.FeatureDraftReport, ai.FeatureDraftModule:
		return true
	}
	return false
}

// buildAdvicePayload assembles the feature-specific input from the engagement's
// own findings and risk picture, then marshals it for the advisor.
func (h *Handler) buildAdvicePayload(feature, engID, engName string, nameMap map[string]string, findingID string) (json.RawMessage, error) {
	switch feature {
	case ai.FeatureExplainFinding:
		if findingID == "" {
			return nil, errors.New("finding_id is required for explain-finding")
		}
		findings := h.collectFindings([]string{engID}, nameMap)
		for _, f := range findings {
			if f.GetId() == findingID {
				return json.Marshal(findingToInput(f))
			}
		}
		return nil, errors.New("finding not found in this engagement")

	case ai.FeatureSuggestChecks:
		return json.Marshal(h.buildProfileInput(engID, engName))

	case ai.FeatureNarratePaths:
		risk := report.RiskOf(h.outcomes.ByEngagement(engID))
		return json.Marshal(riskToInput(risk))

	case ai.FeatureDraftReport:
		findings := h.collectFindings([]string{engID}, nameMap)
		risk := report.RiskOf(h.outcomes.ByEngagement(engID))
		return json.Marshal(buildReportInput(engName, findings, risk))
	}
	return nil, errors.New("unknown feature")
}

// findingToInput flattens a proto Finding into the advisor's input shape.
func findingToInput(f *aresv1.Finding) ai.FindingInput {
	in := ai.FindingInput{
		Technique: f.GetTechnique(),
		Target:    f.GetTarget(),
		Module:    f.GetModule(),
	}
	data := f.GetData().AsMap()
	in.Title = str(data["title"])
	if in.Title == "" {
		in.Title = str(data["name"])
	}
	in.Severity = str(data["severity"])
	in.IssueKey = str(data["issueKey"])
	in.Description = str(data["description"])
	in.Remediation = firstNonEmpty(str(data["remediation"]), str(data["remediationDetail"]))
	if ev, ok := data["evidence"].(map[string]any); ok {
		in.Evidence = ev
	}
	return in
}

// buildProfileInput summarizes what has been observed so the advisor can suggest
// the next checks, grounded in the techniques and modules actually seen.
func (h *Handler) buildProfileInput(engID, engName string) ai.ProfileInput {
	outcomes := h.outcomes.ByEngagement(engID)
	ranModules := map[string]bool{}
	techniques := map[string]bool{}
	var findingCount int
	for _, o := range outcomes {
		if o.Module != "" {
			ranModules[o.Module] = true
		}
		for _, r := range o.Results {
			if r.Kind == "finding" {
				findingCount++
			}
			if r.Technique != "" {
				techniques[r.Technique] = true
			}
		}
	}
	p := ai.ProfileInput{
		Target:     engName,
		AlreadyRun: sortedKeys(ranModules),
		Signals:    sortedKeys(techniques),
	}
	p.Summary = summarize(findingCount, len(ranModules))
	return p
}

func riskToInput(r intel.RiskPicture) ai.RiskInput {
	in := ai.RiskInput{Target: r.Target, Score: r.Score, Rating: r.Rating}
	for _, p := range r.Paths {
		pi := ai.PathInput{Name: p.Name, Outcome: p.Outcome, Severity: p.Severity}
		for _, s := range p.Steps {
			pi.Steps = append(pi.Steps, ai.StepInput{Title: s.Title, Technique: s.Technique, Role: s.Role})
		}
		in.Paths = append(in.Paths, pi)
	}
	return in
}

func buildReportInput(engName string, findings []*aresv1.Finding, risk intel.RiskPicture) ai.ReportInput {
	in := ai.ReportInput{Engagement: engName, Target: risk.Target, Score: risk.Score, Rating: risk.Rating}
	// Most severe first, then cap to keep the prompt bounded.
	sorted := append([]*aresv1.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank(sorted[i]) > severityRank(sorted[j])
	})
	for i, f := range sorted {
		if i >= maxReportFindings {
			break
		}
		in.Findings = append(in.Findings, findingToInput(f))
	}
	return in
}

// ---- small helpers ----

func severityRank(f *aresv1.Finding) int {
	switch str(f.GetData().AsMap()["severity"]) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func summarize(findings, modules int) string {
	return itoa(findings) + " finding(s) across " + itoa(modules) + " module(s) run so far"
}

// itoa keeps this file free of a strconv import for one tiny use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
