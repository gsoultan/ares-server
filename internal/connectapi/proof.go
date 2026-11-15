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
	"strings"
	"time"

	"connectrpc.com/connect"

	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/remediation"
)

// proofProto converts the engine's structured proof into its wire form. A nil
// proof maps to nil: a finding with no reproducible exchange simply carries no
// proof, and the UI shows the honest "Observed" label from the kind.
func proofProto(p *module.Proof) *aresv1.Proof {
	if p == nil {
		return nil
	}
	out := &aresv1.Proof{
		V:           int32(p.V),
		Kind:        string(p.Kind),
		Summary:     p.Summary,
		Claim:       p.Claim,
		Token:       p.Token,
		Sent:        exchangeProto(p.Sent),
		Received:    exchangeProto(p.Received),
		Callback:    callbackProto(p.Callback),
		Computed:    computedProto(p.Computed),
		Version:     versionProto(p.Version),
		Recheck:     recheckProto(p.Recheck),
		Fingerprint: p.Fingerprint,
		Cleanup:     cleanupProto(p.Cleanup),
	}
	if p.Control != nil {
		out.Control = &aresv1.Control{
			Sent:     exchangeProto(p.Control.Sent),
			Received: exchangeProto(p.Control.Received),
		}
	}
	return out
}

func exchangeProto(e *module.Exchange) *aresv1.Exchange {
	if e == nil {
		return nil
	}
	return &aresv1.Exchange{
		At:       rfc(e.At),
		Protocol: e.Protocol,
		Method:   e.Method,
		Url:      e.URL,
		Headers:  e.Headers,
		Body:     e.Body,
		Status:   int32(e.Status),
		Size:     int32(e.Size),
		Title:    e.Title,
		Excerpt:  e.Excerpt,
	}
}

func callbackProto(c *module.Callback) *aresv1.Callback {
	if c == nil {
		return nil
	}
	return &aresv1.Callback{
		Channel:   c.Channel,
		At:        rfc(c.At),
		DelayMs:   c.DelayMs,
		SourceIp:  c.SourceIP,
		TargetIp:  c.TargetIP,
		Method:    c.Method,
		Path:      c.Path,
		Host:      c.Host,
		UserAgent: c.UserAgent,
	}
}

func computedProto(c *module.Computed) *aresv1.Computed {
	if c == nil {
		return nil
	}
	return &aresv1.Computed{Expression: c.Expression, Expected: c.Expected, Markers: c.Markers}
}

func versionProto(v *module.VersionMatch) *aresv1.VersionMatch {
	if v == nil {
		return nil
	}
	return &aresv1.VersionMatch{
		Found: v.Found, From: v.From, Range: v.Range, Cve: v.CVE,
		Advisory: v.Advisory, Kev: v.KEV, Source: v.Source, AsOf: v.AsOf,
	}
}

func recheckProto(r *module.Recheck) *aresv1.Recheck {
	if r == nil {
		return nil
	}
	return &aresv1.Recheck{
		Module: r.Module,
		Target: targetProto(r.Target),
		Params: string(r.Params),
	}
}

// findingProofs indexes a finding's structured proof by the finding id, derived
// from the stored outcomes the same way collectFindings derives the findings.
// It returns the proof from the finding's most recent run.
func (h *Handler) findingProofs(engIDs []string) map[string]*module.Proof {
	proofs := map[string]*module.Proof{}
	latest := map[string]time.Time{}
	for _, engID := range engIDs {
		for _, o := range h.outcomes.ByEngagement(engID) {
			for _, r := range o.Results {
				if r.Kind != "finding" && r.Kind != "info" {
					continue
				}
				if r.Proof == nil {
					continue
				}
				title, _ := r.Data["title"].(string)
				id := findingKey(o.Engagement, r.Capability, r.Technique, title, r.Target.String())
				if o.StartedAt.Before(latest[id]) {
					continue
				}
				latest[id] = o.StartedAt
				proofs[id] = r.Proof
			}
		}
	}
	return proofs
}

// RecheckFinding reproduces a finding's proof on demand by dispatching its
// narrowed re-check probe through the normal scope gate. It never bypasses
// authorization: the engagement must still be runnable.
func (h *Handler) RecheckFinding(_ context.Context, req *connect.Request[aresv1.RecheckFindingRequest]) (*connect.Response[aresv1.RecheckFindingResponse], error) {
	engIDs, _, err := h.workspaceEngagements(req.Msg.GetTenantId(), "")
	if err != nil {
		return nil, err
	}
	proof, ok := h.findingProofs(engIDs)[req.Msg.GetFindingId()]
	if !ok || proof == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("finding not found"))
	}
	if proof.Recheck == nil {
		return connect.NewResponse(&aresv1.RecheckFindingResponse{
			Rechecked: false,
			Message:   "this finding has no reproducible proof to re-check",
		}), nil
	}
	// Find the engagement that owns the finding so the re-check runs in it.
	engID, err := h.engagementForFinding(engIDs, req.Msg.GetFindingId())
	if err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), engID)
	if err != nil {
		return nil, err
	}
	if ok, reason := eng.CanRun(); !ok {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New(reason))
	}
	rc := proof.Recheck
	if _, known := h.reg.Get(rc.Module); !known {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("re-check module is not available"))
	}
	actor := req.Msg.GetActor()
	if actor == "" {
		actor = "operator"
	}
	jobID := uuid.NewV7()
	h.queue.Enqueue(queue.Job{
		ID:           jobID,
		EngagementID: eng.ID,
		Module:       rc.Module,
		Actor:        actor,
		Targets:      []module.Target{rc.Target},
		Params:       rc.Params,
	})
	h.pending.add(jobID, eng.ID, rc.Module)
	eng.Audit.Append(actor, "proof-recheck", req.Msg.GetFindingId(),
		"module="+rc.Module+" claim="+proof.Claim)
	_ = h.store.Save(eng)
	return connect.NewResponse(&aresv1.RecheckFindingResponse{JobId: jobID, Status: "queued", Rechecked: true}), nil
}

// GetProofArtifact returns a finding's proof as a downloadable, verifiable JSON
// record, with the audit entry (seq and chain hash) that anchors its
// fingerprint so a user can confirm it offline.
func (h *Handler) GetProofArtifact(_ context.Context, req *connect.Request[aresv1.GetProofArtifactRequest]) (*connect.Response[aresv1.GetProofArtifactResponse], error) {
	engIDs, _, err := h.workspaceEngagements(req.Msg.GetTenantId(), "")
	if err != nil {
		return nil, err
	}
	proof, ok := h.findingProofs(engIDs)[req.Msg.GetFindingId()]
	if !ok || proof == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("finding has no proof to download"))
	}
	artifact, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not serialize proof"))
	}
	resp := &aresv1.GetProofArtifactResponse{
		Proof:    proofProto(proof),
		Filename: proofFilename(req.Msg.GetFindingId(), proof.Fingerprint),
		Artifact: artifact,
	}
	// Attach the audit anchor if the proof-recorded entry is present.
	if engID, err := h.engagementForFinding(engIDs, req.Msg.GetFindingId()); err == nil {
		if eng, err := h.engagementInTenant(req.Msg.GetTenantId(), engID); err == nil {
			for _, e := range eng.Audit.Entries() {
				if e.Action == "proof-recorded" && strings.Contains(e.Detail, proof.Fingerprint) {
					resp.AuditSeq = int32(e.Seq)
					resp.AuditHash = e.Hash
					break
				}
			}
		}
	}
	return connect.NewResponse(resp), nil
}

// engagementForFinding resolves which engagement a finding id belongs to within
// the caller's workspace.
func (h *Handler) engagementForFinding(engIDs []string, findingID string) (string, error) {
	for _, engID := range engIDs {
		for _, o := range h.outcomes.ByEngagement(engID) {
			for _, r := range o.Results {
				if r.Kind != "finding" && r.Kind != "info" {
					continue
				}
				title, _ := r.Data["title"].(string)
				if findingKey(o.Engagement, r.Capability, r.Technique, title, r.Target.String()) == findingID {
					return engID, nil
				}
			}
		}
	}
	return "", connect.NewError(connect.CodeNotFound, errors.New("finding not found"))
}

func proofFilename(findingID, fingerprint string) string {
	short := strings.TrimPrefix(fingerprint, "sha256:")
	if len(short) > 12 {
		short = short[:12]
	}
	id := findingID
	if len(id) > 12 {
		id = id[:12]
	}
	return "proof-" + id + "-" + short + ".json"
}

// remediationProto lifts the engine's structured remediation guidance onto the
// typed wire field. It derives the guidance the same way the worker's enrichment
// does (from the issue key, technique and the finding's own fix line), so the UI
// gets first-class, per-platform fix steps and authoritative references without
// re-parsing the untyped data payload. A finding with no guidance maps to nil.
func remediationProto(r module.Result) *aresv1.Remediation {
	issueKey, _ := r.Data["issueKey"].(string)
	existingFix, _ := r.Data["remediation"].(string)
	g := remediation.For(issueKey, r.Technique, existingFix)
	out := &aresv1.Remediation{
		Summary:    g.Summary,
		Technique:  g.Technique,
		Fix:        stepsProto(g.Fix),
		Prevent:    stepsProto(g.Prevent),
		Verify:     stepsProto(g.Verify),
		Detect:     stepsProto(g.Detect),
		References: append([]string(nil), g.References...),
	}
	for _, m := range g.Mitigations {
		out.Mitigations = append(out.Mitigations, &aresv1.Mitigation{Id: m.ID, Name: m.Name})
	}
	if out.GetSummary() == "" && len(out.GetFix()) == 0 && len(out.GetPrevent()) == 0 &&
		len(out.GetVerify()) == 0 && len(out.GetReferences()) == 0 {
		return nil
	}
	return out
}

func stepsProto(steps []remediation.Step) []*aresv1.RemediationStep {
	if len(steps) == 0 {
		return nil
	}
	out := make([]*aresv1.RemediationStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, &aresv1.RemediationStep{Text: s.Text, Code: s.Code, Lang: s.Lang})
	}
	return out
}

func cleanupProto(c *module.Cleanup) *aresv1.Cleanup {
	if c == nil {
		return nil
	}
	return &aresv1.Cleanup{Performed: c.Performed, At: rfc(c.At), Detail: c.Detail}
}
