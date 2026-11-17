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

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares-server/internal/egresscheck"
	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares/module"
)

// These are the operator-facing agent-management RPCs on the ControlPlane
// service. The agent itself speaks the separate AgentService. Every call is
// scoped to an engagement the caller can see (h.engagementInTenant enforces the
// tenant boundary), so an operator can only manage agents in their own
// engagements.

func (h *Handler) agentsEnabled() error {
	if h.agents == nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("agent management is not enabled"))
	}
	return nil
}

// MintAgentKey records the host-owner permission and creates a one-time install
// key for the engagement. The engagement must be able to run; a permission
// record is required.
func (h *Handler) MintAgentKey(_ context.Context, req *connect.Request[aresv1.MintAgentKeyRequest]) (*connect.Response[aresv1.MintAgentKeyResponse], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	if ok, reason := eng.CanRun(); !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(reason))
	}
	consent := consentFromProto(req.Msg.GetConsent())
	if !consent.Valid() {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("a host-owner permission record (who, how, recorded_by) is required"))
	}
	keyID, raw, err := h.agents.MintEnrollToken(eng.TenantID, eng.ID, req.Msg.GetCapabilities(), consent)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	eng.Audit.Append(consent.RecordedBy, "agent.key.mint", keyID, "install key minted")
	_ = h.store.Save(eng)
	return connect.NewResponse(&aresv1.MintAgentKeyResponse{
		KeyId:      keyID,
		InstallKey: raw,
		ExpiresAt:  time.Now().Add(agent.DefaultEnrollTokenTTL).Format(time.RFC3339),
	}), nil
}

// CancelAgentKey withdraws an unused install key.
func (h *Handler) CancelAgentKey(_ context.Context, req *connect.Request[aresv1.CancelAgentKeyRequest]) (*connect.Response[aresv1.CancelAgentKeyResponse], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	if err := h.agents.CancelEnrollToken(req.Msg.GetKeyId()); err != nil {
		return nil, mapAgentErr(err)
	}
	eng.Audit.Append("operator", "agent.key.cancel", req.Msg.GetKeyId(), "install key cancelled")
	_ = h.store.Save(eng)
	return connect.NewResponse(&aresv1.CancelAgentKeyResponse{Ok: true}), nil
}

// ListAgentKeys lists the engagement's unused install keys.
func (h *Handler) ListAgentKeys(_ context.Context, req *connect.Request[aresv1.ListAgentKeysRequest]) (*connect.Response[aresv1.ListAgentKeysResponse], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	keys := h.agents.ListEnrollTokens(eng.TenantID, eng.ID)
	out := make([]*aresv1.AgentKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, &aresv1.AgentKeyView{
			KeyId:        k.ID,
			Capabilities: k.Capabilities,
			Consent:      consentProto(k.Consent),
			CreatedAt:    k.CreatedAt.Format(time.RFC3339),
			ExpiresAt:    k.ExpiresAt.Format(time.RFC3339),
		})
	}
	return connect.NewResponse(&aresv1.ListAgentKeysResponse{Keys: out}), nil
}

// ListAgents lists the engagement's agents with status, host facts and consent.
func (h *Handler) ListAgents(_ context.Context, req *connect.Request[aresv1.ListAgentsRequest]) (*connect.Response[aresv1.ListAgentsResponse], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	agents := h.agents.ListByEngagement(eng.TenantID, eng.ID)
	out := make([]*aresv1.AgentView, 0, len(agents))
	for _, a := range agents {
		out = append(out, agentViewProto(a, now))
	}
	return connect.NewResponse(&aresv1.ListAgentsResponse{Agents: out}), nil
}

// GetAgent returns one agent in the engagement.
func (h *Handler) GetAgent(_ context.Context, req *connect.Request[aresv1.GetAgentRequest]) (*connect.Response[aresv1.AgentView], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	a, ok := h.agents.Get(req.Msg.GetAgentId())
	if !ok || a.TenantID != eng.TenantID || a.EngagementID != eng.ID {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown agent"))
	}
	return connect.NewResponse(agentViewProto(a, time.Now())), nil
}

// RemoveAgent revokes an agent immediately; it self-uninstalls on next contact.
// Findings it already sent are kept.
func (h *Handler) RemoveAgent(_ context.Context, req *connect.Request[aresv1.RemoveAgentRequest]) (*connect.Response[aresv1.RemoveAgentResponse], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	a, ok := h.agents.Get(req.Msg.GetAgentId())
	if !ok || a.TenantID != eng.TenantID || a.EngagementID != eng.ID {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown agent"))
	}
	if err := h.agents.Revoke(a.ID); err != nil {
		return nil, mapAgentErr(err)
	}
	eng.Audit.Append("operator", "agent.remove", a.ID, "agent revoked; self-uninstalls on next contact")
	_ = h.store.Save(eng)
	return connect.NewResponse(&aresv1.RemoveAgentResponse{Ok: true}), nil
}

// DispatchAgentJob queues an authorized check for an agent. The server
// gate-checks it and hands the agent the engagement scope snapshot; the agent
// re-enforces the scope locally before touching a target (the double barrier).
func (h *Handler) DispatchAgentJob(_ context.Context, req *connect.Request[aresv1.DispatchAgentJobRequest]) (*connect.Response[aresv1.DispatchAgentJobResponse], error) {
	if err := h.agentsEnabled(); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	if ok, reason := eng.CanRun(); !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(reason))
	}
	a, ok := h.agents.Get(req.Msg.GetAgentId())
	if !ok || a.TenantID != eng.TenantID || a.EngagementID != eng.ID {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown agent"))
	}
	mod := req.Msg.GetModule()
	// The module must exist in the engine and be on the agent's capability
	// allow-list. Both the server (here) and the agent enforce this.
	// Agent-native capabilities (hostposture, egresscheck) run in the agent
	// itself, not as engine modules.
	if _, known := h.reg.Get(mod); (!known && !agent.IsAgentNative(mod)) || agent.GroupOf(mod) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("unknown or non-dispatchable module"))
	}
	if err := h.agents.AuthorizeModule(a.ID, mod); err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("module not on the agent's capability allow-list"))
	}
	// Snapshot the engagement scope so the agent enforces the same boundary.
	snap, err := json.Marshal(eng.Scope.Snapshot())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	targets := make([]module.Target, 0, len(req.Msg.GetTargets()))
	for _, t := range req.Msg.GetTargets() {
		targets = append(targets, targetDomain(t))
	}
	tp := agentTaskParams{Targets: targets}
	if mod == "egresscheck" {
		if h.egress == nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				errors.New("egress check needs the canary collaborator (ARES_CANARY_URL / ARES_CANARY_DOMAIN)"))
		}
		tp.Egress = h.egress.plan(eng.ID)
		if len(tp.Egress) == 0 {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no canary listener is configured for any egress channel"))
		}
	}
	params, err := json.Marshal(tp)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	taskID, err := h.agents.EnqueueTask(a.ID, agent.Task{Module: mod, ScopeSnapshot: snap, Params: params})
	if err != nil {
		return nil, mapAgentErr(err)
	}
	// Reflect "running a check" in the agent's UI status.
	h.agents.SetCurrentCapability(a.ID, mod)
	detail := "queued " + mod
	if len(tp.Egress) > 0 {
		toks := make([]string, 0, len(tp.Egress))
		for _, t := range tp.Egress {
			toks = append(toks, t.Channel+"="+t.Token)
		}
		detail += " with egress canary tokens " + strings.Join(toks, ",")
	}
	eng.Audit.Append("operator", "agent.dispatch", a.ID, detail)
	_ = h.store.Save(eng)
	return connect.NewResponse(&aresv1.DispatchAgentJobResponse{TaskId: taskID}), nil
}

// agentTaskParams is the JSON payload of an agent task (the capability-specific
// parameters). For the recon capabilities it is just the target list.
type agentTaskParams struct {
	Targets []module.Target `json:"targets"`
	// Egress carries the canary tokens for an egresscheck task.
	Egress []egresscheck.Token `json:"egress,omitempty"`
}

// engagementGate adapts the engagement store into the registry's gate: an agent
// may act only while its engagement can run.
func (h *Handler) engagementGate() agent.EngagementGate {
	return func(tenantID, engagementID string) bool {
		eng, ok := h.store.Get(engagementID)
		if !ok || eng.TenantID != engagement.ResolveTenant(tenantID) {
			return false
		}
		ok2, _ := eng.CanRun()
		return ok2
	}
}

// --- proto mapping ---------------------------------------------------------

func consentFromProto(c *aresv1.Consent) agent.Consent {
	if c == nil {
		return agent.Consent{}
	}
	out := agent.Consent{
		Who:                 c.GetWho(),
		How:                 c.GetHow(),
		AuthFileFingerprint: c.GetAuthFileFingerprint(),
		RecordedBy:          c.GetRecordedBy(),
	}
	if s := c.GetEndsAt(); s != "" {
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			out.EndsAt = ts
		}
	}
	return out
}

func consentProto(c agent.Consent) *aresv1.Consent {
	p := &aresv1.Consent{
		Who:                 c.Who,
		How:                 c.How,
		AuthFileFingerprint: c.AuthFileFingerprint,
		RecordedBy:          c.RecordedBy,
	}
	if !c.EndsAt.IsZero() {
		p.EndsAt = c.EndsAt.Format(time.RFC3339)
	}
	return p
}

func hostFactsProto(h agent.HostFacts) *aresv1.HostFacts {
	return &aresv1.HostFacts{
		Hostname:     h.Hostname,
		Os:           h.OS,
		Arch:         h.Arch,
		AgentVersion: h.AgentVersion,
		Ip:           h.IP,
		SegmentCidrs: h.SegmentCIDRs,
	}
}

func agentStatusProto(s agent.Status) aresv1.AgentStatus {
	switch s {
	case agent.StatusConnected:
		return aresv1.AgentStatus_AGENT_STATUS_CONNECTED
	case agent.StatusRunningCheck:
		return aresv1.AgentStatus_AGENT_STATUS_RUNNING_CHECK
	case agent.StatusNotHeardFrom:
		return aresv1.AgentStatus_AGENT_STATUS_NOT_HEARD_FROM
	case agent.StatusRemoved:
		return aresv1.AgentStatus_AGENT_STATUS_REMOVED
	default:
		return aresv1.AgentStatus_AGENT_STATUS_UNSPECIFIED
	}
}

func agentViewProto(a *agent.Agent, now time.Time) *aresv1.AgentView {
	v := &aresv1.AgentView{
		Id:                a.ID,
		TenantId:          a.TenantID,
		EngagementId:      a.EngagementID,
		Status:            agentStatusProto(a.StatusAt(now)),
		Host:              hostFactsProto(a.Host),
		Capabilities:      a.Capabilities,
		Consent:           consentProto(a.Consent),
		CurrentCapability: a.CurrentCapability,
		EnrolledAt:        a.EnrolledAt.Format(time.RFC3339),
	}
	if !a.LastSeen.IsZero() {
		v.LastSeen = a.LastSeen.Format(time.RFC3339)
	}
	return v
}

func mapAgentErr(err error) error {
	switch {
	case errors.Is(err, agent.ErrConsentMissing):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, agent.ErrUnknownKey), errors.Is(err, agent.ErrUnknownAgent):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, agent.ErrNotAuthorized):
		return connect.NewError(connect.CodePermissionDenied, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
