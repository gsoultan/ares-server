// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package connectapi serves the Ares control plane over gRPC. It is a thin
// adapter: every RPC maps a generated protobuf message onto the same domain
// types the REST surface uses (the engagement store, the module registry, the
// job queue and the outcome store), so both surfaces share one core and one
// permission gate. The handler is served with connect-go, which speaks gRPC,
// gRPC-Web and the Connect protocol on the same endpoint.
package connectapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares-server/internal/ai"
	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/report"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares-server/internal/setup"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/detection"
	"github.com/gsoultan/ares/intel"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/purple"
)

// Handler implements the generated ControlPlaneHandler over the Ares core.
type Handler struct {
	store    engagement.Store
	reg      *module.Registry
	queue    *queue.Queue
	outcomes worker.OutcomeStore
	purple   *purple.Catalog
	statuses *findingStatusStore
	pending  *pendingJobs
	memo     *memo             // read-path results, keyed by their versioned inputs
	advisor  *ai.Advisor       // nil when no AI provider is configured (feature off)
	settings *settings.Service // nil until a master key is available (pre-setup)
	auth     *auth.Service     // nil disables the auth RPCs
	setup    *setup.Service    // nil disables the setup RPCs
	agents   *agent.Registry   // nil disables the agent-management RPCs
	egress   *egressMinter     // nil refuses egresscheck dispatch (see egress.go)
	jobs     JobStopper        // nil disables StopJob
}

// compile-time check that Handler satisfies the generated interface.
var _ aresv1connect.ControlPlaneHandler = (*Handler)(nil)

// New builds a control-plane gRPC handler over the shared core. The optional AI
// advisor is built from the ARES_AI_* environment; when none is configured the
// advisory feature is simply absent (graceful fallback).
func New(store engagement.Store, reg *module.Registry, q *queue.Queue, outcomes worker.OutcomeStore) *Handler {
	h := &Handler{
		store:    store,
		reg:      reg,
		queue:    q,
		outcomes: outcomes,
		purple:   purple.NewCatalog(),
		statuses: newFindingStatusStore(),
		pending:  newPendingJobs(),
		memo:     newMemo(4096),
	}
	h.restoreFindingStatuses()
	if adv, err := ai.AdvisorFromEnv(); err == nil {
		h.advisor = adv
		log.Printf("ai advisor enabled: provider=%s model=%s", adv.Provider().Name(), adv.Provider().Model())
	} else if !errors.Is(err, ai.ErrNotConfigured) {
		// A provider was named but mis-configured (missing key/model/base URL):
		// log the reason (never the key) and leave the feature off.
		log.Printf("ai advisor disabled: %v", err)
	}
	return h
}

// WithAdvisor overrides the AI advisor (used in tests). A nil advisor disables
// the feature.
func (h *Handler) WithAdvisor(adv *ai.Advisor) *Handler {
	h.advisor = adv
	return h
}

// WithSettings attaches the in-app settings service. Until one is attached (no
// master key yet, i.e. before first-run setup), the settings RPCs report the
// store as unavailable.
func (h *Handler) WithSettings(s *settings.Service) *Handler {
	h.settings = s
	return h
}

// WithAuth attaches the authentication service (Login/Logout/CurrentUser).
func (h *Handler) WithAuth(a *auth.Service) *Handler {
	h.auth = a
	return h
}

// WithSetup attaches the first-run setup service.
func (h *Handler) WithSetup(s *setup.Service) *Handler {
	h.setup = s
	return h
}

// WithAgents attaches the agent registry (the engagement "Agents" view and
// install-key management). Until one is attached the agent RPCs are unavailable.
func (h *Handler) WithAgents(r *agent.Registry) *Handler {
	h.agents = r
	return h
}

// ListModules returns the registered capability names.
func (h *Handler) ListModules(_ context.Context, _ *connect.Request[aresv1.ListModulesRequest]) (*connect.Response[aresv1.ListModulesResponse], error) {
	return connect.NewResponse(&aresv1.ListModulesResponse{Modules: h.reg.Names()}), nil
}

// CreateTenant creates a client workspace. Once accounts exist it is a
// super-admin action.
func (h *Handler) CreateTenant(ctx context.Context, req *connect.Request[aresv1.CreateTenantRequest]) (*connect.Response[aresv1.Tenant], error) {
	if req.Msg.GetName() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}
	if sess, ok := SessionFromContext(ctx); ok && sess.Role != auth.RoleSuperAdmin {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only a super-admin may create workspaces"))
	}
	t := h.store.CreateTenant(req.Msg.GetName())
	return connect.NewResponse(tenantProto(t)), nil
}

// ListTenants lists the client workspaces. A workspace-bound account sees only
// its own, never the names of the platform's other clients.
func (h *Handler) ListTenants(ctx context.Context, _ *connect.Request[aresv1.ListTenantsRequest]) (*connect.Response[aresv1.ListTenantsResponse], error) {
	list := h.store.ListTenants()
	if sess, ok := SessionFromContext(ctx); ok && sess.Role != auth.RoleSuperAdmin {
		list = list[:0:0]
		if t, found := h.store.GetTenant(sess.TenantID); found {
			list = append(list, t)
		}
	}
	resp := &aresv1.ListTenantsResponse{Tenants: make([]*aresv1.Tenant, 0, len(list))}
	for _, t := range list {
		resp.Tenants = append(resp.Tenants, tenantProto(t))
	}
	return connect.NewResponse(resp), nil
}

// engagementInTenant looks an engagement up and confirms it belongs to the
// caller's workspace. A mismatch is reported as not-found rather than
// permission-denied, so one tenant cannot even probe another's engagement ids.
func (h *Handler) engagementInTenant(tenantID, id string) (*engagement.Engagement, error) {
	eng, ok := h.store.Get(id)
	if !ok || eng.TenantID != engagement.ResolveTenant(tenantID) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("engagement not found"))
	}
	return eng, nil
}

// CreateEngagement creates a draft engagement in a workspace.
func (h *Handler) CreateEngagement(_ context.Context, req *connect.Request[aresv1.CreateEngagementRequest]) (*connect.Response[aresv1.Engagement], error) {
	if req.Msg.GetName() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}
	eng, err := h.store.Create(req.Msg.GetTenantId(), req.Msg.GetName())
	if err != nil {
		if errors.Is(err, engagement.ErrUnknownTenant) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(engagementProto(eng)), nil
}

// ListEngagements lists the engagements in one workspace.
func (h *Handler) ListEngagements(_ context.Context, req *connect.Request[aresv1.ListEngagementsRequest]) (*connect.Response[aresv1.ListEngagementsResponse], error) {
	list := h.store.List(req.Msg.GetTenantId())
	resp := &aresv1.ListEngagementsResponse{Engagements: make([]*aresv1.Engagement, 0, len(list))}
	for _, e := range list {
		resp.Engagements = append(resp.Engagements, engagementProto(e))
	}
	return connect.NewResponse(resp), nil
}

// GetEngagement returns one engagement from the caller's workspace.
func (h *Handler) GetEngagement(_ context.Context, req *connect.Request[aresv1.GetEngagementRequest]) (*connect.Response[aresv1.Engagement], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(engagementProto(eng)), nil
}

// SetScope configures the permission gate while the engagement is a draft.
func (h *Handler) SetScope(_ context.Context, req *connect.Request[aresv1.SetScopeRequest]) (*connect.Response[aresv1.Engagement], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	if eng.Status != engagement.StatusDraft {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("scope can only be edited while the engagement is a draft"))
	}
	for _, e := range req.Msg.GetInScope() {
		if err := eng.Scope.AddInScope(e); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	for _, e := range req.Msg.GetExclude() {
		if err := eng.Scope.AddExclusion(e); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if win := req.Msg.GetWindow(); win != nil {
		if win.GetStart() != "" {
			ts, err := time.Parse(time.RFC3339, win.GetStart())
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("window.start must be RFC3339"))
			}
			eng.Scope.Window.Start = ts
		}
		if win.GetEnd() != "" {
			ts, err := time.Parse(time.RFC3339, win.GetEnd())
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("window.end must be RFC3339"))
			}
			eng.Scope.Window.End = ts
		}
		if days := win.GetDays(); len(days) > 0 {
			wd := make([]time.Weekday, 0, len(days))
			for _, d := range days {
				wd = append(wd, time.Weekday(d))
			}
			eng.Scope.Window.Days = wd
		}
		if win.GetHoursSet() {
			if err := eng.Scope.Window.SetHours(int(win.GetStartHour()), int(win.GetEndHour())); err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, err)
			}
		}
	}
	eng.Audit.Append("grpc", "scope-updated", eng.ID,
		fmt.Sprintf("%d in scope, %d excluded", len(req.Msg.GetInScope()), len(req.Msg.GetExclude())))
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(engagementProto(eng)), nil
}

// Authorize attaches a signed permission and enables running.
func (h *Handler) Authorize(_ context.Context, req *connect.Request[aresv1.AuthorizeRequest]) (*connect.Response[aresv1.Engagement], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	if err := eng.Authorize(engagement.Authorization{
		Document:   req.Msg.GetDocument(),
		ApprovedBy: req.Msg.GetApprovedBy(),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(engagementProto(eng)), nil
}

// Halt is the kill switch.
func (h *Handler) Halt(_ context.Context, req *connect.Request[aresv1.HaltRequest]) (*connect.Response[aresv1.Engagement], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	actor := req.Msg.GetActor()
	if actor == "" {
		actor = "operator"
	}
	eng.Halt(actor)
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(engagementProto(eng)), nil
}

// DispatchJob enqueues a job against the engagement's targets. It refuses
// immediately if the engagement cannot run; the worker still re-checks the gate
// per target before any module acts.
func (h *Handler) DispatchJob(_ context.Context, req *connect.Request[aresv1.DispatchJobRequest]) (*connect.Response[aresv1.DispatchJobResponse], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	if ok, reason := eng.CanRun(); !ok {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New(reason))
	}
	if _, known := h.reg.Get(req.Msg.GetModule()); !known {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("unknown module %q", req.Msg.GetModule()))
	}
	actor := req.Msg.GetActor()
	if actor == "" {
		actor = "operator"
	}
	params, err := structToJSON(req.Msg.GetParams())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid params: %w", err))
	}
	targets := make([]module.Target, 0, len(req.Msg.GetTargets()))
	for _, t := range req.Msg.GetTargets() {
		targets = append(targets, targetDomain(t))
	}
	jobID := uuid.NewV7()
	// The consent gate: the engagement's test intensity, and for an intrusive
	// test a usable approval per target, reserved for this job.
	if err := h.consentPrecheck(eng, req.Msg.GetModule(), params, targets, jobID); err != nil {
		return nil, err
	}
	if err := h.queue.TryEnqueue(queue.Job{
		ID:           jobID,
		EngagementID: eng.ID,
		Module:       req.Msg.GetModule(),
		Actor:        actor,
		Targets:      targets,
		Params:       params,
	}); err != nil {
		eng.ReleaseJob(jobID)
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("job queue is full, try again shortly"))
	}
	_ = h.store.Save(eng)
	// Record it as running so ListJobs shows an in-flight row that survives a page
	// reload; it is pruned once the worker records the outcome.
	h.pending.add(jobID, eng.ID, req.Msg.GetModule())
	return connect.NewResponse(&aresv1.DispatchJobResponse{JobId: jobID, Status: "queued"}), nil
}

// GetJob returns a job outcome, or a pending status if it has not run yet. A
// job belongs to the workspace of its engagement: a caller in another workspace
// sees the same "pending" it would see for an id that does not exist, so job
// ids leak nothing across the isolation boundary.
func (h *Handler) GetJob(_ context.Context, req *connect.Request[aresv1.GetJobRequest]) (*connect.Response[aresv1.JobOutcome], error) {
	pending := connect.NewResponse(&aresv1.JobOutcome{Status: "pending", JobId: req.Msg.GetJobId()})
	o, ok := h.outcomes.Get(req.Msg.GetJobId())
	if !ok {
		return pending, nil
	}
	if eng, found := h.store.Get(o.Engagement); !found || eng.TenantID != engagement.ResolveTenant(req.Msg.GetTenantId()) {
		return pending, nil
	}
	// Results are append-only and a job's other fields only change as it
	// progresses, so this tuple identifies the outcome's state exactly; a
	// finished job's results are built once and then served from memory. The
	// cached message is shared, so the response is a new message over its
	// (read-only) slices, with the time-dependent progress added fresh.
	fp := newFingerprint().num(uint64(len(o.Results))).num(uint64(o.FinishedAt.UnixNano())).
		str(o.CurrentCapability).str(o.Error).num(uint64(len(o.Allowed))).num(uint64(len(o.Denied))).sum()
	base := h.memo.get("job|"+o.JobID, fp, func() any { return outcomeProto(o) }).(*aresv1.JobOutcome)
	jo := &aresv1.JobOutcome{
		Status: base.Status, JobId: base.JobId, Engagement: base.Engagement, Module: base.Module,
		Allowed: base.Allowed, Denied: base.Denied, Results: base.Results,
		Error: base.Error, CurrentCapability: base.CurrentCapability,
		Progress: progressProto(o, h.outcomes, time.Now()),
	}
	return connect.NewResponse(jo), nil
}

// GetAudit returns the hash-chained audit trail and whether it verifies.
func (h *Handler) GetAudit(_ context.Context, req *connect.Request[aresv1.GetAuditRequest]) (*connect.Response[aresv1.GetAuditResponse], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	// The trail is append-only: its length identifies its state, so the proto
	// (and the O(n) hash-chain verification) is rebuilt only after an append.
	n := uint64(eng.Audit.Len())
	resp := h.memo.get("audit|"+eng.ID, n, func() any { return auditProto(eng) }).(*aresv1.GetAuditResponse)
	return connect.NewResponse(resp), nil
}

// auditProto renders an engagement's audit trail and its verification result.
func auditProto(eng *engagement.Engagement) *aresv1.GetAuditResponse {
	entries := eng.Audit.Entries()
	resp := &aresv1.GetAuditResponse{
		Valid:   audit.Load(entries).Verify() == nil,
		Entries: make([]*aresv1.AuditEntry, 0, len(entries)),
	}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &aresv1.AuditEntry{
			Seq: int32(e.Seq),
			// UTC RFC3339Nano is exactly the string the hash is computed over
			// (see audit.Entry.computeHash), so a client can recompute and
			// independently verify the chain from the wire data alone.
			Time:     e.Time.UTC().Format(time.RFC3339Nano),
			Actor:    e.Actor,
			Action:   e.Action,
			Target:   e.Target,
			Detail:   e.Detail,
			PrevHash: e.PrevHash,
			Hash:     e.Hash,
		})
	}
	return resp
}

// GenerateReport renders a client-ready report (PDF, DOCX or Markdown) for an
// engagement in the caller's workspace, aggregating the findings of every job
// it ran.
func (h *Handler) GenerateReport(_ context.Context, req *connect.Request[aresv1.GenerateReportRequest]) (*connect.Response[aresv1.GenerateReportResponse], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	workspace := ""
	if t, ok := h.store.GetTenant(eng.TenantID); ok {
		workspace = t.Name
	}
	rep := report.Build(eng, workspace, h.outcomes.ByEngagement(eng.ID))

	data, contentType, ext, err := rep.Render(req.Msg.GetFormat())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&aresv1.GenerateReportResponse{
		Filename:    report.Filename(eng.Name, ext),
		ContentType: contentType,
		Data:        data,
	}), nil
}

// GetDetectionSummary returns the detection-coverage summary for an engagement
// in the caller's workspace.
func (h *Handler) GetDetectionSummary(_ context.Context, req *connect.Request[aresv1.GetDetectionSummaryRequest]) (*connect.Response[aresv1.DetectionSummary], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	ex := report.ExercisedTechniques(h.outcomes.ByEngagement(eng.ID))
	return connect.NewResponse(detectionSummaryProto(detection.BuildSummary(ex, eng.Detections()))), nil
}

// GetRiskPicture correlates an engagement's findings into prioritized attack
// paths — the analytical "risk picture" rather than a flat list.
func (h *Handler) GetRiskPicture(_ context.Context, req *connect.Request[aresv1.GetRiskPictureRequest]) (*connect.Response[aresv1.RiskPicture], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	// A pure function of the engagement's outcomes: rebuilt only when they change.
	v := h.outcomes.Version(eng.ID)
	rp := h.memo.get("risk|"+eng.ID, v, func() any {
		return riskPictureProto(report.RiskOf(h.outcomes.ByEngagement(eng.ID)))
	}).(*aresv1.RiskPicture)
	return connect.NewResponse(rp), nil
}

// SetDetection records the defender's response for one technique and returns the
// updated summary.
func (h *Handler) SetDetection(_ context.Context, req *connect.Request[aresv1.SetDetectionRequest]) (*connect.Response[aresv1.DetectionSummary], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	actor := req.Msg.GetActor()
	if actor == "" {
		actor = "operator"
	}
	if err := eng.SetDetection(req.Msg.GetTechnique(), detection.Outcome(req.Msg.GetOutcome()), req.Msg.GetNote(), actor); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	ex := report.ExercisedTechniques(h.outcomes.ByEngagement(eng.ID))
	return connect.NewResponse(detectionSummaryProto(detection.BuildSummary(ex, eng.Detections()))), nil
}

// ListPurpleTemplates returns the purple-team catalog. With an engagement id
// (in the caller's workspace), every template is scored against that
// engagement's recorded detection outcomes; without one, the catalog is
// returned unscored.
func (h *Handler) ListPurpleTemplates(_ context.Context, req *connect.Request[aresv1.ListPurpleTemplatesRequest]) (*connect.Response[aresv1.ListPurpleTemplatesResponse], error) {
	var records map[string]detection.Record
	if id := req.Msg.GetEngagementId(); id != "" {
		eng, err := h.engagementInTenant(req.Msg.GetTenantId(), id)
		if err != nil {
			return nil, err
		}
		records = eng.Detections()
	}
	ts := h.purple.List()
	resp := &aresv1.ListPurpleTemplatesResponse{Templates: make([]*aresv1.PurpleTemplateSummary, 0, len(ts))}
	for _, t := range ts {
		sum := &aresv1.PurpleTemplateSummary{
			Id:         t.ID,
			Name:       t.Name,
			Summary:    t.Summary,
			Reference:  t.Reference,
			StepCount:  int32(len(t.Steps)),
			Techniques: int32(len(t.Techniques())),
		}
		if records != nil {
			sum.Coverage = purpleCoverageProto(detection.BuildSummary(t.Techniques(), records))
		}
		resp.Templates = append(resp.Templates, sum)
	}
	return connect.NewResponse(resp), nil
}

// GetPurpleTemplate returns one template fully scored against an engagement in
// the caller's workspace: every step annotated with its recorded defender
// outcome, plus the coverage score over the template's techniques.
func (h *Handler) GetPurpleTemplate(_ context.Context, req *connect.Request[aresv1.GetPurpleTemplateRequest]) (*connect.Response[aresv1.PurpleTemplate], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	t, ok := h.purple.Get(req.Msg.GetTemplateId())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("template not found"))
	}
	records := eng.Detections()
	out := &aresv1.PurpleTemplate{
		Id:        t.ID,
		Name:      t.Name,
		Summary:   t.Summary,
		Reference: t.Reference,
		Coverage:  purpleCoverageProto(detection.BuildSummary(t.Techniques(), records)),
	}
	for _, s := range t.Steps {
		outcome := detection.Unknown
		note := ""
		if rec, ok := records[s.Technique]; ok && detection.Valid(rec.Outcome) {
			outcome = rec.Outcome
			note = rec.Note
		}
		out.Steps = append(out.Steps, &aresv1.PurpleStep{
			Order:                int32(s.Order),
			Tactic:               s.Tactic,
			Technique:            s.Technique,
			TechniqueName:        s.TechniqueName,
			Title:                s.Title,
			Description:          s.Description,
			DetectionExpectation: s.DetectionExpectation,
			Defense:              s.Defense,
			SafeEmulation:        s.SafeEmulation,
			Outcome:              string(outcome),
			Note:                 note,
		})
	}
	return connect.NewResponse(out), nil
}

// --- mapping helpers ---

func purpleCoverageProto(s detection.Summary) *aresv1.PurpleCoverage {
	out := &aresv1.PurpleCoverage{
		Total:           int32(s.Total),
		Covered:         int32(s.Covered()),
		CoveragePercent: int32(s.CoveragePercent),
		Counts:          map[string]int32{},
	}
	for o, n := range s.Counts {
		out.Counts[string(o)] = int32(n)
	}
	return out
}

func detectionSummaryProto(s detection.Summary) *aresv1.DetectionSummary {
	out := &aresv1.DetectionSummary{
		Total:           int32(s.Total),
		Covered:         int32(s.Covered()),
		CoveragePercent: int32(s.CoveragePercent),
		Counts:          map[string]int32{},
	}
	for o, n := range s.Counts {
		out.Counts[string(o)] = int32(n)
	}
	for _, t := range s.Techniques {
		out.Techniques = append(out.Techniques, &aresv1.TechniqueStatus{
			Technique: t.Technique,
			Findings:  int32(t.Findings),
			Outcome:   string(t.Outcome),
			Note:      t.Note,
		})
	}
	return out
}

func riskPictureProto(r intel.RiskPicture) *aresv1.RiskPicture {
	out := &aresv1.RiskPicture{
		Target:    r.Target,
		Score:     int32(r.Score),
		Rating:    r.Rating,
		Unchained: append([]string(nil), r.Unchained...),
	}
	for _, p := range r.Paths {
		ap := &aresv1.AttackPath{
			Name:     p.Name,
			Outcome:  p.Outcome,
			Severity: p.Severity,
			Priority: int32(p.Priority),
			Why:      p.Why,
		}
		for _, s := range p.Steps {
			ap.Steps = append(ap.Steps, &aresv1.PathStep{
				Title:     s.Title,
				Technique: s.Technique,
				Role:      s.Role,
			})
		}
		out.Paths = append(out.Paths, ap)
	}
	return out
}

func tenantProto(t *tenant.Tenant) *aresv1.Tenant {
	return &aresv1.Tenant{
		Id:        t.ID,
		Name:      t.Name,
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
	}
}

func engagementProto(e *engagement.Engagement) *aresv1.Engagement {
	pe := &aresv1.Engagement{
		Id:        e.ID,
		TenantId:  e.TenantID,
		Name:      e.Name,
		Status:    string(e.Status),
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
	if e.Authorization != nil {
		pe.Authorization = &aresv1.Authorization{
			Document:   e.Authorization.Document,
			ApprovedBy: e.Authorization.ApprovedBy,
			ApprovedAt: e.Authorization.ApprovedAt.Format(time.RFC3339),
		}
	}
	// The saved scope, so the scope screen can show and edit what is in force.
	snap := e.Scope.Snapshot()
	pe.InScope = append([]string(nil), snap.InScope...)
	pe.Exclude = append([]string(nil), snap.Exclude...)
	return pe
}

func targetDomain(t *aresv1.Target) module.Target {
	if t == nil {
		return module.Target{}
	}
	return module.Target{Host: t.GetHost(), Port: int(t.GetPort()), URL: t.GetUrl()}
}

func targetProto(t module.Target) *aresv1.Target {
	return &aresv1.Target{Host: t.Host, Port: int32(t.Port), Url: t.URL}
}

func outcomeProto(o worker.Outcome) *aresv1.JobOutcome {
	status := "done"
	if o.Running() {
		status = "running"
	}
	jo := &aresv1.JobOutcome{
		Status:            status,
		JobId:             o.JobID,
		Engagement:        o.Engagement,
		Module:            o.Module,
		Error:             o.Error,
		CurrentCapability: o.CurrentCapability,
	}
	for _, t := range o.Allowed {
		jo.Allowed = append(jo.Allowed, targetProto(t))
	}
	for _, d := range o.Denied {
		jo.Denied = append(jo.Denied, &aresv1.Denial{Target: targetProto(d.Target), Reason: d.Reason})
	}
	for _, r := range o.Results {
		pr := &aresv1.Result{
			Capability: r.Capability,
			Kind:       r.Kind,
			Target:     targetProto(r.Target),
			Technique:  r.Technique,
		}
		if s, err := mapToStruct(r.Data); err == nil {
			pr.Data = s
		}
		pr.Proof = proofProto(r.Proof)
		pr.Remediation = remediationProto(r)
		jo.Results = append(jo.Results, pr)
	}
	return jo
}

// structToJSON converts job params (a protobuf Struct) back to the json.RawMessage
// the module.Configurable contract expects. An empty struct yields nil params.
func structToJSON(s *structpb.Struct) (json.RawMessage, error) {
	if s == nil || len(s.GetFields()) == 0 {
		return nil, nil
	}
	b, err := protojson.Marshal(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
