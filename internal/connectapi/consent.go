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
	"time"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/technique"
	"github.com/gsoultan/ares/module"
)

// Test intensity and consent: the engagement's level, the tests above safe
// proof and the single-use approvals for intrusive ones. The worker enforces
// the same gate before anything runs (engagement.ConsentGate); these calls
// record the consent and check it early so the operator gets a clear answer.

// JobStopper stops one running job. The worker pool implements it.
type JobStopper interface {
	Stop(jobID string) bool
}

// WithJobs lets StopJob reach the running jobs.
func (h *Handler) WithJobs(s JobStopper) *Handler {
	h.jobs = s
	return h
}

// requireConsentManager refuses a consent change from a signed-in member: raising the
// intensity or approving an intrusive test is a manager's decision. With
// authentication off (a single-operator install) there is no session to check.
func requireConsentManager(ctx context.Context) error {
	if sess, ok := SessionFromContext(ctx); ok && !sess.Role.IsManager() {
		return connect.NewError(connect.CodePermissionDenied,
			errors.New("only an owner or admin can change test intensity or approve an intrusive test"))
	}
	return nil
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func approvalProto(a engagement.Approval) *aresv1.TechniqueApproval {
	return &aresv1.TechniqueApproval{
		Id:         a.ID,
		Module:     a.Module,
		Target:     a.Target,
		ApprovedBy: a.ApprovedBy,
		How:        a.How,
		Note:       a.Note,
		ApprovedAt: rfc3339(a.ApprovedAt),
		JobId:      a.JobID,
		UsedAt:     rfc3339(a.UsedAt),
		Withdrawn:  a.Withdrawn,
	}
}

func (h *Handler) testConsentProto(eng *engagement.Engagement) *aresv1.TestConsent {
	c := eng.ConsentSnapshot()
	out := &aresv1.TestConsent{
		Level: int32(c.Level),
		SetBy: c.SetBy,
		SetAt: rfc3339(c.SetAt),
	}
	for _, t := range technique.AboveSafeProof(h.reg) {
		out.Techniques = append(out.Techniques, &aresv1.TechniqueInfo{
			Module:     t.Module,
			Level:      int32(t.Level),
			Name:       t.Name,
			Action:     t.Action,
			Risk:       t.Risk,
			Reversible: t.Reversible,
			Recovery:   t.Recovery,
			Touches:    t.Touches,
			Limit:      t.Limit,
		})
	}
	// Newest first: the approval just recorded is at the top.
	for i := len(c.Approvals) - 1; i >= 0; i-- {
		out.Approvals = append(out.Approvals, approvalProto(c.Approvals[i]))
	}
	return out
}

// GetTestConsent returns the engagement's level, the tests above safe proof
// and the approvals on file.
func (h *Handler) GetTestConsent(_ context.Context, req *connect.Request[aresv1.GetTestConsentRequest]) (*connect.Response[aresv1.TestConsent], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(h.testConsentProto(eng)), nil
}

// SetTestIntensity sets the highest level the engagement allows.
func (h *Handler) SetTestIntensity(ctx context.Context, req *connect.Request[aresv1.SetTestIntensityRequest]) (*connect.Response[aresv1.TestConsent], error) {
	if err := requireConsentManager(ctx); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	if ok, reason := eng.CanRun(); !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(reason))
	}
	actor := auth.Actor(ctx, req.Msg.GetActor(), "operator")
	if err := eng.SetTestLevel(module.ConsentLevel(req.Msg.GetLevel()), actor); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(h.testConsentProto(eng)), nil
}

// ApproveTechnique records a single-use approval for one intrusive test
// against one target.
func (h *Handler) ApproveTechnique(ctx context.Context, req *connect.Request[aresv1.ApproveTechniqueRequest]) (*connect.Response[aresv1.TechniqueApproval], error) {
	if err := requireConsentManager(ctx); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	mod := req.Msg.GetModule()
	if _, known := h.reg.Get(mod); !known {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown test"))
	}
	if technique.LevelOf(h.reg, mod) < module.LevelIntrusive {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("this test does not need a per-run approval"))
	}
	a, err := eng.Approve(mod, targetDomain(req.Msg.GetTarget()), req.Msg.GetApprovedBy(), req.Msg.GetHow(), req.Msg.GetNote())
	if err != nil {
		code := connect.CodeInvalidArgument
		if errors.Is(err, engagement.ErrAboveIntensity) {
			code = connect.CodeFailedPrecondition
		}
		return nil, connect.NewError(code, err)
	}
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(approvalProto(a)), nil
}

// DeclineTechnique records that an intrusive test was not allowed.
func (h *Handler) DeclineTechnique(ctx context.Context, req *connect.Request[aresv1.DeclineTechniqueRequest]) (*connect.Response[aresv1.DeclineTechniqueResponse], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	actor := auth.Actor(ctx, req.Msg.GetActor(), "operator")
	eng.Decline(req.Msg.GetModule(), targetDomain(req.Msg.GetTarget()), actor, req.Msg.GetNote())
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&aresv1.DeclineTechniqueResponse{Ok: true}), nil
}

// WithdrawApproval takes back an unused approval.
func (h *Handler) WithdrawApproval(ctx context.Context, req *connect.Request[aresv1.WithdrawApprovalRequest]) (*connect.Response[aresv1.TestConsent], error) {
	if err := requireConsentManager(ctx); err != nil {
		return nil, err
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	actor := auth.Actor(ctx, req.Msg.GetActor(), "operator")
	if err := eng.Withdraw(req.Msg.GetApprovalId(), actor); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.store.Save(eng); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(h.testConsentProto(eng)), nil
}

// StopJob stops one running test without stopping the engagement. A job from
// another workspace is reported as not running, so ids leak nothing.
func (h *Handler) StopJob(ctx context.Context, req *connect.Request[aresv1.StopJobRequest]) (*connect.Response[aresv1.StopJobResponse], error) {
	if h.jobs == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("stopping a single test is not available"))
	}
	jobID := req.Msg.GetJobId()
	engID := ""
	if o, ok := h.outcomes.Get(jobID); ok {
		engID = o.Engagement
	} else if p, ok := h.pending.get(jobID); ok {
		engID = p
	}
	if engID == "" {
		return connect.NewResponse(&aresv1.StopJobResponse{}), nil
	}
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), engID)
	if err != nil {
		return connect.NewResponse(&aresv1.StopJobResponse{}), nil
	}
	stopped := h.jobs.Stop(jobID)
	if stopped {
		actor := auth.Actor(ctx, req.Msg.GetActor(), "operator")
		eng.Audit.Append(actor, "job-stopped", jobID, "stopped by hand")
		_ = h.store.Save(eng)
	}
	return connect.NewResponse(&aresv1.StopJobResponse{Stopped: stopped}), nil
}

// consentPrecheck runs the consent gate at dispatch, so the operator hears at
// once why a test cannot run. For an intrusive test it reserves the approvals
// for the job id the worker will run under; the worker's own gate then accepts
// the same reservation.
func (h *Handler) consentPrecheck(eng *engagement.Engagement, mod string, params json.RawMessage, targets []module.Target, jobID string) error {
	level, err := technique.LevelForJob(h.reg, mod, params)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if level <= module.LevelSafeProof {
		return nil
	}
	// Only in-scope targets are ever run, and only they need approvals.
	now := time.Now()
	in := make([]module.Target, 0, len(targets))
	for _, t := range targets {
		if ok, _ := eng.Scope.AllowAt(t, now); ok {
			in = append(in, t)
		}
	}
	if _, err := eng.ConsentGate(mod, level, in, jobID); err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return nil
}
