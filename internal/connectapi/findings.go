// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/worker"
)

// findingStatusStore holds the operator-set triage state per finding id. It is
// in-memory, matching the in-memory outcome store: findings are derived from job
// outcomes and do not survive a restart, so their status need not either.
type findingStatusStore struct {
	mu       sync.Mutex
	m        map[string]string
	versions map[string]uint64 // engagement -> bumps on every status change
}

func newFindingStatusStore() *findingStatusStore {
	return &findingStatusStore{m: make(map[string]string), versions: make(map[string]uint64)}
}

func (s *findingStatusStore) get(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[id]; ok {
		return v
	}
	return "open"
}

// set records a finding's status; engagementID is the finding's engagement, so
// cached findings views of that engagement are invalidated.
func (s *findingStatusStore) set(engagementID, id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = status
	s.versions[engagementID]++
}

// version changes whenever a status of one of the engagement's findings does.
func (s *findingStatusStore) version(engagementID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.versions[engagementID]
}

// restoreFindingStatuses rebuilds the triage state from the audit trails, where
// every status change is recorded ("finding-status", target = finding id,
// detail = status). Job outcomes now survive a restart, so their findings'
// statuses must too; the audit trail already holds them, in order.
func (h *Handler) restoreFindingStatuses() {
	for _, t := range h.store.ListTenants() {
		for _, eng := range h.store.List(t.ID) {
			for _, e := range eng.Audit.Entries() {
				if e.Action == "finding-status" && validFindingStatus(e.Detail) {
					h.statuses.set(eng.ID, e.Target, e.Detail)
				}
			}
		}
	}
}

func validFindingStatus(s string) bool {
	switch s {
	case "open", "in_progress", "fixed":
		return true
	}
	return false
}

// pendingJobs tracks dispatched jobs that have not yet produced an outcome, so
// ListJobs can show a "running" row that survives a page reload. Entries are
// pruned once the worker records the job's outcome.
type pendingJobs struct {
	mu sync.Mutex
	m  map[string]pendingJob
}

type pendingJob struct {
	engagement string
	module     string
	started    time.Time
}

func newPendingJobs() *pendingJobs { return &pendingJobs{m: make(map[string]pendingJob)} }

func (p *pendingJobs) add(jobID, engagement, module string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[jobID] = pendingJob{engagement: engagement, module: module, started: time.Now()}
}

func (p *pendingJobs) remove(jobID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, jobID)
}

// snapshot returns a copy of the pending jobs for one engagement.
func (p *pendingJobs) snapshot(engagement string) map[string]pendingJob {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]pendingJob{}
	for id, j := range p.m {
		if j.engagement == engagement {
			out[id] = j
		}
	}
	return out
}

// rfc renders a time as RFC3339 (UTC), or "" when zero.
func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ListJobs lists an engagement's completed jobs, newest first — enough for the
// "earlier tests" view and to reopen one with GetJob.
func (h *Handler) ListJobs(_ context.Context, req *connect.Request[aresv1.ListJobsRequest]) (*connect.Response[aresv1.ListJobsResponse], error) {
	eng, err := h.engagementInTenant(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	resp := &aresv1.ListJobsResponse{}
	completed := map[string]bool{}
	now := time.Now()
	for _, o := range h.outcomes.ByEngagement(eng.ID) { // already newest first
		completed[o.JobID] = true
		status := "done"
		switch {
		case o.Running():
			// An in-flight snapshot: the job has started but not finished.
			status = "running"
		case o.Error != "":
			status = "error"
		}
		findings := 0
		for _, r := range o.Results {
			if r.Kind == "finding" {
				findings++
			}
		}
		resp.Jobs = append(resp.Jobs, &aresv1.JobSummary{
			JobId:      o.JobID,
			Module:     o.Module,
			Status:     status,
			StartedAt:  rfc(o.StartedAt),
			FinishedAt: rfc(o.FinishedAt),
			Allowed:    int32(len(o.Allowed)),
			Denied:     int32(len(o.Denied)),
			Findings:   int32(findings),
			Error:      o.Error,
			Progress:   progressProto(o, h.outcomes, now),
		})
	}
	// Add still-running jobs (dispatched, no outcome yet), and prune any pending
	// entry the worker has since completed.
	for id, pj := range h.pending.snapshot(eng.ID) {
		if completed[id] {
			h.pending.remove(id)
			continue
		}
		resp.Jobs = append(resp.Jobs, &aresv1.JobSummary{
			JobId:     id,
			Module:    pj.module,
			Status:    "running",
			StartedAt: rfc(pj.started),
		})
	}
	// Newest first across completed and running (RFC3339 sorts chronologically).
	sort.SliceStable(resp.Jobs, func(i, j int) bool {
		return resp.Jobs[i].GetStartedAt() > resp.Jobs[j].GetStartedAt()
	})
	return connect.NewResponse(resp), nil
}

// ListFindings lists the findings of one engagement, or of the whole workspace
// when engagement_id is empty, deduplicated across re-runs.
func (h *Handler) ListFindings(_ context.Context, req *connect.Request[aresv1.ListFindingsRequest]) (*connect.Response[aresv1.ListFindingsResponse], error) {
	engIDs, engName, err := h.workspaceEngagements(req.Msg.GetTenantId(), req.Msg.GetEngagementId())
	if err != nil {
		return nil, err
	}
	key := engagement.ResolveTenant(req.Msg.GetTenantId()) + "|" + req.Msg.GetEngagementId()
	return connect.NewResponse(&aresv1.ListFindingsResponse{Findings: h.cachedFindings(key, engIDs, engName)}), nil
}

// SetFindingStatus records the operator's triage state for a finding and audits
// it on the finding's engagement.
func (h *Handler) SetFindingStatus(_ context.Context, req *connect.Request[aresv1.SetFindingStatusRequest]) (*connect.Response[aresv1.Finding], error) {
	status := req.Msg.GetStatus()
	if !validFindingStatus(status) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("status must be open, in_progress or fixed"))
	}
	// Locate the finding across the caller's workspace. This enforces tenant
	// isolation (a finding in another workspace is simply not found) and gives us
	// the engagement to audit.
	engIDs, engName, err := h.workspaceEngagements(req.Msg.GetTenantId(), "")
	if err != nil {
		return nil, err
	}
	var found *aresv1.Finding
	key := engagement.ResolveTenant(req.Msg.GetTenantId()) + "|"
	for _, f := range h.cachedFindings(key, engIDs, engName) {
		if f.GetId() == req.Msg.GetId() {
			// The cached list is shared with concurrent readers: never mutate it.
			found = proto.Clone(f).(*aresv1.Finding)
			break
		}
	}
	if found == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("finding not found"))
	}
	h.statuses.set(found.GetEngagementId(), found.GetId(), status)
	found.Status = status

	actor := req.Msg.GetActor()
	if actor == "" {
		actor = "operator"
	}
	if eng, err := h.engagementInTenant(req.Msg.GetTenantId(), found.GetEngagementId()); err == nil {
		eng.Audit.Append(actor, "finding-status", found.GetId(), status)
		_ = h.store.Save(eng)
	}
	return connect.NewResponse(found), nil
}

// workspaceEngagements resolves the engagement ids and names a findings query
// spans: one engagement when id is set (tenant-checked), else every engagement
// in the workspace.
func (h *Handler) workspaceEngagements(tenantID, id string) ([]string, map[string]string, error) {
	engName := map[string]string{}
	if id != "" {
		eng, err := h.engagementInTenant(tenantID, id)
		if err != nil {
			return nil, nil, err
		}
		engName[eng.ID] = eng.Name
		return []string{eng.ID}, engName, nil
	}
	var ids []string
	for _, e := range h.store.List(tenantID) {
		ids = append(ids, e.ID)
		engName[e.ID] = e.Name
	}
	// A stable order keeps the aggregate deterministic and its cache fingerprint
	// independent of map iteration order.
	sort.Strings(ids)
	return ids, engName, nil
}

// cachedFindings is collectFindings behind the read-path memo. The result is a
// pure function of the engagements' outcomes and finding statuses, both
// versioned, so it is rebuilt only after one of them changes, not on every page
// load. key scopes the entry to the caller's workspace and query. The returned
// slice and its findings are shared: callers must not mutate them.
func (h *Handler) cachedFindings(key string, engIDs []string, engName map[string]string) []*aresv1.Finding {
	fp := newFingerprint()
	for _, id := range engIDs {
		fp.str(id).str(engName[id]).num(h.outcomes.Version(id)).num(h.statuses.version(id))
	}
	return h.memo.get("findings|"+key, fp.sum(), func() any {
		return h.collectFindings(engIDs, engName)
	}).([]*aresv1.Finding)
}

// findingKey is a finding's stable identity across runs: the engagement, the
// module that raised it, its technique, title and target.
func findingKey(engID, module, technique, title, target string) string {
	sum := sha256.Sum256([]byte(engID + "\x00" + module + "\x00" + technique + "\x00" + title + "\x00" + target))
	return hex.EncodeToString(sum[:16]) // 128-bit id
}

// collectFindings aggregates the findings across a set of engagements:
// deduplicated by stable id, with the earliest found_at, the latest last_seen
// and job, each finding's status, and whether it is still present (a later run
// of the same module+target re-raised it).
func (h *Handler) collectFindings(engIDs []string, engName map[string]string) []*aresv1.Finding {
	var outcomes []worker.Outcome
	for _, id := range engIDs {
		outcomes = append(outcomes, h.outcomes.ByEngagement(id)...) // newest first within each
	}

	// When was each (module, target) last run? A finding is "still present" only
	// if no later run of its module+target happened without re-raising it.
	latestRun := map[string]time.Time{}
	for _, o := range outcomes {
		for mt := range ranModuleTargets(o) {
			if o.StartedAt.After(latestRun[mt]) {
				latestRun[mt] = o.StartedAt
			}
		}
	}

	type agg struct {
		f        *aresv1.Finding
		foundAt  time.Time
		lastSeen time.Time
		module   string
		target   string
	}
	byID := map[string]*agg{}
	var order []string

	for _, o := range outcomes {
		for _, r := range o.Results {
			if r.Kind != "finding" && r.Kind != "info" {
				continue
			}
			title, _ := r.Data["title"].(string)
			target := r.Target.String()
			id := findingKey(o.Engagement, r.Capability, r.Technique, title, target)

			a, ok := byID[id]
			if !ok {
				// First time seen (and, within an engagement, the most recent run).
				f := &aresv1.Finding{
					Id:             id,
					EngagementId:   o.Engagement,
					EngagementName: engName[o.Engagement],
					JobId:          o.JobID,
					Module:         r.Capability,
					Kind:           r.Kind,
					Target:         target,
					Technique:      r.Technique,
					FoundAt:        rfc(o.StartedAt),
					LastSeen:       rfc(o.StartedAt),
					Status:         h.statuses.get(id),
				}
				if s, err := mapToStruct(r.Data); err == nil {
					f.Data = s
				}
				a = &agg{f: f, foundAt: o.StartedAt, lastSeen: o.StartedAt, module: r.Capability, target: target}
				byID[id] = a
				order = append(order, id)
				continue
			}
			// A later (older in list) occurrence: lower found_at; raise last_seen and
			// keep the most recent run's job id and payload.
			if o.StartedAt.Before(a.foundAt) {
				a.foundAt = o.StartedAt
				a.f.FoundAt = rfc(o.StartedAt)
			}
			if o.StartedAt.After(a.lastSeen) {
				a.lastSeen = o.StartedAt
				a.f.LastSeen = rfc(o.StartedAt)
				a.f.JobId = o.JobID
				if s, err := mapToStruct(r.Data); err == nil {
					a.f.Data = s
				}
			}
		}
	}

	out := make([]*aresv1.Finding, 0, len(order))
	for _, id := range order {
		a := byID[id]
		if lr, ok := latestRun[a.module+"\x00"+a.target]; ok && lr.After(a.lastSeen) {
			a.f.StillPresent = false
		} else {
			a.f.StillPresent = true
		}
		out = append(out, a.f)
	}
	// Most recently observed first; stable within the same last_seen.
	sort.SliceStable(out, func(i, j int) bool { return out[i].GetLastSeen() > out[j].GetLastSeen() })
	return out
}

// ranModuleTargets returns the set of "module\x00target" pairs a job exercised,
// used to decide whether a later run re-checked a finding's module and target.
// It covers direct dispatch (the job's own module over its allowed targets),
// any module that produced a result, and — for an auto-run recon job — the
// sub-checks it ran, which recon records in its "planned" note even when they
// found nothing.
func ranModuleTargets(o worker.Outcome) map[string]bool {
	set := map[string]bool{}
	if o.Module != "" && o.Module != "recon" {
		for _, t := range o.Allowed {
			set[o.Module+"\x00"+t.String()] = true
		}
	}
	for _, r := range o.Results {
		set[r.Capability+"\x00"+r.Target.String()] = true
		if r.Capability == "recon" && r.Kind == "info" {
			planned, _ := r.Data["planned"].([]any)
			tgt := r.Target.String()
			for _, p := range planned {
				if name, ok := p.(string); ok {
					set[name+"\x00"+tgt] = true
				}
			}
		}
	}
	return set
}
