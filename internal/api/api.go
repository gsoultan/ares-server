// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package api is the control-plane HTTP surface. It exposes engagements, the
// permission gate configuration, the authorization step, job dispatch, and the
// audit trail. Dispatching a job only enqueues it; the worker pool runs it.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/eta"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/report"
	"github.com/gsoultan/ares-server/internal/technique"
	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/detection"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/purple"
)

// tenantHeader names the workspace a REST request acts in. An empty or absent
// header means the default workspace.
const tenantHeader = "X-Ares-Tenant"

func tenantOf(r *http.Request) string {
	return engagement.ResolveTenant(r.Header.Get(tenantHeader))
}

// boundToTenant reports whether the caller is confined to one workspace: an
// authenticated account other than a super-admin. Such a caller may never name
// another workspace, in a header or in a body.
func boundToTenant(r *http.Request) (auth.Session, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	return sess, ok && sess.Role != auth.RoleSuperAdmin
}

// Server holds the control-plane dependencies.
type Server struct {
	store    engagement.Store
	reg      *module.Registry
	queue    *queue.Queue
	outcomes worker.OutcomeStore
	purple   *purple.Catalog
}

// New builds a control-plane server.
func New(store engagement.Store, reg *module.Registry, q *queue.Queue, outcomes worker.OutcomeStore) *Server {
	return &Server{store: store, reg: reg, queue: q, outcomes: outcomes, purple: purple.NewCatalog()}
}

// Routes returns the HTTP handler for the control plane.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/modules", s.listModules)
	mux.HandleFunc("POST /api/tenants", s.createTenant)
	mux.HandleFunc("GET /api/tenants", s.listTenants)
	mux.HandleFunc("POST /api/engagements", s.createEngagement)
	mux.HandleFunc("GET /api/engagements", s.listEngagements)
	mux.HandleFunc("GET /api/engagements/{id}", s.getEngagement)
	mux.HandleFunc("POST /api/engagements/{id}/scope", s.setScope)
	mux.HandleFunc("POST /api/engagements/{id}/authorize", s.authorize)
	mux.HandleFunc("POST /api/engagements/{id}/halt", s.halt)
	mux.HandleFunc("POST /api/engagements/{id}/jobs", s.dispatchJob)
	mux.HandleFunc("GET /api/engagements/{id}/audit", s.getAudit)
	mux.HandleFunc("GET /api/engagements/{id}/report", s.getReport)
	mux.HandleFunc("GET /api/engagements/{id}/detection", s.getDetection)
	mux.HandleFunc("POST /api/engagements/{id}/detection", s.setDetection)
	mux.HandleFunc("GET /api/purple", s.listPurpleTemplates)
	mux.HandleFunc("GET /api/engagements/{id}/purple", s.listEngagementPurple)
	mux.HandleFunc("GET /api/engagements/{id}/purple/{templateId}", s.getEngagementPurple)
	mux.HandleFunc("GET /api/jobs/{jobId}", s.getJob)
	return mux
}

func (s *Server) listModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"modules": s.reg.Names()})
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// Creating a workspace is a platform action: only a super-admin may do it
	// once accounts exist.
	if _, bound := boundToTenant(r); bound {
		writeError(w, http.StatusForbidden, "only a super-admin may create workspaces")
		return
	}
	writeJSON(w, http.StatusCreated, s.store.CreateTenant(body.Name))
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	// A workspace-bound caller sees only its own workspace, never the names of
	// the platform's other clients.
	if sess, bound := boundToTenant(r); bound {
		list := []any{}
		if t, ok := s.store.GetTenant(sess.TenantID); ok {
			list = append(list, t)
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": list})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": s.store.ListTenants()})
}

// scopedEngagement fetches an engagement by path id and confirms it belongs to
// the request's workspace, so one tenant can never read or act on another's.
func (s *Server) scopedEngagement(r *http.Request) (*engagement.Engagement, bool) {
	eng, ok := s.store.Get(r.PathValue("id"))
	if !ok || eng.TenantID != tenantOf(r) {
		return nil, false
	}
	return eng, true
}

func (s *Server) createEngagement(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		TenantID string `json:"tenantId"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// The body's tenantId wins; otherwise the workspace header applies. A
	// workspace-bound caller may only name its own workspace.
	tenantID := body.TenantID
	if tenantID == "" {
		tenantID = tenantOf(r)
	}
	if sess, bound := boundToTenant(r); bound && engagement.ResolveTenant(tenantID) != sess.TenantID {
		writeError(w, http.StatusForbidden, "cross-workspace access denied")
		return
	}
	eng, err := s.store.Create(tenantID, body.Name)
	if err != nil {
		if errors.Is(err, engagement.ErrUnknownTenant) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, engagementView(eng))
}

func (s *Server) listEngagements(w http.ResponseWriter, r *http.Request) {
	list := s.store.List(tenantOf(r))
	views := make([]any, 0, len(list))
	for _, e := range list {
		views = append(views, engagementView(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"engagements": views})
}

func (s *Server) getEngagement(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	writeJSON(w, http.StatusOK, engagementView(eng))
}

type scopeBody struct {
	InScope []string `json:"inScope"`
	Exclude []string `json:"exclude"`
	Window  *struct {
		Start     string         `json:"start"`
		End       string         `json:"end"`
		Days      []time.Weekday `json:"days"`
		StartHour *int           `json:"startHour"`
		EndHour   *int           `json:"endHour"`
	} `json:"window"`
}

func (s *Server) setScope(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	if eng.Status != engagement.StatusDraft {
		writeError(w, http.StatusConflict, "scope can only be edited while the engagement is a draft")
		return
	}
	var body scopeBody
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, e := range body.InScope {
		if err := eng.Scope.AddInScope(e); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	for _, e := range body.Exclude {
		if err := eng.Scope.AddExclusion(e); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if body.Window != nil {
		if body.Window.Start != "" {
			ts, err := time.Parse(time.RFC3339, body.Window.Start)
			if err != nil {
				writeError(w, http.StatusBadRequest, "window.start must be RFC3339")
				return
			}
			eng.Scope.Window.Start = ts
		}
		if body.Window.End != "" {
			ts, err := time.Parse(time.RFC3339, body.Window.End)
			if err != nil {
				writeError(w, http.StatusBadRequest, "window.end must be RFC3339")
				return
			}
			eng.Scope.Window.End = ts
		}
		eng.Scope.Window.Days = body.Window.Days
		if body.Window.StartHour != nil && body.Window.EndHour != nil {
			if err := eng.Scope.Window.SetHours(*body.Window.StartHour, *body.Window.EndHour); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	eng.Audit.Append("api", "scope-updated", eng.ID,
		fmt.Sprintf("%d in scope, %d excluded", len(body.InScope), len(body.Exclude)))
	if err := s.store.Save(eng); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, engagementView(eng))
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	var body struct {
		Document   string `json:"document"`
		ApprovedBy string `json:"approvedBy"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := eng.Authorize(engagement.Authorization{Document: body.Document, ApprovedBy: body.ApprovedBy}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.Save(eng); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, engagementView(eng))
}

func (s *Server) halt(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	var body struct {
		Actor string `json:"actor"`
	}
	_ = readJSON(r, &body)
	if body.Actor == "" {
		body.Actor = "operator"
	}
	eng.Halt(body.Actor)
	if err := s.store.Save(eng); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, engagementView(eng))
}

func (s *Server) dispatchJob(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	// Give the caller immediate feedback if the engagement cannot run.
	if ok, reason := eng.CanRun(); !ok {
		writeError(w, http.StatusForbidden, reason)
		return
	}
	var body struct {
		Module  string          `json:"module"`
		Actor   string          `json:"actor"`
		Targets []module.Target `json:"targets"`
		Params  json.RawMessage `json:"params"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, known := s.reg.Get(body.Module); !known {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown module %q", body.Module))
		return
	}
	if body.Actor == "" {
		body.Actor = "operator"
	}
	// The consent gate, as on the control plane. This REST surface takes no
	// approvals, so an intrusive test is refused here; the worker re-checks.
	if level := technique.LevelOf(s.reg, body.Module); level > module.LevelSafeProof {
		if level > eng.TestLevel() {
			writeError(w, http.StatusForbidden, engagement.ErrAboveIntensity.Error())
			return
		}
		if level >= module.LevelIntrusive {
			writeError(w, http.StatusForbidden, engagement.ErrNeedsApproval.Error()+"; use the control plane to approve and run it")
			return
		}
	}
	jobID := uuid.NewV7()
	if err := s.queue.TryEnqueue(queue.Job{
		ID:           jobID,
		EngagementID: eng.ID,
		Module:       body.Module,
		Actor:        body.Actor,
		Targets:      body.Targets,
		Params:       body.Params,
	}); err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "job queue is full, try again shortly", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"jobId":  jobID,
		"status": "queued",
	})
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	workspace := ""
	if t, ok := s.store.GetTenant(eng.TenantID); ok {
		workspace = t.Name
	}
	rep := report.Build(eng, workspace, s.outcomes.ByEngagement(eng.ID))

	data, contentType, ext, err := rep.Render(r.URL.Query().Get("format"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", report.Filename(eng.Name, ext)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// getDetection returns the detection-coverage summary: the techniques the
// engagement's tests exercised, the defender outcome recorded for each, and the
// coverage score.
func (s *Server) getDetection(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	ex := report.ExercisedTechniques(s.outcomes.ByEngagement(eng.ID))
	writeJSON(w, http.StatusOK, detection.BuildSummary(ex, eng.Detections()))
}

// setDetection records the defender's response for one technique and returns
// the updated summary.
func (s *Server) setDetection(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	var body struct {
		Technique string `json:"technique"`
		Outcome   string `json:"outcome"`
		Note      string `json:"note"`
		Actor     string `json:"actor"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Actor == "" {
		body.Actor = "operator"
	}
	if err := eng.SetDetection(body.Technique, detection.Outcome(body.Outcome), body.Note, body.Actor); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.Save(eng); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ex := report.ExercisedTechniques(s.outcomes.ByEngagement(eng.ID))
	writeJSON(w, http.StatusOK, detection.BuildSummary(ex, eng.Detections()))
}

// purpleCoverage is the headline detection score for a template: how many of
// its techniques the defenders prevented or detected.
type purpleCoverage struct {
	Total           int                       `json:"total"`
	Covered         int                       `json:"covered"`
	CoveragePercent int                       `json:"coveragePercent"`
	Counts          map[detection.Outcome]int `json:"counts"`
}

func coverageOf(sum detection.Summary) purpleCoverage {
	return purpleCoverage{
		Total:           sum.Total,
		Covered:         sum.Covered(),
		CoveragePercent: sum.CoveragePercent,
		Counts:          sum.Counts,
	}
}

// purpleStepView is one breach step annotated with the defender outcome the
// operator recorded for its technique.
type purpleStepView struct {
	Order                int    `json:"order"`
	Tactic               string `json:"tactic"`
	Technique            string `json:"technique"`
	TechniqueName        string `json:"techniqueName"`
	Title                string `json:"title"`
	Description          string `json:"description"`
	DetectionExpectation string `json:"detectionExpectation"`
	SafeEmulation        string `json:"safeEmulation"`
	Outcome              string `json:"outcome"` // recorded defender outcome for this technique
	Note                 string `json:"note,omitempty"`
}

// purpleSummaryView lists a template's identity and headline stats without its
// steps, for the catalog and engagement list.
type purpleSummaryView struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Summary    string          `json:"summary"`
	Reference  string          `json:"reference,omitempty"`
	StepCount  int             `json:"stepCount"`
	Techniques int             `json:"techniques"`
	Coverage   *purpleCoverage `json:"coverage,omitempty"`
}

func purpleSummary(t purple.Template) purpleSummaryView {
	return purpleSummaryView{
		ID:         t.ID,
		Name:       t.Name,
		Summary:    t.Summary,
		Reference:  t.Reference,
		StepCount:  len(t.Steps),
		Techniques: len(t.Techniques()),
	}
}

// listPurpleTemplates returns the breach catalog without engagement scoring:
// the exercises available to run, in plain language.
func (s *Server) listPurpleTemplates(w http.ResponseWriter, r *http.Request) {
	ts := s.purple.List()
	views := make([]purpleSummaryView, 0, len(ts))
	for _, t := range ts {
		views = append(views, purpleSummary(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": views})
}

// listEngagementPurple scores every template against this engagement's recorded
// detection outcomes, so the team can see which breaches they are most and
// least prepared for.
func (s *Server) listEngagementPurple(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	records := eng.Detections()
	ts := s.purple.List()
	views := make([]purpleSummaryView, 0, len(ts))
	for _, t := range ts {
		v := purpleSummary(t)
		cov := coverageOf(detection.BuildSummary(t.Techniques(), records))
		v.Coverage = &cov
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": views})
}

// getEngagementPurple returns one template fully scored against the engagement:
// every step annotated with its recorded defender outcome, plus the coverage
// score over the template's techniques.
func (s *Server) getEngagementPurple(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	t, ok := s.purple.Get(r.PathValue("templateId"))
	if !ok {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	records := eng.Detections()
	steps := make([]purpleStepView, 0, len(t.Steps))
	for _, s := range t.Steps {
		outcome := detection.Unknown
		note := ""
		if rec, ok := records[s.Technique]; ok && detection.Valid(rec.Outcome) {
			outcome = rec.Outcome
			note = rec.Note
		}
		steps = append(steps, purpleStepView{
			Order:                s.Order,
			Tactic:               s.Tactic,
			Technique:            s.Technique,
			TechniqueName:        s.TechniqueName,
			Title:                s.Title,
			Description:          s.Description,
			DetectionExpectation: s.DetectionExpectation,
			SafeEmulation:        s.SafeEmulation,
			Outcome:              string(outcome),
			Note:                 note,
		})
	}
	cov := coverageOf(detection.BuildSummary(t.Techniques(), records))
	writeJSON(w, http.StatusOK, map[string]any{
		"id":        t.ID,
		"name":      t.Name,
		"summary":   t.Summary,
		"reference": t.Reference,
		"steps":     steps,
		"coverage":  cov,
	})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	o, ok := s.outcomes.Get(r.PathValue("jobId"))
	// A job belongs to its engagement's workspace: a caller in another one sees
	// the same "pending" it would for an unknown id, so job ids leak nothing.
	if ok {
		if eng, found := s.store.Get(o.Engagement); !found || eng.TenantID != tenantOf(r) {
			ok = false
		}
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	}
	// The outcome, plus how long it has left when the store can estimate it.
	resp := struct {
		worker.Outcome
		TimeLeft *eta.Estimate `json:"timeLeft,omitempty"`
	}{Outcome: o}
	if est, can := s.outcomes.(worker.Estimator); can {
		e := est.Estimate(o, time.Now())
		resp.TimeLeft = &e
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.scopedEngagement(r)
	if !ok {
		writeError(w, http.StatusNotFound, "engagement not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": eng.Audit.Entries(),
		"valid":   eng.Audit.Verify() == nil,
	})
}

// engagementView is the JSON shape returned for an engagement.
func engagementView(e *engagement.Engagement) map[string]any {
	return map[string]any{
		"id":            e.ID,
		"tenantId":      e.TenantID,
		"name":          e.Name,
		"status":        e.Status,
		"authorization": e.Authorization,
		"createdAt":     e.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}
