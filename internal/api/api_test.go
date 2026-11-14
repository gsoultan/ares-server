// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	reg := module.NewRegistry()
	store := engagement.NewMemStore()
	q := queue.New(8)
	outcomes := worker.NewMemOutcomes()
	return New(store, reg, q, outcomes).Routes()
}

// do runs a request against the handler, optionally in a workspace (header).
func do(t *testing.T, h http.Handler, method, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if tenant != "" {
		r.Header.Set("X-Ares-Tenant", tenant)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRESTTenantIsolation(t *testing.T) {
	h := newTestServer(t)

	// Create a workspace.
	w := do(t, h, "POST", "/api/tenants", "", map[string]string{"name": "Acme"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create tenant: status %d", w.Code)
	}
	var tn struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tn); err != nil {
		t.Fatalf("decode tenant: %v", err)
	}

	// The default workspace is always listed alongside the new one.
	w = do(t, h, "GET", "/api/tenants", "", nil)
	var tl struct {
		Tenants []struct {
			ID string `json:"id"`
		} `json:"tenants"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tl)
	if len(tl.Tenants) != 2 {
		t.Fatalf("tenants = %d, want 2 (Acme + default)", len(tl.Tenants))
	}

	// Create an engagement inside Acme via the workspace header.
	w = do(t, h, "POST", "/api/engagements", tn.ID, map[string]string{"name": "Acme app"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create engagement: status %d body %s", w.Code, w.Body.String())
	}
	var eng struct {
		ID       string `json:"id"`
		TenantID string `json:"tenantId"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &eng)
	if eng.TenantID != tn.ID {
		t.Fatalf("engagement tenant = %q, want %q", eng.TenantID, tn.ID)
	}

	// The default workspace listing must not include it.
	w = do(t, h, "GET", "/api/engagements", "", nil)
	var def struct {
		Engagements []struct {
			ID string `json:"id"`
		} `json:"engagements"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &def)
	if len(def.Engagements) != 0 {
		t.Fatalf("default workspace listing = %+v, want empty", def.Engagements)
	}

	// Reading the engagement from the wrong workspace is a 404.
	if w := do(t, h, "GET", "/api/engagements/"+eng.ID, "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET: status %d, want 404", w.Code)
	}
	// Reading it from its own workspace succeeds.
	if w := do(t, h, "GET", "/api/engagements/"+eng.ID, tn.ID, nil); w.Code != http.StatusOK {
		t.Fatalf("same-tenant GET: status %d, want 200", w.Code)
	}
}

func TestRESTCreateUnderUnknownTenant(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, "POST", "/api/engagements", "tnt-ghost", map[string]string{"name": "Nope"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("create under unknown tenant: status %d, want 404", w.Code)
	}
}

func TestRESTDetectionFlow(t *testing.T) {
	reg := module.NewRegistry()
	store := engagement.NewMemStore()
	q := queue.New(8)
	outcomes := worker.NewMemOutcomes()
	h := New(store, reg, q, outcomes).Routes()

	w := do(t, h, "POST", "/api/engagements", "", map[string]string{"name": "Det"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create engagement: status %d", w.Code)
	}
	var eng struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &eng); err != nil {
		t.Fatalf("decode engagement: %v", err)
	}

	// Seed an outcome whose findings exercise two techniques; the info result
	// must not count toward exercised techniques.
	outcomes.Save(worker.Outcome{
		JobID:      "j1",
		Engagement: eng.ID,
		Results: []module.Result{
			{Kind: "finding", Technique: "T1190"},
			{Kind: "finding", Technique: "T1190"},
			{Kind: "finding", Technique: "T1552"},
			{Kind: "info", Technique: "T9999"},
		},
	})

	type summary struct {
		Total           int `json:"total"`
		CoveragePercent int `json:"coveragePercent"`
		Techniques      []struct {
			Technique string `json:"technique"`
			Findings  int    `json:"findings"`
			Outcome   string `json:"outcome"`
		} `json:"techniques"`
	}

	// Initial summary: two techniques exercised, nothing recorded yet.
	w = do(t, h, "GET", "/api/engagements/"+eng.ID+"/detection", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get detection: status %d", w.Code)
	}
	var s summary
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if s.Total != 2 || s.CoveragePercent != 0 {
		t.Fatalf("initial summary total=%d coverage=%d, want 2/0", s.Total, s.CoveragePercent)
	}

	// Record one technique as detected; coverage becomes 1 of 2 = 50%.
	w = do(t, h, "POST", "/api/engagements/"+eng.ID+"/detection", "",
		map[string]string{"technique": "T1190", "outcome": "detected"})
	if w.Code != http.StatusOK {
		t.Fatalf("set detection: status %d (%s)", w.Code, w.Body.String())
	}
	s = summary{}
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if s.CoveragePercent != 50 {
		t.Fatalf("coverage after one detected = %d, want 50", s.CoveragePercent)
	}

	// An unknown outcome is rejected.
	w = do(t, h, "POST", "/api/engagements/"+eng.ID+"/detection", "",
		map[string]string{"technique": "T1190", "outcome": "bogus"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad outcome: status %d, want 400", w.Code)
	}

	// Another workspace cannot see or set this engagement's detection.
	w = do(t, h, "GET", "/api/engagements/"+eng.ID+"/detection", "someone-else", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant detection read: status %d, want 404", w.Code)
	}
}

func TestRESTPurpleFlow(t *testing.T) {
	reg := module.NewRegistry()
	store := engagement.NewMemStore()
	q := queue.New(8)
	outcomes := worker.NewMemOutcomes()
	h := New(store, reg, q, outcomes).Routes()

	// The catalog listing is global and carries no coverage.
	type tmpl struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		StepCount int    `json:"stepCount"`
		Coverage  *struct {
			Total           int `json:"total"`
			Covered         int `json:"covered"`
			CoveragePercent int `json:"coveragePercent"`
		} `json:"coverage"`
	}
	w := do(t, h, "GET", "/api/purple", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list purple: status %d", w.Code)
	}
	var cat struct {
		Templates []tmpl `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cat); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(cat.Templates) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, c := range cat.Templates {
		if c.Coverage != nil {
			t.Fatalf("catalog template %q carries coverage; should not", c.ID)
		}
	}

	w = do(t, h, "POST", "/api/engagements", "", map[string]string{"name": "Purple"})
	var eng struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &eng)

	// The log4shell template exercises three techniques (T1190, T1203, T1105).
	// With nothing recorded, coverage is 0 of 3.
	w = do(t, h, "GET", "/api/engagements/"+eng.ID+"/purple", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("engagement purple list: status %d", w.Code)
	}
	var scored struct {
		Templates []tmpl `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &scored); err != nil {
		t.Fatalf("decode scored: %v", err)
	}
	var log4 *tmpl
	for i := range scored.Templates {
		if scored.Templates[i].ID == "log4shell" {
			log4 = &scored.Templates[i]
		}
	}
	if log4 == nil {
		t.Fatal("log4shell missing from scored list")
	}
	if log4.Coverage == nil || log4.Coverage.Total != 3 || log4.Coverage.CoveragePercent != 0 {
		t.Fatalf("log4shell initial coverage = %+v, want total 3 / 0%%", log4.Coverage)
	}

	// Record T1190 as detected; log4shell coverage becomes 1 of 3 = 33%.
	w = do(t, h, "POST", "/api/engagements/"+eng.ID+"/detection", "",
		map[string]string{"technique": "T1190", "outcome": "detected"})
	if w.Code != http.StatusOK {
		t.Fatalf("set detection: status %d", w.Code)
	}

	w = do(t, h, "GET", "/api/engagements/"+eng.ID+"/purple/log4shell", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get scored template: status %d", w.Code)
	}
	var detail struct {
		ID    string `json:"id"`
		Steps []struct {
			Technique string `json:"technique"`
			Outcome   string `json:"outcome"`
		} `json:"steps"`
		Coverage struct {
			Total           int `json:"total"`
			Covered         int `json:"covered"`
			CoveragePercent int `json:"coveragePercent"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Coverage.Covered != 1 || detail.Coverage.CoveragePercent != 33 {
		t.Fatalf("log4shell coverage after one detected = %+v, want covered 1 / 33%%", detail.Coverage)
	}
	var sawDetected bool
	for _, st := range detail.Steps {
		if st.Technique == "T1190" {
			if st.Outcome != "detected" {
				t.Fatalf("T1190 step outcome = %q, want detected", st.Outcome)
			}
			sawDetected = true
		}
	}
	if !sawDetected {
		t.Fatal("no T1190 step found in log4shell detail")
	}

	// Unknown template id is a 404.
	w = do(t, h, "GET", "/api/engagements/"+eng.ID+"/purple/nope", "", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown template: status %d, want 404", w.Code)
	}

	// Another workspace cannot read this engagement's scored templates.
	w = do(t, h, "GET", "/api/engagements/"+eng.ID+"/purple/log4shell", "someone-else", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant purple read: status %d, want 404", w.Code)
	}
}
