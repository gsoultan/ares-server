// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

// echoModule emits one finding per target it is given (the worker only hands it
// targets that cleared the gate), so a test can see what the gate let through.
type echoModule struct{}

func (echoModule) Name() string { return "echo" }
func (echoModule) Run(_ context.Context, _ module.Scope, targets []module.Target, out chan<- module.Result) error {
	for _, t := range targets {
		out <- module.Result{Capability: "echo", Kind: "finding", Target: t, Data: map[string]any{"seen": t.Host}}
	}
	return nil
}

// newTestHandler wires a handler over a real, running worker pool.
func newTestHandler(t testing.TB) *Handler {
	t.Helper()
	reg := module.NewRegistry()
	if err := reg.Register(echoModule{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	store := engagement.NewMemStore()
	q := queue.New(16)
	outcomes := worker.NewMemOutcomes()
	pool := worker.NewPool(worker.NewProcessor(reg, store), outcomes, 2)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pool.Run(ctx, q.C())

	return New(store, reg, q, outcomes)
}

func TestControlPlaneLifecycleAndGate(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	// Create.
	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	if id == "" || created.Msg.GetStatus() != "draft" {
		t.Fatalf("unexpected engagement %+v", created.Msg)
	}

	// Dispatch before authorize must be refused by the gate.
	_, err = h.DispatchJob(ctx, connect.NewRequest(&aresv1.DispatchJobRequest{
		EngagementId: id, Module: "echo",
		Targets: []*aresv1.Target{{Host: "127.0.0.1"}},
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dispatch before authorize: want PermissionDenied, got %v", err)
	}

	// Set scope: allow 127.0.0.1, exclude 10.0.0.0/8.
	if _, err := h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{
		Id: id, InScope: []string{"127.0.0.1"}, Exclude: []string{"10.0.0.0/8"},
	})); err != nil {
		t.Fatalf("SetScope: %v", err)
	}

	// Authorize.
	if _, err := h.Authorize(ctx, connect.NewRequest(&aresv1.AuthorizeRequest{
		Id: id, Document: "auth.pdf", ApprovedBy: "lead",
	})); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// Scope edits are refused once authorized.
	_, err = h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{Id: id, InScope: []string{"example.com"}}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("SetScope after authorize: want FailedPrecondition, got %v", err)
	}

	// Dispatch one in-scope and one excluded target.
	disp, err := h.DispatchJob(ctx, connect.NewRequest(&aresv1.DispatchJobRequest{
		EngagementId: id, Module: "echo",
		Targets: []*aresv1.Target{{Host: "127.0.0.1"}, {Host: "10.1.2.3"}},
	}))
	if err != nil {
		t.Fatalf("DispatchJob: %v", err)
	}
	jobID := disp.Msg.GetJobId()

	// Poll until the worker records the outcome.
	var outcome *aresv1.JobOutcome
	for i := 0; i < 100; i++ {
		got, err := h.GetJob(ctx, connect.NewRequest(&aresv1.GetJobRequest{JobId: jobID}))
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		if got.Msg.GetStatus() == "done" {
			outcome = got.Msg
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if outcome == nil {
		t.Fatal("job never completed")
	}

	// The gate let the in-scope target through and dropped the excluded one.
	if len(outcome.GetAllowed()) != 1 || outcome.GetAllowed()[0].GetHost() != "127.0.0.1" {
		t.Fatalf("allowed = %+v, want [127.0.0.1]", outcome.GetAllowed())
	}
	if len(outcome.GetDenied()) != 1 || outcome.GetDenied()[0].GetTarget().GetHost() != "10.1.2.3" {
		t.Fatalf("denied = %+v, want [10.1.2.3]", outcome.GetDenied())
	}
	if len(outcome.GetResults()) != 1 {
		t.Fatalf("results = %d, want 1 (only the allowed target)", len(outcome.GetResults()))
	}
	if outcome.GetResults()[0].GetData() == nil {
		t.Fatal("result data should round-trip through protobuf Struct")
	}

	// The audit trail must verify.
	audit, err := h.GetAudit(ctx, connect.NewRequest(&aresv1.GetAuditRequest{Id: id}))
	if err != nil {
		t.Fatalf("GetAudit: %v", err)
	}
	if !audit.Msg.GetValid() {
		t.Fatal("audit trail should verify")
	}
	if len(audit.Msg.GetEntries()) == 0 {
		t.Fatal("audit trail should not be empty")
	}
}

// TestOverTheWireGRPC confirms the handler actually serves the gRPC protocol
// over the wire (plaintext HTTP/2 via h2c), using the generated gRPC client.
func TestOverTheWireGRPC(t *testing.T) {
	h := newTestHandler(t)
	path, handler := aresv1connect.NewControlPlaneHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, handler)

	srv := httptest.NewServer(h2c.NewHandler(mux, &http2.Server{}))
	t.Cleanup(srv.Close)

	// An HTTP/2 client that speaks plaintext h2c to the test server.
	httpClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	client := aresv1connect.NewControlPlaneClient(httpClient, srv.URL, connect.WithGRPC())

	resp, err := client.ListModules(context.Background(), connect.NewRequest(&aresv1.ListModulesRequest{}))
	if err != nil {
		t.Fatalf("ListModules over gRPC: %v", err)
	}
	if len(resp.Msg.GetModules()) != 1 || resp.Msg.GetModules()[0] != "echo" {
		t.Fatalf("modules over gRPC = %v, want [echo]", resp.Msg.GetModules())
	}

	// The gate is enforced over the wire too: dispatch before authorize is denied.
	created, err := client.CreateEngagement(context.Background(), connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Wire"}))
	if err != nil {
		t.Fatalf("CreateEngagement over gRPC: %v", err)
	}
	_, err = client.DispatchJob(context.Background(), connect.NewRequest(&aresv1.DispatchJobRequest{
		EngagementId: created.Msg.GetId(), Module: "echo",
		Targets: []*aresv1.Target{{Host: "127.0.0.1"}},
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dispatch before authorize over gRPC: want PermissionDenied, got %v", err)
	}
}

func TestNotFound(t *testing.T) {
	h := newTestHandler(t)
	_, err := h.GetEngagement(context.Background(), connect.NewRequest(&aresv1.GetEngagementRequest{Id: "nope"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

// TestTenantIsolation proves one workspace cannot see or act on another's
// engagement through any by-id RPC, and that listing is scoped per workspace.
func TestTenantIsolation(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	// A separate workspace with one engagement of its own.
	tn, err := h.CreateTenant(ctx, connect.NewRequest(&aresv1.CreateTenantRequest{Name: "Acme"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	acme := tn.Msg.GetId()

	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{
		Name: "Acme app", TenantId: acme,
	}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()
	if created.Msg.GetTenantId() != acme {
		t.Fatalf("engagement tenant = %q, want %q", created.Msg.GetTenantId(), acme)
	}

	// Listing the default workspace must not reveal Acme's engagement.
	def, err := h.ListEngagements(ctx, connect.NewRequest(&aresv1.ListEngagementsRequest{}))
	if err != nil {
		t.Fatalf("ListEngagements(default): %v", err)
	}
	for _, e := range def.Msg.GetEngagements() {
		if e.GetId() == id {
			t.Fatal("default workspace must not list Acme's engagement")
		}
	}
	// Listing Acme's workspace reveals exactly it.
	got, err := h.ListEngagements(ctx, connect.NewRequest(&aresv1.ListEngagementsRequest{TenantId: acme}))
	if err != nil {
		t.Fatalf("ListEngagements(acme): %v", err)
	}
	if len(got.Msg.GetEngagements()) != 1 || got.Msg.GetEngagements()[0].GetId() != id {
		t.Fatalf("Acme list = %+v, want just %s", got.Msg.GetEngagements(), id)
	}

	// Every by-id RPC, called from the default workspace against Acme's id,
	// must come back NotFound — the id leaks nothing across the boundary.
	wantNotFound := func(name string, err error) {
		t.Helper()
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("%s cross-tenant: want NotFound, got %v", name, err)
		}
	}
	_, err = h.GetEngagement(ctx, connect.NewRequest(&aresv1.GetEngagementRequest{Id: id}))
	wantNotFound("GetEngagement", err)
	_, err = h.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{Id: id, InScope: []string{"example.com"}}))
	wantNotFound("SetScope", err)
	_, err = h.Authorize(ctx, connect.NewRequest(&aresv1.AuthorizeRequest{Id: id, Document: "d", ApprovedBy: "a"}))
	wantNotFound("Authorize", err)
	_, err = h.Halt(ctx, connect.NewRequest(&aresv1.HaltRequest{Id: id}))
	wantNotFound("Halt", err)
	_, err = h.DispatchJob(ctx, connect.NewRequest(&aresv1.DispatchJobRequest{EngagementId: id, Module: "echo"}))
	wantNotFound("DispatchJob", err)
	_, err = h.GetAudit(ctx, connect.NewRequest(&aresv1.GetAuditRequest{Id: id}))
	wantNotFound("GetAudit", err)

	// The owning workspace still reaches it.
	if _, err := h.GetEngagement(ctx, connect.NewRequest(&aresv1.GetEngagementRequest{Id: id, TenantId: acme})); err != nil {
		t.Fatalf("GetEngagement from owning workspace: %v", err)
	}
}

func TestPurpleTemplatesScored(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Purple"}))
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	id := created.Msg.GetId()

	// Catalog without an engagement carries no coverage.
	cat, err := h.ListPurpleTemplates(ctx, connect.NewRequest(&aresv1.ListPurpleTemplatesRequest{}))
	if err != nil {
		t.Fatalf("list catalog: %v", err)
	}
	if len(cat.Msg.GetTemplates()) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, tpl := range cat.Msg.GetTemplates() {
		if tpl.GetCoverage() != nil {
			t.Fatalf("catalog template %q carries coverage; should not", tpl.GetId())
		}
	}

	// Record T1190 as detected; log4shell (T1190, T1203, T1105) should score 1/3.
	if _, err := h.SetDetection(ctx, connect.NewRequest(&aresv1.SetDetectionRequest{
		Id: id, Technique: "T1190", Outcome: "detected",
	})); err != nil {
		t.Fatalf("set detection: %v", err)
	}

	scored, err := h.ListPurpleTemplates(ctx, connect.NewRequest(&aresv1.ListPurpleTemplatesRequest{EngagementId: id}))
	if err != nil {
		t.Fatalf("list scored: %v", err)
	}
	var found bool
	for _, tpl := range scored.Msg.GetTemplates() {
		if tpl.GetId() != "log4shell" {
			continue
		}
		found = true
		cov := tpl.GetCoverage()
		if cov == nil || cov.GetTotal() != 3 || cov.GetCovered() != 1 || cov.GetCoveragePercent() != 33 {
			t.Fatalf("log4shell coverage = %+v, want total 3 / covered 1 / 33%%", cov)
		}
	}
	if !found {
		t.Fatal("log4shell missing from scored list")
	}

	detail, err := h.GetPurpleTemplate(ctx, connect.NewRequest(&aresv1.GetPurpleTemplateRequest{
		EngagementId: id, TemplateId: "log4shell",
	}))
	if err != nil {
		t.Fatalf("get template: %v", err)
	}
	var sawDetected bool
	for _, s := range detail.Msg.GetSteps() {
		if s.GetTechnique() == "T1190" {
			if s.GetOutcome() != "detected" {
				t.Fatalf("T1190 step outcome = %q, want detected", s.GetOutcome())
			}
			sawDetected = true
		}
	}
	if !sawDetected {
		t.Fatal("no T1190 step in log4shell detail")
	}

	// Unknown template id is NotFound.
	if _, err := h.GetPurpleTemplate(ctx, connect.NewRequest(&aresv1.GetPurpleTemplateRequest{
		EngagementId: id, TemplateId: "nope",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown template: err=%v, want NotFound", err)
	}
}

func TestGetRiskPicture(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	created, err := h.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: "Risk demo"}))
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	id := created.Msg.GetId()

	// No findings yet: the risk picture must be well-formed and rate "none".
	empty, err := h.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{Id: id}))
	if err != nil {
		t.Fatalf("GetRiskPicture (empty): %v", err)
	}
	if empty.Msg.GetRating() != "none" || len(empty.Msg.GetPaths()) != 0 {
		t.Fatalf("empty engagement should rate none with no paths, got %+v", empty.Msg)
	}

	// Inject a confirmed-RCE and a secret-exposure finding, then correlate.
	h.outcomes.Save(worker.Outcome{Engagement: id, Results: []module.Result{
		{Capability: "log4shellprobe", Kind: "finding", Technique: "T1190", Data: map[string]any{
			"issueKey": "log4shell", "severity": "critical", "title": "Log4Shell confirmed",
		}},
		{Capability: "webcheck", Kind: "finding", Technique: "T1552.001", Data: map[string]any{
			"issueKey": "exposed-env-production", "severity": "high", "title": "Exposed .env.production",
		}},
	}})

	risk, err := h.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{Id: id}))
	if err != nil {
		t.Fatalf("GetRiskPicture: %v", err)
	}
	if risk.Msg.GetRating() != "critical" {
		t.Errorf("rating = %q, want critical", risk.Msg.GetRating())
	}
	if len(risk.Msg.GetPaths()) < 2 {
		t.Fatalf("expected at least two attack paths, got %d", len(risk.Msg.GetPaths()))
	}
	top := risk.Msg.GetPaths()[0]
	if top.GetName() != "Remote code execution" {
		t.Errorf("top path = %q, want Remote code execution", top.GetName())
	}
	if len(top.GetSteps()) == 0 || top.GetOutcome() == "" || top.GetWhy() == "" {
		t.Error("attack path should carry steps, an outcome and a rationale")
	}

	// Tenant isolation: another workspace cannot read this engagement's risk.
	if _, err := h.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{
		Id: id, TenantId: "someone-else",
	})); err == nil {
		t.Error("cross-tenant GetRiskPicture should be refused")
	}
}
