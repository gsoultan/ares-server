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
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares-server/internal/engagement"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

// AgentServer implements the agent-facing AgentService. It is served on its own
// endpoint, behind the agent-credential interceptor, separate from the operator
// ControlPlane. Every call is outbound-initiated by an enrolled agent.
//
// Credential: the agent presents its scoped credential as an Authorization
// bearer header, authenticated at the application layer (not transport mTLS).
// This is deliberate: the hard connectivity requirement is that the agent runs
// behind NAT and egresses over HTTPS/443 through corporate proxies, a Cloudflare
// Tunnel / CDN front, and TLS-inspecting middleboxes — all of which terminate
// TLS at the edge, which breaks true client-certificate mTLS to the origin. An
// app-layer credential travels through those intact. The credential is a 256-bit
// random secret, stored server-side only as a SHA-256 hash and bound to the
// agent's {tenant, engagement}; it is revoked immediately on removal.
type AgentServer struct {
	agents   *agent.Registry
	store    engagement.Store
	outcomes worker.OutcomeStore
}

var _ aresv1connect.AgentServiceHandler = (*AgentServer)(nil)

// NewAgentServer builds the agent-facing service over the registry. outcomes may
// be nil (then pushed results are accepted but not recorded).
func NewAgentServer(agents *agent.Registry, store engagement.Store, outcomes worker.OutcomeStore) *AgentServer {
	return &AgentServer{agents: agents, store: store, outcomes: outcomes}
}

// Enroll redeems a one-time install key and registers the agent. It is the only
// public AgentService call — it authenticates from the key in its body, not a
// credential. The raw credential is returned once.
func (s *AgentServer) Enroll(_ context.Context, req *connect.Request[aresv1.EnrollRequest]) (*connect.Response[aresv1.EnrollResponse], error) {
	host := hostFactsFromProto(req.Msg.GetHost())
	a, cred, err := s.agents.Enroll(req.Msg.GetEnrollmentToken(), req.Msg.GetPublicKey(), host)
	if err != nil {
		// Coarse, credential-free error — reveal nothing about which keys exist.
		return connect.NewResponse(&aresv1.EnrollResponse{Ok: false, Error: "enrollment failed"}),
			nil
	}
	if eng, ok := s.store.Get(a.EngagementID); ok {
		eng.Audit.Append(a.ID, "agent.enroll", a.Host.Hostname, "agent enrolled")
		_ = s.store.Save(eng)
	}
	return connect.NewResponse(&aresv1.EnrollResponse{
		Ok:           true,
		AgentId:      a.ID,
		Credential:   cred,
		TenantId:     a.TenantID,
		EngagementId: a.EngagementID,
		Capabilities: a.Capabilities,
	}), nil
}

// Heartbeat marks the agent seen and returns its directive (continue / stop /
// deregister) plus its current capability allow-list.
func (s *AgentServer) Heartbeat(ctx context.Context, _ *connect.Request[aresv1.HeartbeatRequest]) (*connect.Response[aresv1.HeartbeatResponse], error) {
	a, err := agentFromContext(ctx)
	if err != nil {
		return nil, err
	}
	keep, err := s.agents.Heartbeat(a.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unknown agent"))
	}
	dir := aresv1.AgentDirective_AGENT_DIRECTIVE_CONTINUE
	if !keep {
		// Distinguish a revoked agent (tear down) from a paused engagement (hold).
		if cur, ok := s.agents.Get(a.ID); ok && cur.State != agent.StateActive {
			dir = aresv1.AgentDirective_AGENT_DIRECTIVE_DEREGISTER
		} else {
			dir = aresv1.AgentDirective_AGENT_DIRECTIVE_STOP
		}
	}
	return connect.NewResponse(&aresv1.HeartbeatResponse{
		Directive:    dir,
		Capabilities: a.Capabilities,
	}), nil
}

// PullTasks streams the tasks an operator has dispatched for this agent. The
// agent opens it outbound; the server never dials in. It delivers any queued
// tasks, then polls while the stream stays open, and returns when the agent
// disconnects.
func (s *AgentServer) PullTasks(ctx context.Context, _ *connect.Request[aresv1.PullTasksRequest], stream *connect.ServerStream[aresv1.AgentTask]) error {
	a, err := agentFromContext(ctx)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for _, t := range s.agents.DrainTasks(a.ID) {
			if err := stream.Send(&aresv1.AgentTask{
				TaskId:        t.ID,
				Capability:    t.Module,
				ScopeSnapshot: t.ScopeSnapshot,
				Params:        t.Params,
			}); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// PushResults forwards an agent's results into the same outcome/findings pipeline
// as server-run jobs, attributed to the agent, then clears its "running a check"
// status. Idempotent on task id. Results carry the module.Result values the agent
// produced; denied carries targets its local gate refused, for the audit trail.
func (s *AgentServer) PushResults(ctx context.Context, req *connect.Request[aresv1.PushResultsRequest]) (*connect.Response[aresv1.PushResultsResponse], error) {
	a, err := agentFromContext(ctx)
	if err != nil {
		return nil, err
	}
	s.agents.SetCurrentCapability(a.ID, "")

	var results []module.Result
	if raw := req.Msg.GetResults(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &results); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid results: %w", err))
		}
	}
	var denied []worker.Denial
	if raw := req.Msg.GetDenied(); len(raw) > 0 {
		_ = json.Unmarshal(raw, &denied)
	}

	moduleName := ""
	if len(results) > 0 {
		moduleName = results[0].Capability
	}
	if s.outcomes != nil {
		now := time.Now()
		s.outcomes.Save(worker.Outcome{
			JobID:      req.Msg.GetTaskId(),
			Engagement: a.EngagementID,
			Module:     moduleName,
			Results:    results,
			Denied:     denied,
			Error:      req.Msg.GetError(),
			StartedAt:  now,
			FinishedAt: now,
		})
	}
	if eng, ok := s.store.Get(a.EngagementID); ok {
		eng.Audit.Append(a.ID, "agent.results", req.Msg.GetTaskId(),
			fmt.Sprintf("%d result(s)", len(results)))
		_ = s.store.Save(eng)
	}
	return connect.NewResponse(&aresv1.PushResultsResponse{Ok: true, Accepted: true}), nil
}

// Deregister revokes the agent; it then self-uninstalls. Findings already sent
// are kept.
func (s *AgentServer) Deregister(ctx context.Context, req *connect.Request[aresv1.DeregisterRequest]) (*connect.Response[aresv1.DeregisterResponse], error) {
	a, err := agentFromContext(ctx)
	if err != nil {
		return nil, err
	}
	_ = s.agents.Revoke(a.ID)
	if eng, ok := s.store.Get(a.EngagementID); ok {
		eng.Audit.Append(a.ID, "agent.deregister", req.Msg.GetReason(), "agent deregistered")
		_ = s.store.Save(eng)
	}
	return connect.NewResponse(&aresv1.DeregisterResponse{Ok: true}), nil
}

func hostFactsFromProto(h *aresv1.HostFacts) agent.HostFacts {
	if h == nil {
		return agent.HostFacts{}
	}
	return agent.HostFacts{
		Hostname:     h.GetHostname(),
		OS:           h.GetOs(),
		Arch:         h.GetArch(),
		AgentVersion: h.GetAgentVersion(),
		IP:           h.GetIp(),
		SegmentCIDRs: h.GetSegmentCidrs(),
	}
}

// --- agent credential interceptor ------------------------------------------

type agentCtxKey struct{}

func agentFromContext(ctx context.Context) (*agent.Agent, error) {
	a, ok := ctx.Value(agentCtxKey{}).(*agent.Agent)
	if !ok || a == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("agent credential required"))
	}
	return a, nil
}

// agentPublicProcedures never require a credential: Enroll authenticates from the
// install key in its body.
var agentPublicProcedures = map[string]bool{"Enroll": true}

// AgentCredentialInterceptor authenticates the agent credential (an Authorization
// bearer header) on every AgentService call except Enroll, and binds the agent
// into the context so a handler can only ever act as its own {tenant,
// engagement}.
type AgentCredentialInterceptor struct {
	agents *agent.Registry
}

// NewAgentCredentialInterceptor builds the interceptor over the registry.
func NewAgentCredentialInterceptor(agents *agent.Registry) *AgentCredentialInterceptor {
	return &AgentCredentialInterceptor{agents: agents}
}

func procedureName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		return full[i+1:]
	}
	return full
}

// WrapUnary implements connect.Interceptor.
func (i *AgentCredentialInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if agentPublicProcedures[procedureName(req.Spec().Procedure)] {
			return next(ctx, req)
		}
		a, err := i.authenticate(req.Header().Get("Authorization"))
		if err != nil {
			return nil, err
		}
		return next(context.WithValue(ctx, agentCtxKey{}, a), req)
	}
}

// WrapStreamingClient implements connect.Interceptor (unused on the server).
func (i *AgentCredentialInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler authenticates streaming calls (PullTasks).
func (i *AgentCredentialInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if agentPublicProcedures[procedureName(conn.Spec().Procedure)] {
			return next(ctx, conn)
		}
		a, err := i.authenticate(conn.RequestHeader().Get("Authorization"))
		if err != nil {
			return err
		}
		return next(context.WithValue(ctx, agentCtxKey{}, a), conn)
	}
}

func (i *AgentCredentialInterceptor) authenticate(header string) (*agent.Agent, error) {
	// Accept "Bearer <cred>" or a bare credential; TrimPrefix is a no-op when the
	// prefix is absent.
	cred := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if cred == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("agent credential required"))
	}
	a, err := i.agents.Authenticate(cred)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid agent credential"))
	}
	return a, nil
}
