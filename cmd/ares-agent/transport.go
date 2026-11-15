// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package main

import (
	"context"
	"errors"
	"net"
	"runtime"

	"github.com/gsoultan/ares-server/internal/agent"
)

func runtimeGOOS() string   { return runtime.GOOS }
func runtimeGOARCH() string { return runtime.GOARCH }

// primaryIP reports the agent's own primary non-loopback IPv4 address, shown to
// the operator so it is clear which host and segment the agent sits on. It only
// reads local interface addresses; it sends nothing.
func primaryIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// EnrollResult is what the server returns on a successful Enroll: the durable
// agent id, the scoped credential (stored only locally, never logged), the
// engagement binding and the authorized capability allow-list.
type EnrollResult struct {
	AgentID      string   `json:"agentId"`
	Credential   string   `json:"credential"`
	TenantID     string   `json:"tenantId"`
	EngagementID string   `json:"engagementId"`
	Capabilities []string `json:"capabilities"`
}

// Task is one authorized unit of work the server dispatches to the agent. The
// agent runs it only if its capability is on the allow-list, and enforces the
// engagement scope locally before any target is touched.
type Task struct {
	TaskID        string `json:"taskId"`
	Capability    string `json:"capability"`
	ScopeSnapshot []byte `json:"scopeSnapshot"`
	Params        []byte `json:"params"`
}

// Result is the outcome of a task, forwarded to the server's pipeline. It is
// idempotent on TaskID so a store-and-forward retry never double-reports.
type Result struct {
	TaskID  string `json:"taskId"`
	Results []byte `json:"results"`
	Denied  []byte `json:"denied"`
	Error   string `json:"error,omitempty"`
}

// Directive is the server's answer to a heartbeat.
type Directive int

const (
	DirectiveContinue   Directive = iota
	DirectiveStop                 // engagement halted / paused
	DirectiveDeregister           // revoked — tear down and uninstall
)

// Transport is the agent's outbound link to ares-server. It is always
// outbound-initiated over HTTPS/443 and carries the agent credential. The
// concrete implementation is the generated gRPC/Connect AgentService client
// (proto/ares/v1/agent.proto), wired in a later change; this interface keeps the
// skeleton honest about the surface it needs.
type Transport interface {
	Enroll(ctx context.Context, token string, pubKey []byte, host agent.HostFacts) (EnrollResult, error)
	Heartbeat(ctx context.Context) (Directive, []string, error)
	// PullTasks blocks on the server stream and delivers tasks to the channel
	// until the context is cancelled or the link drops.
	PullTasks(ctx context.Context, out chan<- Task) error
	PushResults(ctx context.Context, r Result) error
	Deregister(ctx context.Context, reason string) error
}

// errTransportNotWired is returned by the placeholder transport. Phase 1 is the
// skeleton; the Connect client lands once the proto is generated (scripts/gen.sh)
// and the design is signed off.
var errTransportNotWired = errors.New("agent transport not yet wired (phase-1 skeleton): generate the AgentService Connect client and replace newTransport")

// newTransport builds the outbound transport for a config. It honors the
// explicit proxy when set, otherwise the system/corporate proxy, pins the server
// certificate (or the operator-supplied inspecting CA), and only ever dials out.
//
// Until the Connect client is generated it returns the placeholder below, so the
// binary builds and the lifecycle commands work end to end against a real
// server once the client is dropped in.
func newTransport(cfg config) (Transport, error) {
	return &placeholderTransport{cfg: cfg}, nil
}

type placeholderTransport struct{ cfg config }

func (p *placeholderTransport) Enroll(context.Context, string, []byte, agent.HostFacts) (EnrollResult, error) {
	return EnrollResult{}, errTransportNotWired
}
func (p *placeholderTransport) Heartbeat(context.Context) (Directive, []string, error) {
	return DirectiveContinue, nil, errTransportNotWired
}
func (p *placeholderTransport) PullTasks(context.Context, chan<- Task) error {
	return errTransportNotWired
}
func (p *placeholderTransport) PushResults(context.Context, Result) error {
	return errTransportNotWired
}
func (p *placeholderTransport) Deregister(context.Context, string) error {
	return errTransportNotWired
}
