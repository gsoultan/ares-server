// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"time"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/agent"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
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

// newTransport builds the outbound Connect transport for a config. It is always
// outbound-initiated over HTTPS, honors the explicit proxy when set and
// otherwise the system/corporate proxy, and trusts the operator-supplied CA when
// a TLS-inspecting middlebox is in the path. cred returns the agent's current
// credential (empty during enrollment); it is sent as a bearer header on every
// authenticated call.
func newTransport(cfg config, cred func() string) (Transport, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("no server URL configured")
	}
	if cred == nil {
		cred = func() string { return "" }
	}
	hc, err := httpClient(cfg)
	if err != nil {
		return nil, err
	}
	client := aresv1connect.NewAgentServiceClient(hc, cfg.ServerURL)
	return &connectTransport{client: client, cred: cred}, nil
}

// httpClient builds the outbound HTTP client: proxy-aware (explicit or system),
// with an optional extra trust anchor for a TLS-inspecting proxy. It never opens
// an inbound listener.
func httpClient(cfg config) (*http.Client, error) {
	proxy := http.ProxyFromEnvironment
	if cfg.Proxy != "" {
		u, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid --proxy: %w", err)
		}
		proxy = http.ProxyURL(u)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read --trust-ca: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("--trust-ca: no certificates found in file")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr}, nil
}

// connectTransport is the concrete AgentService client.
type connectTransport struct {
	client aresv1connect.AgentServiceClient
	cred   func() string
}

func (c *connectTransport) auth(h http.Header) {
	if v := c.cred(); v != "" {
		h.Set("Authorization", "Bearer "+v)
	}
}

func (c *connectTransport) Enroll(ctx context.Context, token string, pubKey []byte, host agent.HostFacts) (EnrollResult, error) {
	req := connect.NewRequest(&aresv1.EnrollRequest{
		EnrollmentToken: token,
		PublicKey:       pubKey,
		Host: &aresv1.HostFacts{
			Hostname: host.Hostname, Os: host.OS, Arch: host.Arch,
			AgentVersion: host.AgentVersion, Ip: host.IP, SegmentCidrs: host.SegmentCIDRs,
		},
	})
	res, err := c.client.Enroll(ctx, req)
	if err != nil {
		return EnrollResult{}, err
	}
	if !res.Msg.GetOk() {
		return EnrollResult{}, errors.New("enrollment refused by server")
	}
	return EnrollResult{
		AgentID:      res.Msg.GetAgentId(),
		Credential:   res.Msg.GetCredential(),
		TenantID:     res.Msg.GetTenantId(),
		EngagementID: res.Msg.GetEngagementId(),
		Capabilities: res.Msg.GetCapabilities(),
	}, nil
}

func (c *connectTransport) Heartbeat(ctx context.Context) (Directive, []string, error) {
	req := connect.NewRequest(&aresv1.HeartbeatRequest{AgentVersion: agentVersion})
	c.auth(req.Header())
	res, err := c.client.Heartbeat(ctx, req)
	if err != nil {
		return DirectiveContinue, nil, err
	}
	var dir Directive
	switch res.Msg.GetDirective() {
	case aresv1.AgentDirective_AGENT_DIRECTIVE_STOP:
		dir = DirectiveStop
	case aresv1.AgentDirective_AGENT_DIRECTIVE_DEREGISTER:
		dir = DirectiveDeregister
	default:
		dir = DirectiveContinue
	}
	return dir, res.Msg.GetCapabilities(), nil
}

func (c *connectTransport) PullTasks(ctx context.Context, out chan<- Task) error {
	req := connect.NewRequest(&aresv1.PullTasksRequest{})
	c.auth(req.Header())
	stream, err := c.client.PullTasks(ctx, req)
	if err != nil {
		return err
	}
	for stream.Receive() {
		m := stream.Msg()
		select {
		case out <- Task{
			TaskID:        m.GetTaskId(),
			Capability:    m.GetCapability(),
			ScopeSnapshot: m.GetScopeSnapshot(),
			Params:        m.GetParams(),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return stream.Err()
}

func (c *connectTransport) PushResults(ctx context.Context, r Result) error {
	req := connect.NewRequest(&aresv1.PushResultsRequest{
		TaskId: r.TaskID, Results: r.Results, Denied: r.Denied, Error: r.Error,
	})
	c.auth(req.Header())
	_, err := c.client.PushResults(ctx, req)
	return err
}

func (c *connectTransport) Deregister(ctx context.Context, reason string) error {
	req := connect.NewRequest(&aresv1.DeregisterRequest{Reason: reason})
	c.auth(req.Header())
	_, err := c.client.Deregister(ctx, req)
	return err
}
