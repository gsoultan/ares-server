// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Command ares-agent is the Ares agent: a small, transparent component an
// operator deploys inside a target's network or on a host, with the host
// owner's knowledge, to run authorized, inside-the-perimeter checks. It is NOT
// an implant (see ares-design/agent-design.md and agent-prd.md):
//
//   - It installs and runs under its real name, logs everything it does to a
//     local, operator-readable activity log, and does not hide.
//   - It uses no stealth, evasion, persistence tricks or self-defense, and never
//     spreads to another host.
//   - It is bound to one engagement + tenant with a scoped, revocable
//     credential, and stops the moment it is revoked or the engagement is halted.
//   - It reaches ares-server outbound-only over HTTPS/443 (works behind NAT,
//     proxies and tunnels; no inbound port on the target) and forwards every
//     result to the server — nothing of the engagement's data is kept host-only.
//
// This is the phase-1 skeleton: enrollment, the heartbeat/task loop, the
// encrypted store-and-forward outbox and the lifecycle commands. The transport
// is an interface; the concrete gRPC/Connect AgentService client
// (proto/ares/v1/agent.proto) is wired in a later change, and no live testing
// capability runs until the design is signed off.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gsoultan/ares-server/internal/agent"
)

const agentVersion = "0.0.1-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "enroll":
		err = runEnroll(args)
	case "run":
		err = runRun(args)
	case "status":
		err = runStatus(args)
	case "uninstall":
		err = runUninstall(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "ares-agent: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ares-agent: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ares-agent — the Ares authorized testing agent (transparent, not an implant)

Usage:
  ares-agent enroll   --server <url> --key <install-key> [--proxy <url>] [--trust-ca <file>] [--state <dir>]
  ares-agent run      [--state <dir>]
  ares-agent status   [--state <dir>]
  ares-agent uninstall [--state <dir>]

Commands:
  enroll     Redeem a one-time enrollment token and register to an engagement.
  run        Connect outbound, heartbeat, and run authorized tasks (the service).
  status     Print what this agent is: engagement, scope and last check-in.
  uninstall  Deregister (revoke the credential), remove the service and wipe state.

The agent connects outbound only, over HTTPS/443; it opens no inbound port.
Everything it does is written to a local activity log and the engagement audit
trail. It can be stopped, inspected and removed at any time.
`)
}

// config is the agent's local, operator-supplied connectivity configuration. It
// encodes the private-network requirements: outbound-only to an HTTPS endpoint
// that may sit behind a proxy, a tunnel or a CDN front, possibly through a
// TLS-inspecting middlebox.
type config struct {
	// ServerURL is the HTTPS/443 endpoint. It may be a Cloudflare Tunnel / CDN
	// hostname; the agent treats it as an ordinary HTTPS origin.
	ServerURL string
	// Proxy, if set, is an explicit HTTP(S) proxy (with optional credentials in
	// the URL). When empty the agent honors the system/corporate proxy
	// (HTTPS_PROXY / PAC) — it never bypasses a configured egress proxy.
	Proxy string
	// CAFile is an optional trust anchor. The agent pins the real server cert by
	// default; on a network with a TLS-inspecting proxy the operator supplies the
	// inspecting CA here so validation still succeeds.
	CAFile string
	// StateDir holds the enrolled credential, the local activity log and the
	// encrypted store-and-forward outbox.
	StateDir string
}

func defaultStateDir() string {
	if d := os.Getenv("ARES_AGENT_STATE"); d != "" {
		return d
	}
	return "./ares-agent-state"
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	cfg := config{}
	var token string
	fs.StringVar(&cfg.ServerURL, "server", "", "ares-server HTTPS endpoint (may be a tunnel/CDN hostname)")
	fs.StringVar(&token, "key", "", "one-time install key (from the operator)")
	fs.StringVar(&cfg.Proxy, "proxy", "", "explicit HTTP(S) proxy (else the system proxy is honored)")
	fs.StringVar(&cfg.CAFile, "trust-ca", "", "trust anchor for a TLS-inspecting proxy (optional)")
	fs.StringVar(&cfg.StateDir, "state", defaultStateDir(), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.ServerURL == "" || token == "" {
		return errors.New("enroll requires --server and --key")
	}

	st, err := openState(cfg)
	if err != nil {
		return err
	}
	if st.Enrolled() {
		return errors.New("this agent is already enrolled; run uninstall first to re-enroll")
	}

	host := collectHostFacts()
	transport, err := newTransport(cfg, st.Credential)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := transport.Enroll(ctx, token, st.PublicKey(), host)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := st.SaveEnrollment(res); err != nil {
		return err
	}
	st.Log("enrolled to engagement %s (tenant %s); capabilities: %v", res.EngagementID, res.TenantID, res.Capabilities)
	fmt.Printf("Enrolled. Agent %s is bound to engagement %s.\n", res.AgentID, res.EngagementID)
	fmt.Println("Install the service to start it, or run `ares-agent run` in the foreground.")
	return nil
}

func runRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg := config{}
	fs.StringVar(&cfg.StateDir, "state", defaultStateDir(), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openState(cfg)
	if err != nil {
		return err
	}
	if !st.Enrolled() {
		return errors.New("not enrolled; run `ares-agent enroll` first")
	}
	cfg = st.Config()

	transport, err := newTransport(cfg, st.Credential)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st.Log("agent run: connecting outbound to %s", cfg.ServerURL)
	loop := &agentLoop{state: st, transport: transport}
	return loop.Run(ctx)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfg := config{}
	fs.StringVar(&cfg.StateDir, "state", defaultStateDir(), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openState(cfg)
	if err != nil {
		return err
	}
	if !st.Enrolled() {
		fmt.Println("ares-agent: not enrolled.")
		return nil
	}
	e := st.Enrollment()
	fmt.Printf("Ares agent %s\n", agentVersion)
	fmt.Printf("  agent id:     %s\n", e.AgentID)
	fmt.Printf("  engagement:   %s (tenant %s)\n", e.EngagementID, e.TenantID)
	fmt.Printf("  capabilities: %v\n", e.Capabilities)
	fmt.Printf("  server:       %s (outbound only)\n", st.Config().ServerURL)
	fmt.Printf("  last check-in: %s\n", st.LastSeen())
	fmt.Printf("  outbox:       %d result(s) pending delivery\n", st.OutboxLen())
	fmt.Println("  This agent is visible, logged, scope-bound and removable (ares-agent uninstall).")
	return nil
}

func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	cfg := config{}
	fs.StringVar(&cfg.StateDir, "state", defaultStateDir(), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openState(cfg)
	if err != nil {
		return err
	}
	if st.Enrolled() {
		// Best-effort deregister so the server revokes the credential and audits
		// the teardown; even if the server is unreachable, local state is wiped.
		if transport, terr := newTransport(st.Config(), st.Credential); terr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = transport.Deregister(ctx, "uninstall")
			cancel()
		}
		st.Log("uninstall: deregistered and wiping local state")
	}
	if err := st.Wipe(); err != nil {
		return err
	}
	fmt.Println("Uninstalled. Credential revoked, service removed, local state wiped. Nothing left behind.")
	return nil
}

// collectHostFacts gathers the non-identifying host context shown on the
// operator's Agents view. The agent is transparent about what it is and where.
func collectHostFacts() agent.HostFacts {
	hostname, _ := os.Hostname()
	return agent.HostFacts{
		Hostname:     hostname,
		OS:           runtimeGOOS(),
		Arch:         runtimeGOARCH(),
		AgentVersion: agentVersion,
		IP:           primaryIP(),
	}
}
