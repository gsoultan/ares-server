// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares/engine"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/scope"
)

// capabilityRunner runs engine modules on the agent — the same modules the
// server runs, so there is one codebase, not two. It re-enforces the engagement
// scope locally: it rebuilds the scope the server sent, filters every target
// through it (the agent-side gate), and then runs the module WITH that scope as
// the gate, so the module re-checks each target too. That is the same double
// barrier the server's worker provides.
type capabilityRunner struct {
	reg    *module.Registry
	native nativeConfig
}

// newRunner builds the engine registry inside the agent. Canary options are
// nil: the inert internal-recon capabilities do not use the out-of-band
// collaborator.
func newRunner(native ...nativeConfig) (*capabilityRunner, error) {
	reg, err := engine.New(engine.Options{})
	if err != nil {
		return nil, err
	}
	r := &capabilityRunner{reg: reg}
	if len(native) > 0 {
		r.native = native[0]
	}
	return r, nil
}

// taskParams mirrors the server's agentTaskParams JSON payload.
type taskParams struct {
	Targets []module.Target `json:"targets"`
}

// denial mirrors the server's worker.Denial JSON so denied targets round-trip
// into the audit trail.
type denial struct {
	Target module.Target `json:"target"`
	Reason string        `json:"reason"`
}

// Run executes one task and returns the Result to forward. Any failure is
// returned in the Result's Error so it still reaches the server (and the agent
// never silently drops work).
func (r *capabilityRunner) Run(ctx context.Context, t Task) Result {
	fail := func(err error) Result { return Result{TaskID: t.TaskID, Error: err.Error()} }

	// The module must be one the agent is allowed to run. The server already
	// checked the allow-list; the agent checks the module is dispatchable too.
	if agent.GroupOf(t.Capability) == "" {
		return fail(fmt.Errorf("module %q is not dispatchable to an agent", t.Capability))
	}
	if agent.IsAgentNative(t.Capability) {
		return r.runNative(ctx, t)
	}
	mod, ok := r.reg.Get(t.Capability)
	if !ok {
		return fail(fmt.Errorf("unknown module %q", t.Capability))
	}

	// Rebuild the engagement scope the server sent — this is the gate.
	var snap scope.Snapshot
	if err := json.Unmarshal(t.ScopeSnapshot, &snap); err != nil {
		return fail(fmt.Errorf("scope snapshot: %w", err))
	}
	sc, err := scope.Restore(snap)
	if err != nil {
		return fail(fmt.Errorf("restore scope: %w", err))
	}

	var params taskParams
	if len(t.Params) > 0 {
		if err := json.Unmarshal(t.Params, &params); err != nil {
			return fail(fmt.Errorf("task params: %w", err))
		}
	}

	// Agent-side gate: only targets the scope permits proceed; the rest are
	// recorded as denials for the audit trail (barrier one).
	now := time.Now()
	allowed := make([]module.Target, 0, len(params.Targets))
	var denied []denial
	for _, tgt := range params.Targets {
		if ok, reason := sc.AllowAt(tgt, now); ok {
			allowed = append(allowed, tgt)
		} else {
			denied = append(denied, denial{Target: tgt, Reason: reason})
		}
	}

	// Run the module WITH the scope as its gate, so it re-checks every target
	// (barrier two). The module owns no channel; we own and drain it.
	out := make(chan module.Result, 32)
	runErr := make(chan error, 1)
	go func() { runErr <- mod.Run(ctx, sc, allowed, out); close(out) }()

	var results []module.Result
	for res := range out {
		results = append(results, res)
	}
	resultErr := <-runErr

	res := Result{TaskID: t.TaskID}
	if rb, err := json.Marshal(results); err == nil {
		res.Results = rb
	}
	if len(denied) > 0 {
		if db, err := json.Marshal(denied); err == nil {
			res.Denied = db
		}
	}
	if resultErr != nil {
		res.Error = resultErr.Error()
	}
	return res
}
