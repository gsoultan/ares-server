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

	"github.com/gsoultan/ares-server/internal/egresscheck"
	"github.com/gsoultan/ares-server/internal/hostposture"
	"github.com/gsoultan/ares/module"
)

// nativeConfig is the agent's install-time configuration for the
// agent-native capabilities. The egress destinations come only from here.
type nativeConfig struct {
	Egress egresscheck.Config
}

// egressParams is the egresscheck task payload: the tokens the server minted.
type egressParams struct {
	Egress []egresscheck.Token `json:"egress"`
}

// runNative runs an agent-native capability. Neither takes a target: both
// act on this host only, so the scope gate is not consulted for targets, but
// the task still needed the server-side allow-list and engagement checks.
func (r *capabilityRunner) runNative(ctx context.Context, t Task) Result {
	res := Result{TaskID: t.TaskID}
	var results []module.Result
	switch t.Capability {
	case "hostposture":
		rep := hostposture.New().Collect(ctx)
		results = append(results, module.Result{
			Capability: "hostposture", Kind: "info",
			Data: map[string]any{
				"title": "Host posture collected", "os": rep.OS, "items": rep.Items,
				"skipped": rep.Skipped, "truncated": rep.Truncated,
				"description": fmt.Sprintf("Read-only collection: %d item(s), %d skipped.", len(rep.Items), len(rep.Skipped)),
			},
		})
	case "egresscheck":
		var p egressParams
		if len(t.Params) > 0 {
			if err := json.Unmarshal(t.Params, &p); err != nil {
				res.Error = "task params: " + err.Error()
				return res
			}
		}
		outs, err := egresscheck.New(r.native.Egress).Send(ctx, p.Egress)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		results = append(results, module.Result{
			Capability: "egresscheck", Kind: "info",
			Data: map[string]any{
				"title": "Egress canary requests sent", "outcomes": outs,
				"description": "One benign request per channel to the Ares canary, carrying only the token. The server's egressproof check reads which arrived.",
			},
		})
	default:
		res.Error = fmt.Sprintf("module %q is not agent-native", t.Capability)
		return res
	}
	if b, err := json.Marshal(results); err == nil {
		res.Results = b
	}
	return res
}
