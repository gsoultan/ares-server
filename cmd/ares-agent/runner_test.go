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
	"testing"

	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/scope"
)

// TestRunnerEnforcesScopeLocally verifies the agent-side barrier: a target the
// engagement scope does not permit is never handed to the module — it is
// recorded as a denial — without any network work.
func TestRunnerEnforcesScopeLocally(t *testing.T) {
	r, err := newRunner()
	if err != nil {
		t.Fatalf("newRunner: %v", err)
	}

	// Scope admits only 127.0.0.1; the task targets a different, out-of-scope IP.
	snap := scope.Snapshot{InScope: []string{"127.0.0.1"}}
	sb, _ := json.Marshal(snap)
	params, _ := json.Marshal(taskParams{Targets: []module.Target{{Host: "203.0.113.9"}}})

	res := r.Run(context.Background(), Task{
		TaskID:        "t1",
		Capability:    "recon", // a real discovery module, but it gets no targets
		ScopeSnapshot: sb,
		Params:        params,
	})

	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	var denied []denial
	if err := json.Unmarshal(res.Denied, &denied); err != nil {
		t.Fatalf("denied not JSON: %v", err)
	}
	if len(denied) != 1 || denied[0].Target.Host != "203.0.113.9" {
		t.Fatalf("out-of-scope target should be denied locally, got %+v", denied)
	}
}

func TestRunnerRejectsNonDispatchableModule(t *testing.T) {
	r, err := newRunner()
	if err != nil {
		t.Fatalf("newRunner: %v", err)
	}
	res := r.Run(context.Background(), Task{TaskID: "t2", Capability: "apkscan"})
	if res.Error == "" {
		t.Fatal("a module outside the agent capability map must be refused")
	}
}

func TestRunnerDispatchesAgentNative(t *testing.T) {
	r, err := newRunner()
	if err != nil {
		t.Fatalf("newRunner: %v", err)
	}
	// egresscheck without a configured canary refuses, rather than sending.
	res := r.Run(context.Background(), Task{TaskID: "n1", Capability: "egresscheck"})
	if res.Error == "" {
		t.Fatal("egresscheck with no canary configured must refuse")
	}
	// persistcollect runs locally and returns one info result.
	res = r.Run(context.Background(), Task{TaskID: "n2", Capability: "persistcollect"})
	if res.Error != "" {
		t.Fatalf("persistcollect: %s", res.Error)
	}
	var results []module.Result
	if err := json.Unmarshal(res.Results, &results); err != nil || len(results) != 1 || results[0].Capability != "persistcollect" {
		t.Fatalf("persistcollect results = %s (%v)", res.Results, err)
	}
}
