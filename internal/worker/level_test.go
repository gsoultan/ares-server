// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
)

// paramMod is a configurable fake that records the params it was given, and
// whose "write" param raises it to active confirmation like the SQL-injection
// write proof.
type paramMod struct {
	name string
	mu   *sync.Mutex
	seen *[]map[string]any
}

func (p paramMod) Name() string { return p.name }
func (p paramMod) Run(_ context.Context, _ module.Scope, ts []module.Target, out chan<- module.Result) error {
	for _, t := range ts {
		out <- module.Result{Capability: p.name, Kind: "info", Target: t}
	}
	return nil
}
func (p paramMod) WithParams(raw json.RawMessage) (module.Module, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	p.mu.Lock()
	*p.seen = append(*p.seen, m)
	p.mu.Unlock()
	return p, nil
}
func (paramMod) LevelFor(raw json.RawMessage) (module.ConsentLevel, error) {
	var m struct {
		Write bool `json:"write"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return 0, err
		}
	}
	if m.Write {
		return module.LevelActiveConfirmation, nil
	}
	return module.LevelSafeProof, nil
}

func levelSetup(t *testing.T, name string) (*Processor, *engagement.Engagement, *[]map[string]any) {
	t.Helper()
	seen := &[]map[string]any{}
	reg := module.NewRegistry()
	if err := reg.Register(paramMod{name: name, mu: &sync.Mutex{}, seen: seen}); err != nil {
		t.Fatal(err)
	}
	store := engagement.NewMemStore()
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	if err := eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatal(err)
	}
	return NewProcessor(reg, store), eng, seen
}

// A param that opts into a write is gated at the write's level, not the
// module's default: the job is refused at safe proof and runs once the
// engagement allows active confirmation.
func TestParamOptInGatedAtItsLevel(t *testing.T) {
	proc, eng, _ := levelSetup(t, "writeprobe")
	job := func(id, params string) Outcome {
		return proc.Process(context.Background(), queue.Job{
			ID: id, EngagementID: eng.ID, Module: "writeprobe", Actor: "op",
			Targets: []module.Target{{Host: "example.com"}}, Params: json.RawMessage(params),
		})
	}
	if out := job("j1", `{"write":false}`); out.Error != "" {
		t.Fatalf("the safe variant should run: %v", out.Error)
	}
	if out := job("j2", `{"write":true}`); out.Error == "" || len(out.Results) != 0 {
		t.Fatalf("an opt-in write must be refused at safe proof: %+v", out)
	}
	if err := eng.SetTestLevel(module.LevelActiveConfirmation, "lead"); err != nil {
		t.Fatal(err)
	}
	if out := job("j3", `{"write":true}`); out.Error != "" || len(out.Results) != 1 {
		t.Fatalf("an opt-in write should run once level 2 is allowed: %+v", out)
	}
}

// The adaptive loop always runs at the engagement's stored level: whatever
// maxLevel the job carried is replaced, so a client cannot raise it.
func TestAssessGetsTheEngagementLevel(t *testing.T) {
	proc, eng, seen := levelSetup(t, "assess")
	run := func(id, params string) map[string]any {
		out := proc.Process(context.Background(), queue.Job{
			ID: id, EngagementID: eng.ID, Module: "assess", Actor: "op",
			Targets: []module.Target{{Host: "example.com"}}, Params: json.RawMessage(params),
		})
		if out.Error != "" {
			t.Fatalf("assess refused: %v", out.Error)
		}
		return (*seen)[len(*seen)-1]
	}
	if got := run("a1", ``); got["maxLevel"] != float64(1) {
		t.Fatalf("default engagement: maxLevel = %v, want 1", got["maxLevel"])
	}
	if got := run("a2", `{"maxLevel":3,"maxTasks":5}`); got["maxLevel"] != float64(1) || got["maxTasks"] != float64(5) {
		t.Fatalf("a client-sent maxLevel must be replaced and other params kept: %v", got)
	}
	if err := eng.SetTestLevel(module.LevelActiveConfirmation, "lead"); err != nil {
		t.Fatal(err)
	}
	if got := run("a3", `{"maxLevel":1}`); got["maxLevel"] != float64(2) {
		t.Fatalf("maxLevel = %v, want the engagement's 2", got["maxLevel"])
	}
}
