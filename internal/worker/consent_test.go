// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
)

// intrusiveSetup registers noop described as an intrusive (level 3) test, so the
// consent gate can be exercised without generating real load.
func intrusiveSetup(t *testing.T) (*Processor, *engagement.Engagement) {
	t.Helper()
	reg := module.NewRegistry()
	if err := reg.Register(engineModule(t, "noop")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.SetCapability("noop", module.Capability{
		Level: module.LevelIntrusive, Surface: []module.SurfaceKind{module.SurfaceWeb},
		Recovery: "nothing to undo",
	}); err != nil {
		t.Fatalf("describe: %v", err)
	}
	store := engagement.NewMemStore()
	eng := mustCreate(t, store)
	_ = eng.Scope.AddInScope("example.com")
	if err := eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return NewProcessor(reg, store), eng
}

func TestIntrusiveRefusedAtSafeProof(t *testing.T) {
	proc, eng := intrusiveSetup(t)
	out := proc.Process(context.Background(), queue.Job{
		ID: "j1", EngagementID: eng.ID, Module: "noop", Actor: "op",
		Targets: []module.Target{{Host: "example.com"}},
	})
	if out.Error == "" || len(out.Results) != 0 {
		t.Fatalf("an intrusive test must not run at the default intensity: %+v", out)
	}
}

func TestIntrusiveNeedsApprovalPerRun(t *testing.T) {
	proc, eng := intrusiveSetup(t)
	if err := eng.SetTestLevel(module.LevelIntrusive, "lead"); err != nil {
		t.Fatalf("set level: %v", err)
	}
	target := module.Target{Host: "example.com"}
	job := func(id string) Outcome {
		return proc.Process(context.Background(), queue.Job{
			ID: id, EngagementID: eng.ID, Module: "noop", Actor: "op",
			Targets: []module.Target{target},
		})
	}

	if out := job("j1"); out.Error == "" {
		t.Fatal("level 3 without an approval must be refused")
	}

	a, err := eng.Approve("noop", target, "Rina Halim", "signed change request", "")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	out := job("j2")
	if out.Error != "" || len(out.Results) != 1 {
		t.Fatalf("an approved run should go ahead: %+v", out)
	}
	c, ok := out.Results[0].Data["consent"].(map[string]any)
	if !ok || c["level"] != "intrusive" || c["who"] != "Rina Halim" || c["approvalId"] != a.ID {
		t.Fatalf("the result must carry who approved it, got %#v", out.Results[0].Data["consent"])
	}

	// The approval is spent: a second run needs a second approval.
	if out := job("j3"); out.Error == "" {
		t.Fatal("a used approval must not allow another run")
	}
	used := eng.ApprovalsForJob("j2")
	if len(used) != 1 || used[0].ID != a.ID {
		t.Fatalf("the run should have used the approval, got %+v", used)
	}
	if err := eng.Audit.Verify(); err != nil {
		t.Fatalf("audit chain must stay valid: %v", err)
	}
}

func TestApprovalOutOfScopeRefused(t *testing.T) {
	_, eng := intrusiveSetup(t)
	_ = eng.SetTestLevel(module.LevelIntrusive, "lead")
	if _, err := eng.Approve("noop", module.Target{Host: "elsewhere.org"}, "Rina", "", ""); err == nil {
		t.Fatal("an approval for an out-of-scope target must be refused")
	}
}

func TestLoweringIntensityWithdrawsApprovals(t *testing.T) {
	_, eng := intrusiveSetup(t)
	_ = eng.SetTestLevel(module.LevelIntrusive, "lead")
	if _, err := eng.Approve("noop", module.Target{Host: "example.com"}, "Rina", "", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := eng.SetTestLevel(module.LevelSafeProof, "lead"); err != nil {
		t.Fatalf("lower: %v", err)
	}
	for _, a := range eng.ConsentSnapshot().Approvals {
		if a.Usable() {
			t.Fatal("lowering the intensity must withdraw unused approvals")
		}
	}
	if err := eng.SetTestLevel(module.ConsentLevel(4), "lead"); err == nil {
		t.Fatal("there is no level above intrusive")
	}
}
