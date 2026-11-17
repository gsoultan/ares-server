// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package technique

import (
	"encoding/json"
	"testing"

	"github.com/gsoultan/ares/engine"
	"github.com/gsoultan/ares/module"
)

// With the real engine, every level-2/3 proof is gated at the level the
// doctrine gives it, including an opt-in param that turns on a write.
func TestEngineProofLevels(t *testing.T) {
	reg, err := engine.New(engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, params string
		want         module.ConsentLevel
	}{
		{"webcheck", ``, module.LevelSafeProof},
		{"sqliprobe", ``, module.LevelSafeProof},
		{"sqliprobe", `{"enableWriteProof":true}`, module.LevelActiveConfirmation},
		{"uploadmarker", `{"enableUploadProof":true}`, module.LevelActiveConfirmation},
		{"loadresilience", `{"enable":true,"maxConcurrency":10}`, module.LevelIntrusive},
	} {
		got, err := LevelForJob(reg, c.name, json.RawMessage(c.params))
		if err != nil || got != c.want {
			t.Errorf("LevelForJob(%s, %s) = %v, %v; want %v", c.name, c.params, got, err, c.want)
		}
	}
	if _, err := LevelForJob(reg, "sqliprobe", json.RawMessage(`{`)); err == nil {
		t.Error("unreadable params must refuse the job, not fall back to safe proof")
	}
	// Every test above safe proof says how it is undone, and the ones this
	// package describes also give the approver plain words for what they do.
	names := map[string]bool{}
	for _, tq := range AboveSafeProof(reg) {
		names[tq.Module] = true
		if tq.Recovery == "" {
			t.Errorf("%s: no recovery %+v", tq.Module, tq)
		}
		if _, ours := extra[tq.Module]; ours && tq.Action == "" {
			t.Errorf("%s: missing description %+v", tq.Module, tq)
		}
	}
	if !names["uploadmarker"] || !names["loadresilience"] {
		t.Errorf("above safe proof = %v", names)
	}
}

func TestWithEngagementLevel(t *testing.T) {
	got, err := WithEngagementLevel("assess", json.RawMessage(`{"maxLevel":3,"maxTasks":5}`), module.LevelActiveConfirmation)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(got, &m)
	if m["maxLevel"] != float64(2) || m["maxTasks"] != float64(5) {
		t.Fatalf("params = %s", got)
	}
	if got, _ := WithEngagementLevel("webcheck", json.RawMessage(`{"a":1}`), module.LevelIntrusive); string(got) != `{"a":1}` {
		t.Fatalf("other modules' params must be untouched: %s", got)
	}
	if _, err := WithEngagementLevel("assess", json.RawMessage(`[`), module.LevelSafeProof); err == nil {
		t.Fatal("bad params must be an error")
	}
}
