// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"testing"
	"time"

	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/module"
)

func TestOutcomeRepoRoundTrip(t *testing.T) {
	s := freshStore(t)
	r := s.Outcomes()
	t0 := time.Now()
	for i, eng := range []string{"e1", "e1", "e2"} {
		o := worker.Outcome{JobID: "j" + string(rune('a'+i)), Engagement: eng, Module: "webcheck",
			StartedAt: t0.Add(time.Duration(i) * time.Minute), FinishedAt: t0.Add(time.Hour),
			Results: []module.Result{{Capability: "webcheck", Kind: "finding", Data: map[string]any{"title": "x"}}}}
		if err := r.PutOutcome(o); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := Open(dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	r2 := s2.Outcomes()
	got, err := r2.OutcomesOf("e1")
	if err != nil || len(got) != 2 || got[0].JobID != "ja" || got[1].Results[0].Data["title"] != "x" {
		t.Fatalf("OutcomesOf(e1) = %+v, %v", got, err)
	}
	idx := map[string]string{}
	if err := r2.OutcomeIndex(func(job, eng string, started time.Time) { idx[job] = eng }); err != nil {
		t.Fatal(err)
	}
	if len(idx) != 3 || idx["jc"] != "e2" {
		t.Fatalf("index = %v", idx)
	}
}
