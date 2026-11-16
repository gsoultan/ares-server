// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"fmt"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
)

// BenchmarkProcessWithProgress runs one job that emits n results while a live
// view is subscribed (the progress callback the pool wires to the outcome
// store). It shows how the per-result snapshot scales with the job's size.
func BenchmarkProcessWithProgress(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("results=%d", n), func(b *testing.B) {
			reg := module.NewRegistry()
			if err := reg.Register(multiMod{n: n}); err != nil {
				b.Fatal(err)
			}
			store := engagement.NewMemStore()
			proc := NewProcessor(reg, store)
			eng, _ := store.Create("", "bench")
			_ = eng.Scope.AddInScope("example.com")
			if err := eng.Authorize(engagement.Authorization{Document: "a.pdf", ApprovedBy: "lead"}); err != nil {
				b.Fatal(err)
			}
			outcomes := NewMemOutcomes()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				outcomes.Save(proc.ProcessWithProgress(context.Background(), queue.Job{
					ID: "j", EngagementID: eng.ID, Module: "multi", Actor: "op",
					Targets: []module.Target{{Host: "www.example.com"}},
				}, outcomes.Save))
			}
		})
	}
}
