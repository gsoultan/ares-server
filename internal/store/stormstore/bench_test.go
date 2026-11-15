// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkSaveGrowingAudit measures one engagement Save after an audit append,
// at several audit-trail lengths. A Save that rewrites the whole trail costs
// O(trail) per change; an append-only one stays flat.
func BenchmarkSaveGrowingAudit(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("audit=%d", n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "bench.db")
			s, err := Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			eng, err := s.Create("", "bench")
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < n; i++ {
				eng.Audit.Append("operator", "result", "https://app.example.test/login", "headerprobe/finding")
			}
			if err := s.Save(eng); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				eng.Audit.Append("operator", "result", "https://app.example.test/login", "headerprobe/finding")
				if err := s.Save(eng); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if fi, err := os.Stat(path); err == nil {
				b.ReportMetric(float64(fi.Size())/(1<<20), "dbMiB")
			}
		})
	}
}
