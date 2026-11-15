// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/gsoultan/ares-server/internal/auth"
)

// BenchmarkPGSaveGrowingAudit is the Postgres twin of the stormstore benchmark:
// one Save after one audit append, at several trail lengths. It also reports the
// table's on-disk size (heap + TOAST), which grows with every rewrite until
// autovacuum reclaims the dead tuples.
func BenchmarkPGSaveGrowingAudit(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("audit=%d", n), func(b *testing.B) {
			s := freshStore(b)
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
			var size int64
			if err := s.pool.QueryRow(context.Background(), `SELECT pg_total_relation_size('engagements') + coalesce(pg_total_relation_size(to_regclass('audit_entries')), 0)`).Scan(&size); err == nil {
				b.ReportMetric(float64(size)/(1<<20), "tableMiB")
			}
		})
	}
}

// BenchmarkPGAuthenticate is the cost every authenticated RPC pays before its
// handler runs: hash the bearer token and load the session row.
func BenchmarkPGAuthenticate(b *testing.B) {
	s := freshStore(b)
	svc := auth.NewService(s.Users(), s.Sessions())
	if _, err := svc.CreateUser("", "bench@example.test", "Bench", "correct horse battery staple", auth.RoleAdmin); err != nil {
		b.Fatal(err)
	}
	sess, _, err := svc.Login("bench@example.test", "correct horse battery staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := svc.Authenticate(sess.Token); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
