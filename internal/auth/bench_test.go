// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import "testing"

// BenchmarkVerifyPassword is the CPU one sign-in costs (PBKDF2-SHA256 at the
// stored iteration count).
func BenchmarkVerifyPassword(b *testing.B) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := VerifyPassword(h, "correct horse battery staple"); !ok {
			b.Fatal("mismatch")
		}
	}
}
