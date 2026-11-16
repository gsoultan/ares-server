// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// TestMapToStructMatchesJSON pins the direct conversion to the JSON round trip
// it replaces: for every payload, both paths must produce the same Struct.
func TestMapToStructMatchesJSON(t *testing.T) {
	type typed struct {
		A string `json:"a"`
		B int    `json:"b,omitempty"`
	}
	cases := []map[string]any{
		{"title": "Missing header", "severity": "medium", "score": 5.5, "n": 3, "ok": true, "none": nil},
		{"big": int64(1 << 60), "u": uint64(math.MaxUint64), "i32": int32(-7), "f": 0.1, "neg": -0.0},
		{"list": []any{"a", 1, 2.5, false, nil, []any{"x"}, map[string]any{"k": "v"}}},
		{"strs": []string{"a", "b"}, "nilstrs": []string(nil), "maps": []map[string]any{{"x": 1}}},
		{"ss": map[string]string{"k": "v"}, "nilmap": map[string]any(nil), "nillist": []any(nil)},
		{"num": json.Number("12.50"), "html": "<script>&</script>", "uni": "héllo ✓"},
		// These need encoding/json's own rules and take the fallback path.
		{"typed": typed{A: "x"}, "when": time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)},
		{"bytes": []byte("raw"), "f32": float32(0.1), "ints": []int{1, 2}},
		{"bad": "\xff\xfeok"},
		{"nested": map[string]any{"deep": map[string]any{"deeper": []any{map[string]any{"t": typed{B: 2}}}}}},
	}
	for i, m := range cases {
		got, err := mapToStruct(m)
		if err != nil {
			t.Fatalf("case %d: mapToStruct: %v", i, err)
		}
		want, err := jsonStruct(m)
		if err != nil {
			t.Fatalf("case %d: jsonStruct: %v", i, err)
		}
		if !proto.Equal(got, want) {
			t.Errorf("case %d: direct conversion differs from JSON round trip\n got: %v\nwant: %v", i, got, want)
		}
	}
	// NaN is refused by encoding/json; the result must still be an error.
	if _, err := mapToStruct(map[string]any{"x": math.NaN()}); err == nil {
		t.Error("NaN payload: want the JSON path's error")
	}
}

func BenchmarkMapToStruct(b *testing.B) {
	m := map[string]any{"title": "Missing header", "severity": "medium", "evidence": "x-frame-options absent",
		"fix": map[string]any{"steps": []any{"add header", "redeploy"}, "refs": []any{"https://owasp.org"}}, "cvss": 5.3}
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = mapToStruct(m)
		}
	})
	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = jsonStruct(m)
		}
	})
}
