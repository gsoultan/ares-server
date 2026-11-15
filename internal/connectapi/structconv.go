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
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// mapToStruct converts a module's result payload to a protobuf Struct.
//
// Payloads are almost always plain JSON-shaped values (strings, numbers, bools,
// []any, map[string]any), which convert directly with no intermediate encoding.
// Anything else (a typed struct, a typed slice, time.Time, []byte) falls back to
// a JSON round trip, so the result is exactly what encoding/json would produce:
// the direct path is only taken when it gives the same answer.
func mapToStruct(m map[string]any) (*structpb.Struct, error) {
	if len(m) == 0 {
		return nil, nil
	}
	if s, ok := directStruct(m); ok {
		return s, nil
	}
	return jsonStruct(m)
}

// jsonStruct is the general (slow) path: encode with encoding/json and decode
// into a Struct.
func jsonStruct(m map[string]any) (*structpb.Struct, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func directStruct(m map[string]any) (*structpb.Struct, bool) {
	fields := make(map[string]*structpb.Value, len(m))
	for k, v := range m {
		if !utf8.ValidString(k) {
			return nil, false
		}
		pv, ok := directValue(v)
		if !ok {
			return nil, false
		}
		fields[k] = pv
	}
	return &structpb.Struct{Fields: fields}, true
}

// directValue converts the JSON-shaped Go values; ok is false for anything that
// needs encoding/json's rules (the caller then takes the JSON path for the
// whole payload).
func directValue(v any) (*structpb.Value, bool) {
	switch x := v.(type) {
	case nil:
		return structpb.NewNullValue(), true
	case string:
		if !utf8.ValidString(x) {
			return nil, false // encoding/json's replacement rules apply
		}
		return structpb.NewStringValue(x), true
	case bool:
		return structpb.NewBoolValue(x), true
	case float64:
		return number(x)
	case float32:
		// encoding/json formats a float32 with 32-bit precision; the decoded
		// float64 differs from float64(x), so leave it to the JSON path.
		return nil, false
	case int:
		return structpb.NewNumberValue(float64(x)), true
	case int64:
		return structpb.NewNumberValue(float64(x)), true
	case int32:
		return structpb.NewNumberValue(float64(x)), true
	case uint:
		return structpb.NewNumberValue(float64(x)), true
	case uint64:
		return structpb.NewNumberValue(float64(x)), true
	case uint32:
		return structpb.NewNumberValue(float64(x)), true
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return nil, false
		}
		return number(f)
	case map[string]any:
		if x == nil {
			return structpb.NewNullValue(), true
		}
		s, ok := directStruct(x)
		if !ok {
			return nil, false
		}
		return structpb.NewStructValue(s), true
	case []any:
		if x == nil {
			return structpb.NewNullValue(), true
		}
		vals := make([]*structpb.Value, len(x))
		for i, e := range x {
			pv, ok := directValue(e)
			if !ok {
				return nil, false
			}
			vals[i] = pv
		}
		return structpb.NewListValue(&structpb.ListValue{Values: vals}), true
	case []string:
		if x == nil {
			return structpb.NewNullValue(), true
		}
		vals := make([]*structpb.Value, len(x))
		for i, e := range x {
			if !utf8.ValidString(e) {
				return nil, false
			}
			vals[i] = structpb.NewStringValue(e)
		}
		return structpb.NewListValue(&structpb.ListValue{Values: vals}), true
	case []map[string]any:
		if x == nil {
			return structpb.NewNullValue(), true
		}
		vals := make([]*structpb.Value, len(x))
		for i, e := range x {
			pv, ok := directValue(e)
			if !ok {
				return nil, false
			}
			vals[i] = pv
		}
		return structpb.NewListValue(&structpb.ListValue{Values: vals}), true
	case map[string]string:
		if x == nil {
			return structpb.NewNullValue(), true
		}
		fields := make(map[string]*structpb.Value, len(x))
		for k, e := range x {
			if !utf8.ValidString(k) || !utf8.ValidString(e) {
				return nil, false
			}
			fields[k] = structpb.NewStringValue(e)
		}
		return structpb.NewStructValue(&structpb.Struct{Fields: fields}), true
	default:
		return nil, false
	}
}

// number refuses NaN and ±Inf, which encoding/json rejects (the JSON path then
// reports the error exactly as before).
func number(f float64) (*structpb.Value, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, false
	}
	return structpb.NewNumberValue(f), true
}
