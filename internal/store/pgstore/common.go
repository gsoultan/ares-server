// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"encoding/json"

	"github.com/gsoultan/storm/runtime"
)

// marshalJSON encodes v as a jsonb payload. encoding/json preserves full
// nanosecond timestamps, which is what keeps the audit hash-chain verifiable
// across a reload.
func marshalJSON(v any) (runtime.JSON, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return runtime.JSON(b), nil
}
