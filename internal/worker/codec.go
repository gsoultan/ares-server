// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// Outcomes are stored as zstd-compressed JSON. Results are repetitive JSON
// (the same keys, techniques and targets over and over), which zstd shrinks
// several times over at a few hundred MB/s, so the stored form is a fraction
// of the in-memory one and costs little CPU to write or read back.
var (
	zEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	zDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
)

// Sealer encrypts stored outcomes per tenant. *tenantkey.Ring satisfies it.
// The record name binds a ciphertext to its job, so one cannot be swapped for
// another's.
type Sealer interface {
	Seal(tenantID, record string, plaintext []byte) (string, error)
	Open(tenantID, record, sealed string) ([]byte, error)
}

// zstdMagic starts every zstd frame; a stored value without it is sealed.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

func outcomeRecord(jobID string) string { return "outcome/" + jobID }

// EncodeOutcome is the stored form of an outcome: zstd-compressed JSON, then
// sealed for tenantID when sealer is non-nil (pass a nil interface, not a nil
// pointer, while encryption is off).
func EncodeOutcome(o Outcome, sealer Sealer, tenantID string) ([]byte, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("worker: encode outcome %s: %w", o.JobID, err)
	}
	z := zEnc.EncodeAll(raw, make([]byte, 0, len(raw)/4))
	if sealer == nil {
		return z, nil
	}
	sealed, err := sealer.Seal(tenantID, outcomeRecord(o.JobID), z)
	if err != nil {
		return nil, fmt.Errorf("worker: seal outcome %s: %w", o.JobID, err)
	}
	return []byte(sealed), nil
}

// DecodeOutcome reverses EncodeOutcome. A value stored before encryption was
// turned on (plain zstd) stays readable.
func DecodeOutcome(b []byte, sealer Sealer, tenantID, jobID string) (Outcome, error) {
	if !bytes.HasPrefix(b, zstdMagic) {
		if sealer == nil {
			return Outcome{}, fmt.Errorf("worker: outcome %s is sealed and encryption is off", jobID)
		}
		opened, err := sealer.Open(tenantID, outcomeRecord(jobID), string(b))
		if err != nil {
			return Outcome{}, fmt.Errorf("worker: open outcome %s: %w", jobID, err)
		}
		b = opened
	}
	raw, err := zDec.DecodeAll(b, nil)
	if err != nil {
		return Outcome{}, fmt.Errorf("worker: decompress outcome: %w", err)
	}
	var o Outcome
	if err := json.Unmarshal(raw, &o); err != nil {
		return Outcome{}, fmt.Errorf("worker: decode outcome: %w", err)
	}
	return o, nil
}
