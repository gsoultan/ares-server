// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/ares/module"
)

func TestProofProtoNilIsNil(t *testing.T) {
	if proofProto(nil) != nil {
		t.Fatal("nil proof should map to nil, so a finding with no exchange carries none")
	}
}

func TestProofProtoCarriesCallback(t *testing.T) {
	p := &module.Proof{
		Kind:    module.ProofCallback,
		Summary: "the server resolved a one-time canary name",
		Claim:   "log4shell:header:X-Api-Version",
		Token:   "abc123",
		Sent:    &module.Exchange{At: time.Now().UTC(), Protocol: "http", Method: "GET", URL: "http://t/"},
		Callback: &module.Callback{
			Channel: "dns", At: time.Now().UTC(), DelayMs: 820, SourceIP: "198.51.100.7",
		},
	}
	module.SealProof(p)
	got := proofProto(p)
	if got.GetKind() != "callback" || got.GetToken() != "abc123" {
		t.Fatalf("proof not carried: %+v", got)
	}
	if got.GetCallback().GetSourceIp() != "198.51.100.7" || got.GetCallback().GetDelayMs() != 820 {
		t.Fatalf("callback detail lost: %+v", got.GetCallback())
	}
	if got.GetFingerprint() != p.Fingerprint {
		t.Fatalf("fingerprint not carried: %q vs %q", got.GetFingerprint(), p.Fingerprint)
	}
}

func TestProofFilename(t *testing.T) {
	name := proofFilename("engABCDEFGHIJKLMNOP", "sha256:deadbeefcafebabe0000")
	if !strings.HasPrefix(name, "proof-") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("unexpected filename: %q", name)
	}
	if strings.Contains(name, "sha256:") {
		t.Fatalf("filename should use the short hex, not the prefix: %q", name)
	}
}
