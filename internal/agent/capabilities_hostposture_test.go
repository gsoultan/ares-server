// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package agent

import "testing"

// The v6 Linux host-posture modules are dispatchable under the hostposture
// capability group, so an agent granted that group can run them.
func TestHostPostureModulesAreGrouped(t *testing.T) {
	for _, m := range []string{"hostposture", "sshbanner", "nftreach"} {
		if g := GroupOf(m); g != CapHostPosture {
			t.Errorf("GroupOf(%q) = %q, want %q", m, g, CapHostPosture)
		}
	}
	// An ungrouped module is still refused.
	if GroupOf("versionscan") != "" {
		t.Error("versionscan must not be dispatchable to an agent")
	}
}
