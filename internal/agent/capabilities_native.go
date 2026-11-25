// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package agent

// Agent-native capabilities are implemented by the agent itself rather than by
// an engine module. They are named so they never collide with an engine module
// (the engine's "hostposture" module is a different thing), and they register
// here rather than in the moduleGroup literal so other changes to that list
// merge cleanly.
//
//   - persistcollect: read-only collection of persistence locations, socket
//     owners, file attributes, package verification and auditd state, for the
//     ares linpersist / winpersist analyzers. Grouped with host posture.
//   - egresscheck: one benign request per channel to Ares's own canary (M-25).
var agentNative = map[string]string{
	"persistcollect": CapHostPosture,
	"egresscheck":    CapEgressCheck,
}

func init() {
	for m, g := range agentNative {
		if _, taken := moduleGroup[m]; taken {
			panic("agent: native capability " + m + " collides with an engine module")
		}
		moduleGroup[m] = g
	}
}

// IsAgentNative reports whether a module name is implemented by the agent.
func IsAgentNative(module string) bool { _, ok := agentNative[module]; return ok }
