// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package agent

// Capability groups are the plain-language permissions an operator grants an
// agent (the allow-list on the install key and the agent record). Each group
// maps to a set of engine modules the agent may run. A task names a module; the
// server and the agent both check that the module's group is on the allow-list,
// so an agent can only ever run modules it was explicitly permitted — the same
// shape as the engine's scope gate, one layer up.
//
// Phase 2 ships the inert internal-recon groups. The exposure groups
// (passivesniff, mitmexposure) and hostposture are declared here so the UI and
// allow-list are stable, and are wired as their capability phases land.
const (
	CapDiscovery    = "discovery"    // internal host/network discovery
	CapWebCheck     = "webcheck"     // internal web/service checks
	CapHostPosture  = "hostposture"  // local read-only posture (phase 2+)
	CapPassiveSniff = "passivesniff" // passive exposure listening (phase 3)
	CapMITMExposure = "mitmexposure" // MITM susceptibility, observation-only (phase 3)
)

// moduleGroup maps an engine module name to its capability group. Only modules
// listed here can be dispatched to an agent; anything else is refused even if an
// operator names it. This is the allow-list of engine modules the agent may run,
// kept deliberately narrow and inert.
var moduleGroup = map[string]string{
	// discovery
	"portscan": CapDiscovery,
	"recon":    CapDiscovery,
	"dnsrecon": CapDiscovery,
	"rdap":     CapDiscovery,
	// webcheck
	"webcheck":    CapWebCheck,
	"tlscheck":    CapWebCheck,
	"headerprobe": CapWebCheck,
	"httpprobe":   CapWebCheck,
	// passive internal-exposure assessment (observation-only, inert)
	"passivesniff": CapPassiveSniff,
	"mitmexposure": CapMITMExposure,
	// local read-only Linux host posture (the v6 Linux CVE wave). sshbanner is
	// a pre-auth banner read and belongs with the host's own posture; nftreach
	// is the consented level-3 nf_tables reachability probe, gated by a
	// recorded approval in the module itself.
	"hostposture": CapHostPosture,
	"sshbanner":   CapHostPosture,
	"nftreach":    CapHostPosture,
}

// AllCapabilities lists every capability group, for the operator UI. mitmexposure
// is included but is off unless an operator adds it explicitly.
func AllCapabilities() []string {
	return []string{CapDiscovery, CapWebCheck, CapHostPosture, CapPassiveSniff, CapMITMExposure}
}

// GroupOf returns the capability group a module belongs to, or "" if the module
// is not dispatchable to an agent.
func GroupOf(module string) string { return moduleGroup[module] }

// AuthorizeModule checks that a module is dispatchable and that its capability
// group is on the agent's allow-list. The agent re-checks the same before it
// runs anything.
func (r *Registry) AuthorizeModule(agentID, module string) error {
	group := GroupOf(module)
	if group == "" {
		return ErrCapabilityGate
	}
	return r.AuthorizeCapability(agentID, group)
}
