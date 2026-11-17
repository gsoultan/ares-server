// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package technique says how far each test goes, in the engine's own consent
// levels (module.ConsentLevel), and describes every test above safe proof in
// the words an approver needs: what it does, the risk, whether and how it is
// undone, and what it touches.
//
// The level of a module comes from the engine's registry (module.Describer or
// the engine's capability table). A module the engine does not describe is
// treated as safe proof, which is what every undescribed module is today. The
// few modules the engine ships without a description but that go further are
// described here, through the registry's own SetCapability, so the engine's
// validation still applies: nothing above intrusive-but-recoverable can be
// described, and anything above safe proof must say how it is undone.
package technique

import (
	"sort"

	"github.com/gsoultan/ares/module"
)

// Technique is the plain-language description of a test above safe proof,
// shown before anyone allows it.
type Technique struct {
	Module     string              `json:"module"`
	Level      module.ConsentLevel `json:"level"`
	Name       string              `json:"name"`
	Action     string              `json:"action"`     // what it does
	Risk       string              `json:"risk"`       // what could go wrong
	Reversible bool                `json:"reversible"` // the effect ends or is undone
	Recovery   string              `json:"recovery"`   // how it is undone
	Touches    string              `json:"touches"`    // what it touches
	Limit      string              `json:"limit"`      // the hard limit it never crosses
}

// extra describes engine modules that ship without a capability row but go
// further than safe proof.
var extra = map[string]struct {
	cap  module.Capability
	desc Technique
}{
	"loadresilience": {
		cap: module.Capability{
			Level:    module.LevelIntrusive,
			Surface:  []module.SurfaceKind{module.SurfaceWeb},
			Proofs:   []string{"differential"},
			Cost:     module.Cost{Requests: 2000, Seconds: 300},
			Recovery: "the load stops at the first sign of distress or when stopped, and the service recovers on its own",
		},
		desc: Technique{
			Name:       "Resilience test",
			Action:     "Sends a controlled, rising number of ordinary requests from one source to find the load where the service slows down or starts to fail.",
			Risk:       "The service may be slow or briefly unavailable for its users near the top of the ramp.",
			Reversible: true,
			Recovery:   "The load stops the moment errors or delays cross the limits you set, or when you press Stop now. The service recovers on its own once the load stops.",
			Touches:    "Only the address you approve, from Ares's own address. Nothing is changed or stored on the target.",
			Limit:      "Never more than the ceiling you set. No amplification, no spoofed sources, no botnet, and it never holds a system down.",
		},
	},
}

// Register describes the extra modules in the engine's registry. It is called
// once at start-up, after the engine has built the registry.
func Register(reg *module.Registry) error {
	names := make([]string, 0, len(extra))
	for name := range extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := reg.Get(name); !ok {
			continue
		}
		if _, described := reg.Capability(name); described {
			continue // the engine describes it itself now
		}
		if err := reg.SetCapability(name, extra[name].cap); err != nil {
			return err
		}
	}
	return nil
}

// LevelOf returns the consent level a module needs. Undescribed modules are
// safe proof.
func LevelOf(reg *module.Registry, name string) module.ConsentLevel {
	if c, ok := reg.Capability(name); ok && c.Level >= module.LevelSafeProof {
		return c.Level
	}
	return module.LevelSafeProof
}

// Describe returns the description of a module above safe proof. ok is false
// for a safe-proof module, which needs no description.
func Describe(reg *module.Registry, name string) (Technique, bool) {
	level := LevelOf(reg, name)
	if level <= module.LevelSafeProof {
		return Technique{}, false
	}
	t := Technique{Module: name, Level: level, Reversible: true}
	if e, ok := extra[name]; ok {
		t = e.desc
		t.Module, t.Level = name, level
	}
	if c, ok := reg.Capability(name); ok && t.Recovery == "" {
		t.Recovery = c.Recovery
	}
	if t.Name == "" {
		t.Name = name
	}
	return t, true
}

// AboveSafeProof lists every registered module above safe proof, by name.
func AboveSafeProof(reg *module.Registry) []Technique {
	var out []Technique
	for _, name := range reg.Described() {
		if t, ok := Describe(reg, name); ok {
			out = append(out, t)
		}
	}
	return out
}
