// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"path/filepath"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares/module"
)

// The test intensity and its approvals survive a restart, so an approval given
// before a restart still allows exactly one run after it.
func TestConsentPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ares.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	eng, err := s.Create("", "Demo")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = eng.Scope.AddInScope("example.com")
	_ = eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"})
	if err := eng.SetTestLevel(module.LevelIntrusive, "lead"); err != nil {
		t.Fatalf("level: %v", err)
	}
	a, err := eng.Approve("loadresilience", module.Target{URL: "https://example.com/"}, "Rina", "signed", "")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := s.Save(eng); err != nil {
		t.Fatalf("save: %v", err)
	}
	_ = s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, ok := s2.Get(eng.ID)
	if !ok {
		t.Fatal("engagement lost")
	}
	c := got.ConsentSnapshot()
	if c.Level != module.LevelIntrusive || len(c.Approvals) != 1 || c.Approvals[0].ID != a.ID || !c.Approvals[0].Usable() {
		t.Fatalf("consent did not survive the restart: %+v", c)
	}
}
