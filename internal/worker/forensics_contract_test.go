// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
)

// The Forensics page sends each engine module exactly these parameter shapes
// (web/src/features/forensics/sources.ts): items by name, and indicators
// narrowed to the types that module accepts, carrying the feed's provenance.
// This pins that contract against the engine version the server is built
// with, so an engine change that would refuse the page's jobs fails here.
func TestForensicsPageParamsRunOnTheEngine(t *testing.T) {
	ind := func(typ, value string) map[string]any {
		return map[string]any{
			"type": typ, "value": value, "label": "ExampleSpy, Example feed",
			"tier": "malicious-activity", "confidence": "primary",
		}
	}
	item := func(name, text string) map[string]any {
		return map[string]any{"name": name, "text": text, "source": "Test handset"}
	}
	cases := []struct {
		module string
		params map[string]any
		want   string // an issueKey the run must raise
	}{
		{"androidqf", map[string]any{
			"items":      []any{item("collection/packages.json", `[{"name":"com.example.spyagent","system":false,"installer":""}]`)},
			"indicators": []any{ind("appid", "com.example.spyagent"), ind("domain", "spy.example"), ind("ip", "203.0.113.7")},
		}, "androidqf-known-app"},
		{"dnslogscan", map[string]any{
			"items":      []any{item("router.log", "query[A] cdn.spy.example from 192.168.1.5\n")},
			"indicators": []any{ind("domain", "spy.example"), ind("ip", "203.0.113.7")},
		}, "dns-indicator-match"},
		{"connrecord", map[string]any{
			"items":      []any{item("conntrack.txt", "tcp 6 431999 ESTABLISHED src=192.168.1.5 dst=203.0.113.7 sport=51000 dport=443\n")},
			"indicators": []any{ind("ip", "203.0.113.7"), ind("domain", "spy.example")},
		}, ""},
		{"winartifacts", map[string]any{
			"items":      []any{item("hosts", "203.0.113.7 login.bank.example\n")},
			"indicators": []any{ind("ip", "203.0.113.7"), ind("sha256", "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"), ind("url", "https://spy.example/a")},
		}, ""},
		{"eventlog", map[string]any{
			"items":      []any{item("security.xml", "<Events><Event><System><EventID>1102</EventID><TimeCreated SystemTime='2026-11-15T07:00:00Z'/></System></Event></Events>")},
			"indicators": []any{ind("domain", "spy.example")},
		}, ""},
		{"winpersist", map[string]any{
			"items":      []any{item("run.reg", "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"x\"=\"powershell -enc AAAA\"\n")},
			"indicators": []any{ind("url", "https://spy.example/a")},
		}, ""},
		{"iocmatch", map[string]any{
			"observations": []any{map[string]any{"name": "note.txt", "text": "beacon to cdn.spy.example", "hash": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"}},
			"indicators":   []any{ind("domain", "cdn.spy.example"), map[string]any{"type": "domain", "value": "old.example", "withdrawn": true}},
		}, "ioc-match"},
		{"iocexport", map[string]any{
			"indicators": []any{ind("domain", "spy.example"), ind("ip", "203.0.113.7")},
			"title":      "Quick check · personal", "producer": "Ares",
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.module, func(t *testing.T) {
			reg := module.NewRegistry()
			if err := reg.Register(engineModule(t, c.module)); err != nil {
				t.Fatalf("register: %v", err)
			}
			store := engagement.NewMemStore()
			eng, err := store.Create("", "Quick check · personal")
			if err != nil {
				t.Fatal(err)
			}
			if err := eng.Authorize(engagement.Authorization{Document: "quick check consent", ApprovedBy: "operator"}); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(c.params)
			out := NewProcessor(reg, store).Process(context.Background(), queue.Job{
				ID: "j-" + c.module, EngagementID: eng.ID, Module: c.module, Actor: "operator", Params: raw,
			})
			if out.Error != "" {
				t.Fatalf("the engine refused the page's parameters: %s", out.Error)
			}
			if len(out.Results) == 0 {
				t.Fatal("no results")
			}
			if c.want == "" {
				return
			}
			for _, r := range out.Results {
				if r.Kind == "finding" && r.Data["issueKey"] == c.want {
					return
				}
			}
			t.Fatalf("want a %q finding, got %d results", c.want, len(out.Results))
		})
	}
}
