// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package hostposture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, p, body string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxCollectionIsFixedAndReadOnly(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/crontab", "* * * * * root /tmp/.x/kdevtmpfsi\n")
	write(t, root, "etc/ld.so.preload", "/usr/lib/libprocesshider.so\n")
	write(t, root, "etc/shadow", "root:$6$secret:...\n")
	write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	write(t, root, "home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nz test@example\n")
	write(t, root, "home/alice/.ssh/id_ed25519", "PRIVATE KEY\n")
	write(t, root, "home/alice/.bash_history", "export TOKEN=abc\n")

	var ran []string
	c := &Collector{goos: "linux", root: root, run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		if name == "rpm" {
			return nil, errors.New("executable file not found in $PATH")
		}
		return []byte("output of " + name), nil
	}}
	rep := c.Collect(context.Background())
	got := map[string]string{}
	for _, it := range rep.Items {
		got[it.Name] = it.Text
		if strings.Contains(it.Text, "secret") || strings.Contains(it.Text, "PRIVATE KEY") || strings.Contains(it.Text, "TOKEN=") {
			t.Errorf("collected a forbidden file: %s", it.Name)
		}
	}
	for _, want := range []string{"/etc/crontab", "/etc/ld.so.preload", "/home/alice/.ssh/authorized_keys", "ss -tunap", "auditctl -s"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s (have %d items)", want, len(rep.Items))
		}
	}
	if len(ran) != len(linuxCommands) {
		t.Errorf("ran %d commands, want the fixed %d", len(ran), len(linuxCommands))
	}
	found := false
	for _, s := range rep.Skipped {
		if strings.HasPrefix(s, "rpm -Va") && strings.Contains(s, "not installed") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing rpm skip note: %v", rep.Skipped)
	}
}

func TestEveryCommandIsFixed(t *testing.T) {
	for _, set := range [][]command{linuxCommands, darwinCommands, windowsCommands} {
		for _, c := range set {
			for _, a := range c.args {
				if strings.ContainsAny(a, ";|&$`") {
					t.Errorf("%s has a shell-like argument %q", c.name, a)
				}
			}
		}
	}
}
