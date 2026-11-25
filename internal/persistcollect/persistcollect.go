// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package persistcollect is the agent's local, read-only posture collector for
// the malware and botnet detection wave (docs/detection-scenarios-malware-
// botnet.md in the ares repository: M-12 to M-15, M-23, M-24).
//
// It gathers the evidence the engine's offline readers (linpersist,
// winpersist, persistplist) analyse: persistence locations, socket-to-process
// tables, audit state and package integrity. It
//
//   - reads a fixed list of files and directories, with size caps;
//   - runs only an allow-listed set of commands with fixed arguments, no shell,
//     no argument taken from a task, a timeout and an output cap;
//   - never reads password hashes, private keys, shell history or browser data;
//   - never changes, removes, kills or installs anything.
//
// The output items use the same shape (name, path, kind, text, source) as the
// engine readers' params, so the server can hand them straight to linpersist
// or winpersist.
package persistcollect

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxFileBytes  = 1 << 20  // per file
	maxTotalBytes = 32 << 20 // per collection
	maxCmdBytes   = 4 << 20  // per command output
	cmdTimeout    = 20 * time.Second
	maxDirEntries = 500
)

// Item is one collected artefact.
type Item struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	Kind   string `json:"kind,omitempty"` // file | command
	Text   string `json:"text"`
	Source string `json:"source"`
}

// Report is the outcome of one collection.
type Report struct {
	OS        string   `json:"os"`
	Items     []Item   `json:"items"`
	Skipped   []string `json:"skipped,omitempty"` // unreadable or capped, with reason
	Truncated bool     `json:"truncated,omitempty"`
}

// command is one allow-listed read-only command with fixed arguments.
type command struct {
	name string
	args []string
}

// Fixed collection plans. Paths may be globs; nothing comes from a task.
var (
	linuxFiles = []string{
		"/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
		"/var/spool/cron/*", "/var/spool/cron/crontabs/*",
		"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*/*.service",
		"/lib/systemd/system/*.service", "/usr/lib/systemd/system/*.service",
		"/etc/rc.local", "/etc/init.d/*", "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc",
		"/etc/ld.so.preload", "/etc/pam.d/*", "/etc/udev/rules.d/*",
		"/etc/audit/auditd.conf", "/etc/audit/audit.rules", "/etc/audit/rules.d/*",
		"/etc/ssh/sshd_config",
	}
	// Per-user files read for every account in /etc/passwd with a home dir.
	linuxUserFiles = []string{".ssh/authorized_keys", ".config/systemd/user/*.service", ".bashrc", ".profile"}
	linuxCommands  = []command{
		{"ss", []string{"-tunap"}},
		{"systemctl", []string{"list-unit-files", "--state=enabled", "--no-pager", "--no-legend"}},
		{"auditctl", []string{"-s"}},
		{"auditctl", []string{"-l"}},
		{"lsattr", []string{"-d", "/etc/ld.so.preload", "/etc/crontab", "/etc/passwd", "/etc/ssh/sshd_config", "/etc/rc.local"}},
		{"debsums", []string{"-c"}},
		{"rpm", []string{"-Va", "--nomtime"}},
	}
	darwinFiles = []string{
		"/Library/LaunchAgents/*.plist", "/Library/LaunchDaemons/*.plist", "/etc/periodic/daily/*",
	}
	darwinUserFiles = []string{"Library/LaunchAgents/*.plist"}
	darwinCommands  = []command{
		{"launchctl", []string{"list"}},
		{"lsof", []string{"-nP", "-iTCP", "-sTCP:ESTABLISHED"}},
	}
	windowsCommands = []command{
		{"reg", []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`}},
		{"reg", []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`}},
		{"reg", []string{"query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`}},
		{"reg", []string{"query", `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`}},
		{"reg", []string{"query", `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "/s", "/v", "Debugger"}},
		{"schtasks", []string{"/query", "/fo", "CSV", "/v"}},
		{"netstat", []string{"-ano"}},
	}
)

// never lists paths the collector must not read even if a glob reaches them.
var never = []string{"/etc/shadow", "/etc/gshadow", "/etc/security/opasswd", "/id_rsa", "/id_ed25519", "/id_ecdsa", "/id_dsa", "_history"}

// Collector gathers posture. The zero value collects from the real host;
// tests replace root, run and passwd.
type Collector struct {
	goos  string
	root  string // prefix for every path (tests)
	run   func(ctx context.Context, name string, args ...string) ([]byte, error)
	total int
}

// New returns a collector for this host.
func New() *Collector { return &Collector{goos: runtime.GOOS, run: runCmd} }

// Collect runs the fixed plan for this OS.
func (c *Collector) Collect(ctx context.Context) Report {
	rep := Report{OS: c.goos}
	switch c.goos {
	case "linux":
		c.files(ctx, &rep, linuxFiles)
		c.userFiles(ctx, &rep, linuxUserFiles)
		c.commands(ctx, &rep, linuxCommands)
	case "darwin":
		c.files(ctx, &rep, darwinFiles)
		c.userFiles(ctx, &rep, darwinUserFiles)
		c.commands(ctx, &rep, darwinCommands)
	case "windows":
		c.commands(ctx, &rep, windowsCommands)
	default:
		rep.Skipped = append(rep.Skipped, "unsupported OS "+c.goos)
	}
	return rep
}

func forbidden(p string) bool {
	l := strings.ToLower(p)
	for _, n := range never {
		if strings.HasSuffix(l, n) || strings.Contains(l, n+"/") {
			return true
		}
	}
	return false
}

func (c *Collector) files(ctx context.Context, rep *Report, globs []string) {
	for _, g := range globs {
		if ctx.Err() != nil {
			return
		}
		matches, _ := filepath.Glob(c.root + g)
		if len(matches) > maxDirEntries {
			rep.Skipped = append(rep.Skipped, g+": more than 500 entries, first 500 read")
			matches = matches[:maxDirEntries]
		}
		sort.Strings(matches)
		for _, m := range matches {
			c.readFile(rep, m)
		}
	}
}

func (c *Collector) readFile(rep *Report, full string) {
	path := strings.TrimPrefix(full, c.root)
	if forbidden(path) {
		return
	}
	info, err := os.Lstat(full)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if c.total >= maxTotalBytes {
		rep.Truncated = true
		return
	}
	f, err := os.Open(full)
	if err != nil {
		rep.Skipped = append(rep.Skipped, path+": "+errText(err))
		return
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxFileBytes))
	if info.Size() > maxFileBytes {
		rep.Skipped = append(rep.Skipped, path+": over 1 MiB, first 1 MiB read")
	}
	c.total += len(b)
	rep.Items = append(rep.Items, Item{Name: path, Path: path, Kind: "file", Text: string(b), Source: "persistcollect"})
}

// userFiles reads the per-user files for each account with a home directory.
func (c *Collector) userFiles(ctx context.Context, rep *Report, rel []string) {
	for _, home := range c.homes() {
		for _, r := range rel {
			c.files(ctx, rep, []string{filepath.Join(home, r)})
		}
	}
}

func (c *Collector) homes() []string {
	var out []string
	if c.goos == "darwin" {
		ents, _ := os.ReadDir(c.root + "/Users")
		for _, e := range ents {
			if e.IsDir() && e.Name() != "Shared" {
				out = append(out, "/Users/"+e.Name())
			}
		}
		return out
	}
	f, err := os.Open(c.root + "/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		home := parts[5]
		if home == "" || home == "/" || home == "/nonexistent" || seen[home] {
			continue
		}
		if st, err := os.Stat(c.root + home); err == nil && st.IsDir() {
			seen[home] = true
			out = append(out, home)
		}
	}
	sort.Strings(out)
	return out
}

func (c *Collector) commands(ctx context.Context, rep *Report, cmds []command) {
	for _, cmd := range cmds {
		if ctx.Err() != nil {
			return
		}
		label := cmd.name + " " + strings.Join(cmd.args, " ")
		out, err := c.run(ctx, cmd.name, cmd.args...)
		if err != nil && len(out) == 0 {
			rep.Skipped = append(rep.Skipped, label+": "+errText(err))
			continue
		}
		if len(out) > maxCmdBytes {
			out = out[:maxCmdBytes]
			rep.Skipped = append(rep.Skipped, label+": output over 4 MiB, truncated")
		}
		rep.Items = append(rep.Items, Item{Name: label, Kind: "command", Text: string(out), Source: "persistcollect"})
	}
}

// runCmd runs an allow-listed binary with fixed arguments: no shell, a
// timeout, a minimal environment and a capped output.
func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var buf bytes.Buffer
	cmd.Stdout = &capWriter{w: &buf, left: maxCmdBytes + 1}
	cmd.Stderr = io.Discard
	err = cmd.Run()
	return buf.Bytes(), err
}

type capWriter struct {
	w    io.Writer
	left int
}

func (c *capWriter) Write(p []byte) (int, error) {
	n := len(p)
	if c.left <= 0 {
		return n, nil
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	c.left -= len(p)
	_, err := c.w.Write(p)
	return n, err
}

func errText(err error) string {
	switch {
	case err == nil:
		return "no output"
	case os.IsPermission(err) || err == fs.ErrPermission:
		return "permission denied"
	case err == exec.ErrNotFound || strings.Contains(err.Error(), "executable file not found"):
		return "not installed"
	}
	return err.Error()
}
