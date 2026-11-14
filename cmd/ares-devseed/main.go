// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Command ares-devseed fills a local development install with demo content so
// the app has something to show the moment it opens. It is a development tool
// only: scripts/dev.sh runs it, and nothing in a real deployment should.
//
// It works in two phases, because some state can only be written while the
// server is stopped and some only exists while it runs:
//
//	ares-devseed prepare   (server stopped) writes into the embedded database:
//	                       the master key, a super-admin with the demo
//	                       credential, the default workspace's name, a second
//	                       workspace, and the "setup done" marker, so the app
//	                       skips the /setup wizard. Re-running it is a no-op.
//
//	ares-devseed populate  (server running) signs in over the gRPC/Connect API
//	                       and creates an engagement scoped to the bundled local
//	                       practice target only (127.0.0.1), authorizes it, and
//	                       dispatches safe checks plus forensic jobs over the
//	                       sample files in samples/. Job results live in memory
//	                       on the server, so this runs on every dev start.
//
// The demo credential is deliberately weak and bypasses the 12-character policy
// through auth.HashPasswordForDevSeed. It must never reach a real deployment.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/setup"
	"github.com/gsoultan/ares-server/internal/store/stormstore"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares-server/internal/uuid"
)

// Demo content. The engagement is named so a re-run can find and reuse it.
const (
	demoEngagement = "Northwind practice lab"
	extraWorkspace = "Contoso (empty demo workspace)"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("devseed: ")
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "prepare":
		prepareCmd(os.Args[2:])
	case "populate":
		populateCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ares-devseed prepare|populate [flags]   (run with -h for flags)")
	os.Exit(2)
}

// ---- prepare ---------------------------------------------------------------

func prepareCmd(args []string) {
	fs := flag.NewFlagSet("prepare", flag.ExitOnError)
	db := fs.String("db", "", "embedded database file to seed (required)")
	keyFile := fs.String("key", "", "master key file to create (required)")
	email := fs.String("email", "admin@northwind.db", "super-admin email")
	password := fs.String("password", "admin", "super-admin password (dev only)")
	name := fs.String("name", "Northwind Admin", "super-admin display name")
	workspace := fs.String("workspace", "Northwind Traders", "name for the default workspace")
	_ = fs.Parse(args)
	if *db == "" || *keyFile == "" {
		log.Fatal("prepare needs -db and -key")
	}
	if err := prepare(*db, *keyFile, *email, *password, *name, *workspace); err != nil {
		log.Fatal(err)
	}
}

func prepare(dbPath, keyPath, email, password, name, workspace string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return err
	}
	ss, err := stormstore.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open %s (is the server still running?): %w", dbPath, err)
	}
	defer ss.Close()

	cfg, _, err := ss.Setup().GetConfig()
	if err != nil {
		return err
	}
	if cfg.Initialized {
		log.Printf("database already seeded (%s); leaving it as it is", dbPath)
		return nil
	}
	if n, err := ss.Users().CountUsers(); err != nil {
		return err
	} else if n > 0 {
		return errors.New("database has accounts but no setup marker; run scripts/dev.sh --fresh to start over")
	}

	// Master key first, exactly as the setup wizard does, so the in-app
	// Settings page comes online.
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		key, err := secret.NewKey()
		if err != nil {
			return err
		}
		if err := secret.SaveKeyFile(keyPath, key); err != nil {
			return fmt.Errorf("save master key: %w", err)
		}
	}

	hash, err := auth.HashPasswordForDevSeed(password)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := ss.Users().CreateUser(auth.User{
		ID:           uuid.NewV7(),
		TenantID:     tenant.DefaultID,
		Email:        auth.NormalizeEmail(email),
		Name:         name,
		Role:         auth.RoleSuperAdmin,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		return fmt.Errorf("create super-admin: %w", err)
	}
	if err := ss.SetTenantName(tenant.DefaultID, workspace); err != nil {
		return fmt.Errorf("name default workspace: %w", err)
	}
	ss.CreateTenant(extraWorkspace)
	if err := ss.Setup().PutConfig(setup.Config{
		Initialized: true, InitializedAt: now, DBDriver: setup.DriverFile, DBPath: dbPath,
	}); err != nil {
		return fmt.Errorf("write setup marker: %w", err)
	}
	log.Printf("seeded %s: super-admin %s, workspace %q (setup wizard skipped)", dbPath, auth.NormalizeEmail(email), workspace)
	return nil
}

// ---- populate --------------------------------------------------------------

func populateCmd(args []string) {
	fs := flag.NewFlagSet("populate", flag.ExitOnError)
	api := fs.String("api", "http://127.0.0.1:8080", "control-plane base URL")
	email := fs.String("email", "admin@northwind.db", "account to sign in with")
	password := fs.String("password", "admin", "password for that account")
	target := fs.String("target", "http://127.0.0.1:8089", "base URL of the local practice target")
	samples := fs.String("samples", "samples", "directory holding the sample files")
	_ = fs.Parse(args)
	if err := populate(*api, *email, *password, *target, *samples); err != nil {
		log.Fatal(err)
	}
}

// bearer adds the session token to every call.
type bearer struct{ token string }

func (b *bearer) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if b.token != "" {
			req.Header().Set("Authorization", "Bearer "+b.token)
		}
		return next(ctx, req)
	}
}
func (b *bearer) WrapStreamingClient(n connect.StreamingClientFunc) connect.StreamingClientFunc {
	return n
}
func (b *bearer) WrapStreamingHandler(n connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return n
}

func populate(api, email, password, target, samples string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tok := &bearer{}
	c := aresv1connect.NewControlPlaneClient(http.DefaultClient, strings.TrimRight(api, "/"),
		connect.WithInterceptors(tok))

	login, err := c.Login(ctx, connect.NewRequest(&aresv1.LoginRequest{Email: email, Password: password}))
	if err != nil {
		return fmt.Errorf("sign in as %s: %w", email, err)
	}
	if !login.Msg.GetOk() {
		return fmt.Errorf("sign in as %s refused: %s", email, login.Msg.GetError())
	}
	tok.token = login.Msg.GetToken()

	eng, err := demoEngagementFor(ctx, c)
	if err != nil {
		return err
	}
	id := eng.GetId()
	log.Printf("engagement %q (%s) is authorized for %s only", demoEngagement, id, target)

	type job struct {
		module  string
		targets []*aresv1.Target
		params  map[string]any
	}
	page := func(path string) []*aresv1.Target {
		return []*aresv1.Target{{Url: strings.TrimRight(target, "/") + path}}
	}
	jobs := []job{
		{module: "httpprobe", targets: page("/")},
		{module: "webcheck", targets: page("/")},
		{module: "reflectprobe", targets: page("/search?q=coffee")},
		{module: "sstiprobe", targets: page("/greet?name=guest")},
		{module: "redirectprobe", targets: page("/go?next=/")},
		{module: "traversalprobe", targets: page("/download?file=menu.txt")},
	}

	// Forensic jobs over the bundled sample files. They touch no target.
	read := func(rel string) ([]byte, error) { return os.ReadFile(filepath.Join(samples, rel)) }
	if b, err := read("forensics/access.log"); err == nil {
		auth, _ := read("forensics/auth.log")
		jobs = append(jobs, job{module: "logscan", params: map[string]any{"items": []any{
			map[string]any{"name": "access.log", "text": string(b), "source": "practice web server"},
			map[string]any{"name": "auth.log", "text": string(auth), "source": "practice jump host"},
		}}})
		if ind, err := read("forensics/indicators.txt"); err == nil {
			var indicators []any
			for _, l := range strings.Split(string(ind), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					indicators = append(indicators, map[string]any{"value": l, "label": "Northwind demo feed"})
				}
			}
			jobs = append(jobs, job{module: "iocmatch", params: map[string]any{
				"indicators":   indicators,
				"observations": []any{map[string]any{"name": "access.log", "text": string(b)}},
			}})
		}
	} else {
		log.Printf("skipping log samples: %v", err)
	}
	var items []any
	for _, rel := range []string{"forensics/site-backup.zip", "apk/northwind-field.apk"} {
		b, err := read(rel)
		if err != nil {
			log.Printf("skipping %s: %v", rel, err)
			continue
		}
		items = append(items, map[string]any{"name": filepath.Base(rel), "base64": base64.StdEncoding.EncodeToString(b), "source": "samples/" + rel})
	}
	if len(items) > 0 {
		jobs = append(jobs, job{module: "triage", params: map[string]any{"items": items}})
	}
	if b, err := read("apk/northwind-field.apk"); err == nil {
		jobs = append(jobs, job{module: "apkscan", params: map[string]any{
			"apkBase64": base64.StdEncoding.EncodeToString(b), "name": "northwind-field.apk",
		}})
	}

	for _, j := range jobs {
		req := &aresv1.DispatchJobRequest{EngagementId: id, Module: j.module, Actor: "dev seed", Targets: j.targets}
		if j.params != nil {
			p, err := structpb.NewStruct(j.params)
			if err != nil {
				return fmt.Errorf("%s params: %w", j.module, err)
			}
			req.Params = p
		}
		res, err := c.DispatchJob(ctx, connect.NewRequest(req))
		if err != nil {
			log.Printf("  %-15s not started: %v", j.module, err)
			continue
		}
		log.Printf("  %-15s started (job %s)", j.module, res.Msg.GetJobId())
	}
	return nil
}

// demoEngagementFor finds the demo engagement in the default workspace or
// creates it, then (re)applies its scope and authorization. The scope is the
// loopback practice target only, so no job can leave this machine.
func demoEngagementFor(ctx context.Context, c aresv1connect.ControlPlaneClient) (*aresv1.Engagement, error) {
	list, err := c.ListEngagements(ctx, connect.NewRequest(&aresv1.ListEngagementsRequest{}))
	if err != nil {
		return nil, fmt.Errorf("list engagements: %w", err)
	}
	var eng *aresv1.Engagement
	for _, e := range list.Msg.GetEngagements() {
		if e.GetName() == demoEngagement {
			eng = e
			break
		}
	}
	if eng == nil {
		res, err := c.CreateEngagement(ctx, connect.NewRequest(&aresv1.CreateEngagementRequest{Name: demoEngagement}))
		if err != nil {
			return nil, fmt.Errorf("create engagement: %w", err)
		}
		eng = res.Msg
	}
	if eng.GetStatus() == "draft" || len(eng.GetInScope()) == 0 {
		if _, err := c.SetScope(ctx, connect.NewRequest(&aresv1.SetScopeRequest{
			Id:      eng.GetId(),
			InScope: []string{"127.0.0.1"},
		})); err != nil {
			return nil, fmt.Errorf("set scope: %w", err)
		}
	}
	if eng.GetStatus() != "authorized" {
		res, err := c.Authorize(ctx, connect.NewRequest(&aresv1.AuthorizeRequest{
			Id:         eng.GetId(),
			Document:   "samples/authorization-letter.md",
			ApprovedBy: "Northwind Admin (local practice target)",
		}))
		if err != nil {
			return nil, fmt.Errorf("authorize: %w", err)
		}
		eng = res.Msg
	}
	return eng, nil
}
