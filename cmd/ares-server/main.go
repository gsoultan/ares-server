// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Command ares-server is the Ares control plane. In step 1 it also embeds the
// worker pool, so one binary runs the whole platform: it holds engagements and
// their permission gates, dispatches jobs, runs them through the registered
// modules, and exposes the audit trail. Workers move to their own process in a
// later step behind the same queue interface.
package main

import (
	"compress/gzip"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/gsoultan/ares-server/internal/agent"
	"github.com/gsoultan/ares-server/internal/api"
	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/connectapi"
	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares-server/internal/setup"
	"github.com/gsoultan/ares-server/internal/store/pgstore"
	"github.com/gsoultan/ares-server/internal/store/stormstore"
	"github.com/gsoultan/ares-server/internal/worker"
	"github.com/gsoultan/ares/canary"
	"github.com/gsoultan/ares/engine"
)

func main() {
	setMemoryLimit()

	addr := os.Getenv("ARES_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// The out-of-band collaborator: a listener that records when a target calls
	// back to a unique Ares URL, which confirms SSRF and other blind weaknesses
	// by observation. Targets must be able to reach it, so set ARES_CANARY_URL to
	// a publicly reachable base URL in a real deployment; it defaults to the
	// local listen address for development.
	canaryStore := canary.NewStore()
	canaryBase := os.Getenv("ARES_CANARY_URL")
	if canaryBase == "" {
		port := addr
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			port = addr[i+1:]
		}
		canaryBase = "http://127.0.0.1:" + port
	}
	// Name-resolution weaknesses (Log4Shell JNDI lookups) are confirmed by a DNS
	// query under a canary domain. Set ARES_CANARY_DOMAIN to a domain whose
	// nameserver points at this process, and ARES_CANARY_DNS_ADDR to the UDP
	// address to listen on; without both, log4shellprobe stays inert.
	canaryDomain := os.Getenv("ARES_CANARY_DOMAIN")
	canaryDNSAddr := os.Getenv("ARES_CANARY_DNS_ADDR")

	// The engine: every module, registered and wired, from the ares library.
	// Each module re-checks the engagement's permission gate per target.
	reg, err := engine.New(engine.Options{
		CanaryStore:  canaryStore,
		CanaryBase:   canaryBase,
		CanaryDomain: canaryDomain,
	})
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	// Persistence: Storm (bbolt) by default, so engagements, scope,
	// authorization and the audit trail survive a restart. Set ARES_DB=memory
	// for an ephemeral in-memory run (tests, demos).
	var store engagement.Store
	var settingsRepo settings.Repo
	var userStore auth.UserStore
	var sessionStore auth.SessionStore
	var setupStore setup.Store
	var outcomeBackend worker.OutcomeBackend // nil: in-memory outcomes (ARES_DB=memory)
	dbPath := os.Getenv("ARES_DB")
	if dbPath == "" {
		// ARES_PG_URL is the dedicated Postgres DSN (what the dev script exports);
		// it is a convenience alias for ARES_DB set to that DSN.
		if pg := os.Getenv("ARES_PG_URL"); pg != "" {
			dbPath = pg
		} else {
			dbPath = "ares.db"
		}
	}
	switch {
	case dbPath == "memory":
		store = engagement.NewMemStore()
		settingsRepo = settings.NewMemRepo()
		userStore = auth.NewMemUserStore()
		sessionStore = auth.NewMemSessionStore()
		setupStore = setup.NewMemStore()
		log.Print("ares store: in-memory (ephemeral)")
	case isPostgresDSN(dbPath):
		ps, err := pgstore.Open(dbPath)
		if err != nil {
			log.Fatalf("open store: %v", err)
		}
		defer ps.Close()
		store = ps
		settingsRepo = ps.Settings()
		userStore = ps.Users()
		sessionStore = ps.Sessions()
		setupStore = ps.Setup()
		outcomeBackend = ps.Outcomes()
		log.Print("ares store: postgres")
	default:
		ss, err := stormstore.Open(dbPath)
		if err != nil {
			log.Fatalf("open store: %v", err)
		}
		defer ss.Close()
		store = ss
		settingsRepo = ss.Settings()
		userStore = ss.Users()
		sessionStore = ss.Sessions()
		setupStore = ss.Setup()
		outcomeBackend = ss.Outcomes()
		log.Printf("ares store: storm at %s", dbPath)
	}

	// Authentication: built-in email + password with server-side sessions,
	// available whether or not setup has run (so the super-admin can log in right
	// after setup).
	//
	// Sessions and accounts are read through a seconds-long in-process cache:
	// every request authenticates, and against Postgres that was a round trip
	// (two with the per-request account check) before any handler ran. Writes
	// through the service evict at once, so logout, disable and role changes
	// still apply on the next request; the TTL only bounds how long a change
	// made by another server process can take to be seen.
	// ARES_AUTH_CACHE_TTL sets it (e.g. "5s"); "0" or "off" disables the cache.
	rawSessions := sessionStore
	if ttl, on := authCacheTTL(os.Getenv("ARES_AUTH_CACHE_TTL")); on {
		userStore = auth.CachedUsers(userStore, ttl)
		sessionStore = auth.CachedSessions(sessionStore, ttl)
	}
	authSvc := auth.NewService(userStore, sessionStore)

	// The in-app settings store needs the master encryption key to seal and open
	// provider credentials. Before first-run setup there is no key, so the
	// settings RPCs report the store as unavailable until one exists; after setup
	// (or with ARES_MASTER_KEY / an ARES_KEY_FILE), settings come online.
	var settingsSvc *settings.Service
	if sealer, err := loadSealer(); err != nil {
		log.Fatalf("load master key: %v", err)
	} else if sealer != nil {
		settingsSvc = settings.NewService(sealer, settingsRepo)
		log.Print("ares settings: in-app store enabled (secrets sealed at rest)")
	} else {
		log.Print("ares settings: no master key yet; configure via first-run setup")
	}

	q := queue.New(256)
	// Job outcomes: persisted (compressed) when there is a datastore, so results
	// and findings survive a restart, with a bounded in-memory cache of recently
	// used engagements' outcomes (ARES_OUTCOME_CACHE_RESULTS, in results).
	var outcomes worker.OutcomeStore = worker.NewMemOutcomes()
	if outcomeBackend != nil {
		maxResults, _ := strconv.Atoi(os.Getenv("ARES_OUTCOME_CACHE_RESULTS"))
		po, err := worker.NewPersistentOutcomes(outcomeBackend, maxResults)
		if err != nil {
			log.Fatalf("load job outcomes: %v", err)
		}
		outcomes = po
	}
	proc := worker.NewProcessor(reg, store)
	pool := worker.NewPool(proc, outcomes, 8)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go pool.Run(ctx, q.C())

	// Reclaim sessions nobody will present again (they were never deleted).
	if sw, ok := rawSessions.(auth.ExpiredSweeper); ok {
		go auth.SweepExpiredSessions(ctx, sw, 15*time.Minute)
	}

	// Opt-in profiling on its own listener (keep it on loopback): set
	// ARES_PPROF_ADDR=127.0.0.1:6060 and use `go tool pprof`. It is never mounted
	// on the public mux.
	if pprofAddr := os.Getenv("ARES_PPROF_ADDR"); pprofAddr != "" {
		go servePprof(pprofAddr)
	}

	// Start the DNS collaborator when a domain and listen address are both set,
	// so Log4Shell-style lookups can be observed. It is optional: without it,
	// log4shellprobe simply finds nothing.
	if canaryDomain != "" && canaryDNSAddr != "" {
		if pc, err := net.ListenPacket("udp", canaryDNSAddr); err != nil {
			log.Printf("canary DNS collaborator disabled (listen %s: %v)", canaryDNSAddr, err)
		} else {
			collab := canary.NewDNSCollaborator(canaryStore, canaryDomain)
			go func() { _ = collab.Serve(ctx, pc) }()
			log.Printf("ares DNS collaborator on %s for *.%s", canaryDNSAddr, canaryDomain)
		}
	}

	// One core, two surfaces. The gRPC handler (connect-go, serving gRPC,
	// gRPC-Web and the Connect protocol) and the REST handler share the same
	// store, registry, queue and outcome store, so the permission gate and the
	// audit trail are identical whichever surface a client uses.
	grpcHandler := connectapi.New(store, reg, q, outcomes)
	grpcHandler.WithAuth(authSvc)
	// Agent registry: an agent may act only while its engagement can run. The
	// operator-facing agent-management RPCs are served on the ControlPlane; the
	// agent-facing AgentService is wired separately.
	agentReg := agent.NewRegistry(func(tenantID, engagementID string) bool {
		eng, ok := store.Get(engagementID)
		if !ok || eng.TenantID != engagement.ResolveTenant(tenantID) {
			return false
		}
		runnable, _ := eng.CanRun()
		return runnable
	})
	grpcHandler.WithAgents(agentReg)
	// Egress proof (M-25): tokens for the agent's egresscheck capability. Set
	// ARES_CANARY_ALT_URL / ARES_CANARY_HIGH_URL to collaborator listeners on a
	// non-standard HTTPS port and a high plain-HTTP port to test those channels.
	grpcHandler.WithEgressCanary(canaryStore, canaryBase, canaryDomain, os.Getenv("ARES_CANARY_ALT_URL"), os.Getenv("ARES_CANARY_HIGH_URL"))
	if settingsSvc != nil {
		grpcHandler.WithSettings(settingsSvc)
	}

	// First-run setup. On a successful commit it writes the sealed master key and
	// brings the settings store online without a restart (onKey).
	keyPath := os.Getenv("ARES_KEY_FILE")
	if keyPath == "" {
		keyPath = "ares.key"
	}
	onKey := func(key []byte) {
		sealer, err := secret.NewSealer(key)
		if err != nil {
			log.Printf("setup: install master key failed: %v", err)
			return
		}
		grpcHandler.WithSettings(settings.NewService(sealer, settingsRepo))
		log.Print("ares settings: enabled after first-run setup")
	}
	activeDriver := setup.DriverFile
	if isPostgresDSN(dbPath) {
		activeDriver = setup.DriverPostgres
	}
	grpcHandler.WithSetup(setup.NewService(setupStore, authSvc, store, dbPath, keyPath, onKey).WithActiveDriver(activeDriver))
	// Bound the request body so an unbounded upload cannot exhaust memory. The
	// ceiling sits well above the largest module intake (256 MiB decoded, ~341
	// MiB base64-encoded in the request), leaving headroom; override with
	// ARES_MAX_REQUEST_BYTES. The modules enforce their own per-item ceilings on
	// top of this.
	maxReqBytes := int64(512 << 20)
	if v := os.Getenv("ARES_MAX_REQUEST_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxReqBytes = n
		} else {
			log.Printf("ignoring invalid ARES_MAX_REQUEST_BYTES=%q", v)
		}
	}
	// Authenticate bearer tokens and enforce per-tenant isolation on every
	// control-plane RPC. In the default "auto" mode this activates once first-run
	// setup has created an account; ARES_REQUIRE_AUTH=on|off overrides.
	authInterceptor := connectapi.NewAuthInterceptor(authSvc, connectapi.ParseEnforceMode(os.Getenv("ARES_REQUIRE_AUTH")))
	grpcPath, grpcHTTP := aresv1connect.NewControlPlaneHandler(grpcHandler,
		connect.WithReadMaxBytes(int(maxReqBytes)),
		connect.WithInterceptors(authInterceptor),
		compressionOption(os.Getenv("ARES_COMPRESSION")),
		connect.WithCompressMinBytes(1024))

	mux := http.NewServeMux()
	mux.Handle(grpcPath, grpcHTTP)
	// The agent-facing AgentService is served on its own endpoint behind the
	// agent-credential interceptor (outbound-initiated by enrolled agents).
	agentCred := connectapi.NewAgentCredentialInterceptor(agentReg)
	agentPath, agentHTTP := aresv1connect.NewAgentServiceHandler(
		connectapi.NewAgentServer(agentReg, store, outcomes),
		connect.WithReadMaxBytes(int(maxReqBytes)),
		connect.WithInterceptors(agentCred))
	mux.Handle(agentPath, agentHTTP)
	// The collaborator records out-of-band callbacks under /c/; the more specific
	// pattern takes precedence over the REST catch-all at "/".
	mux.Handle("/c/", canaryStore.Handler())
	// The legacy REST surface predates multi-tenant auth, so it is gated behind
	// the same bearer-token authentication and per-tenant isolation as the
	// gRPC/Connect path (sharing the interceptor's enforcement latch). /healthz
	// stays open for liveness probes.
	mux.Handle("/", authInterceptor.RESTMiddleware(api.New(store, reg, q, outcomes).Routes()))

	// h2c lets plaintext HTTP/2 through, which true gRPC needs; behind TLS this
	// is ordinary gRPC. REST and Connect also work over HTTP/1.1 on the same port.
	// Idle keep-alive connections are closed after two minutes: with thousands
	// of clients, each idle connection otherwise pins its buffers and goroutine
	// for as long as the client keeps it open. Read/write timeouts stay unset
	// on purpose, since large evidence uploads and report downloads are
	// legitimately slow.
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           h2c.NewHandler(mux, &http2.Server{IdleTimeout: 2 * time.Minute}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutCtx)
	}()

	log.Printf("ares control plane listening on %s (modules: %v)", addr, reg.Names())
	log.Printf("ares out-of-band collaborator at %s/c/ (set ARES_CANARY_URL for a public address)", canaryBase)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
	log.Print("ares shut down")
}

// loadSealer resolves the master encryption key for the settings store, in
// order: the ARES_MASTER_KEY environment variable (base64), then the key file at
// ARES_KEY_FILE (default "ares.key") when it exists. It returns (nil, nil) when
// no key is configured yet, so the server starts and first-run setup can create
// one; any configured-but-invalid key is a hard error.
func loadSealer() (*secret.Sealer, error) {
	if enc := os.Getenv("ARES_MASTER_KEY"); enc != "" {
		key, err := secret.DecodeKey(enc)
		if err != nil {
			return nil, err
		}
		return secret.NewSealer(key)
	}
	path := os.Getenv("ARES_KEY_FILE")
	if path == "" {
		path = "ares.key"
	}
	if _, err := os.Stat(path); err == nil {
		return secret.SealerFromFile(path)
	}
	return nil, nil
}

// isPostgresDSN reports whether an ARES_DB value names a PostgreSQL database
// rather than a local Storm file. Anything else is treated as a file path.
func isPostgresDSN(v string) bool {
	return strings.HasPrefix(v, "postgres://") || strings.HasPrefix(v, "postgresql://")
}

// servePprof serves the runtime profiles on a dedicated listener.
func servePprof(addr string) {
	m := http.NewServeMux()
	m.HandleFunc("/debug/pprof/", pprof.Index)
	m.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	m.HandleFunc("/debug/pprof/profile", pprof.Profile)
	m.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	m.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: addr, Handler: m, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("ares pprof on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("pprof: %v", err)
	}
}

// compressionOption picks how control-plane responses are compressed.
// Compression was a third of the server's CPU under load (gzip at the default
// level on every response, however small), so the default is the fastest gzip
// level, which keeps most of the size win at a fraction of the cost, and
// responses under 1 KiB are sent as they are. ARES_COMPRESSION=off turns
// response compression off entirely (the cheapest choice when clients sit on
// the same LAN or a TLS proxy compresses); "default" restores gzip's default
// level.
func compressionOption(mode string) connect.HandlerOption {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off", "none":
		return connect.WithCompression("gzip", nil, nil)
	case "default":
		return connect.WithCompression("gzip", newGzipReader, func() connect.Compressor { return gzip.NewWriter(io.Discard) })
	default:
		return connect.WithCompression("gzip", newGzipReader, newFastGzipWriter)
	}
}

// newFastGzipWriter compresses responses at gzip.BestSpeed. connect pools the
// writers, so the constructor's allocation is paid once per pooled writer.
func newFastGzipWriter() connect.Compressor {
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed) // a valid level never errors
	return w
}

// newGzipReader decompresses gzip request bodies (as connect's default does).
func newGzipReader() connect.Decompressor { return &gzip.Reader{} }

// authCacheTTL parses ARES_AUTH_CACHE_TTL: empty means the default, "0" or
// "off" turns the cache off, anything else is a Go duration.
func authCacheTTL(v string) (time.Duration, bool) {
	switch v = strings.TrimSpace(strings.ToLower(v)); v {
	case "":
		return auth.DefaultCacheTTL, true
	case "0", "off", "none":
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("ignoring invalid ARES_AUTH_CACHE_TTL=%q", v)
		return auth.DefaultCacheTTL, true
	}
	return d, true
}

// setMemoryLimit gives the Go runtime a soft memory limit when none is set:
// 90% of the container's cgroup memory limit, if there is one. The garbage
// collector then works harder as the heap nears the limit instead of letting
// it grow until the container is OOM-killed, so the server can run in a small
// memory allowance. GOMEMLIMIT, when set, wins (the runtime reads it itself).
func setMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	for _, f := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil || n <= 0 || n > 1<<50 { // "max" or an unlimited sentinel
			return
		}
		limit := n / 10 * 9
		debug.SetMemoryLimit(limit)
		log.Printf("ares memory: soft limit %d MiB (90%% of the container's %d MiB)", limit>>20, n>>20)
		return
	}
}
