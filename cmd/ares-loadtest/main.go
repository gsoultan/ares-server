// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Command ares-loadtest drives a running ares-server with many concurrent
// signed-in operators and reports throughput, latency per RPC, and (with -pid)
// the server's CPU time and peak memory. It only talks to the control plane;
// it never dispatches a job, so it touches no target.
//
//	ares-loadtest -api http://127.0.0.1:8080 -email admin@example.test \
//	    -password '...' -users 2000 -duration 60s -think 1s -pid $(pgrep ares-server)
//
// Each virtual user holds its own session and loops over the reads the web UI
// makes while someone works an engagement (engagement list and detail, jobs,
// findings, risk card, audit trail, current user), pausing -think between
// page loads. A small share of iterations write (a finding-status change),
// which appends to the audit trail and saves the engagement.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/gen/ares/v1/aresv1connect"
)

type bearer struct{ token string }

func (b bearer) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+b.token)
		return next(ctx, req)
	}
}
func (bearer) WrapStreamingClient(n connect.StreamingClientFunc) connect.StreamingClientFunc {
	return n
}
func (bearer) WrapStreamingHandler(n connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return n
}

// stats keeps every latency per RPC; a run of a few minutes is a few million
// samples, which is fine to sort at the end.
type stats struct {
	mu   sync.Mutex
	lat  map[string][]time.Duration
	errs map[string]int
	ok   atomic.Int64
}

func (s *stats) add(name string, d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.errs[name+": "+short(err)]++
		return
	}
	s.ok.Add(1)
	s.lat[name] = append(s.lat[name], d)
}

func short(err error) string {
	m := err.Error()
	if len(m) > 80 {
		m = m[:80]
	}
	return m
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	return d[int(float64(len(d)-1)*p)]
}

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "control-plane base URL")
	email := flag.String("email", "", "account to sign in with")
	password := flag.String("password", "", "its password")
	users := flag.Int("users", 1000, "concurrent virtual users (one session each)")
	duration := flag.Duration("duration", 60*time.Second, "how long to run after every user has signed in")
	think := flag.Duration("think", time.Second, "mean pause between one user's page loads (0 = closed loop)")
	writePct := flag.Float64("writes", 0.02, "share of iterations that change a finding's status")
	loginPar := flag.Int("login-concurrency", 8, "sign-ins in flight while the users ramp up")
	pid := flag.Int("pid", 0, "server pid, to report its CPU time and peak memory (Linux)")
	flag.Parse()
	if *email == "" || *password == "" {
		log.Fatal("-email and -password are required")
	}

	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        *users + 16,
		MaxIdleConnsPerHost: *users + 16,
		IdleConnTimeout:     90 * time.Second,
	}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	anon := aresv1connect.NewControlPlaneClient(hc, *api)

	// Ramp: sign every user in (each gets its own session).
	ctx := context.Background()
	clients := make([]aresv1connect.ControlPlaneClient, *users)
	tokens := make([]string, *users)
	st := &stats{lat: map[string][]time.Duration{}, errs: map[string]int{}}
	sem := make(chan struct{}, *loginPar)
	var wg sync.WaitGroup
	cpu0, _ := procCPU(*pid)
	rampStart := time.Now()
	for i := range clients {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			t := time.Now()
			res, err := anon.Login(ctx, connect.NewRequest(&aresv1.LoginRequest{Email: *email, Password: *password}))
			if err == nil && !res.Msg.GetOk() {
				err = errors.New("login refused: " + res.Msg.GetError())
			}
			st.add("Login", time.Since(t), err)
			if err != nil {
				return
			}
			tokens[i] = res.Msg.GetToken()
			clients[i] = aresv1connect.NewControlPlaneClient(hc, *api, connect.WithInterceptors(bearer{tokens[i]}))
		}(i)
	}
	wg.Wait()
	ramp := time.Since(rampStart)
	cpuRamp, _ := procCPU(*pid)
	log.Printf("signed in %d users in %s (server CPU %.1fs)", *users, ramp.Round(time.Millisecond), cpuRamp-cpu0)

	// Discover what to read: the workspace's engagements and their jobs.
	var first aresv1connect.ControlPlaneClient
	for _, c := range clients {
		if c != nil {
			first = c
			break
		}
	}
	if first == nil {
		log.Fatal("no user signed in")
	}
	list, err := first.ListEngagements(ctx, connect.NewRequest(&aresv1.ListEngagementsRequest{}))
	if err != nil || len(list.Msg.GetEngagements()) == 0 {
		log.Fatalf("need at least one engagement to read (seed with ares-devseed): %v", err)
	}
	var engIDs []string
	jobsByEng := map[string][]string{}
	for _, e := range list.Msg.GetEngagements() {
		engIDs = append(engIDs, e.GetId())
		if jl, err := first.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: e.GetId()})); err == nil {
			for _, j := range jl.Msg.GetJobs() {
				jobsByEng[e.GetId()] = append(jobsByEng[e.GetId()], j.GetJobId())
			}
		}
	}
	var findingIDs []string
	if fl, err := first.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{})); err == nil {
		for _, f := range fl.Msg.GetFindings() {
			findingIDs = append(findingIDs, f.GetId())
		}
	}

	// Steady state.
	cpu1, _ := procCPU(*pid)
	start := time.Now()
	deadline := start.Add(*duration)
	stop := make(chan struct{})
	var peakRSS atomic.Int64
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if r, err := procRSS(*pid); err == nil && r > peakRSS.Load() {
					peakRSS.Store(r)
				}
			}
		}
	}()
	statuses := []string{"open", "in_progress", "fixed"}
	for i, c := range clients {
		if c == nil {
			continue
		}
		wg.Add(1)
		go func(i int, c aresv1connect.ControlPlaneClient) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(i), 7))
			call := func(name string, f func() error) {
				t := time.Now()
				err := f()
				st.add(name, time.Since(t), err)
			}
			// Spread the first page load over one think interval.
			if *think > 0 {
				time.Sleep(time.Duration(r.Int64N(int64(*think))))
			}
			for time.Now().Before(deadline) {
				eng := engIDs[r.IntN(len(engIDs))]
				call("ListEngagements", func() error {
					_, err := c.ListEngagements(ctx, connect.NewRequest(&aresv1.ListEngagementsRequest{}))
					return err
				})
				call("GetEngagement", func() error {
					_, err := c.GetEngagement(ctx, connect.NewRequest(&aresv1.GetEngagementRequest{Id: eng}))
					return err
				})
				call("ListJobs", func() error {
					_, err := c.ListJobs(ctx, connect.NewRequest(&aresv1.ListJobsRequest{EngagementId: eng}))
					return err
				})
				if js := jobsByEng[eng]; len(js) > 0 {
					job := js[r.IntN(len(js))]
					call("GetJob", func() error {
						_, err := c.GetJob(ctx, connect.NewRequest(&aresv1.GetJobRequest{JobId: job}))
						return err
					})
				}
				call("ListFindings", func() error {
					_, err := c.ListFindings(ctx, connect.NewRequest(&aresv1.ListFindingsRequest{}))
					return err
				})
				call("GetRiskPicture", func() error {
					_, err := c.GetRiskPicture(ctx, connect.NewRequest(&aresv1.GetRiskPictureRequest{Id: eng}))
					return err
				})
				if r.Float64() < 0.2 {
					call("GetAudit", func() error {
						_, err := c.GetAudit(ctx, connect.NewRequest(&aresv1.GetAuditRequest{Id: eng}))
						return err
					})
				}
				call("CurrentUser", func() error {
					_, err := c.CurrentUser(ctx, connect.NewRequest(&aresv1.CurrentUserRequest{Token: tokens[i]}))
					return err
				})
				if len(findingIDs) > 0 && r.Float64() < *writePct {
					fid := findingIDs[r.IntN(len(findingIDs))]
					call("SetFindingStatus", func() error {
						_, err := c.SetFindingStatus(ctx, connect.NewRequest(&aresv1.SetFindingStatusRequest{
							Id: fid, Status: statuses[r.IntN(len(statuses))], Actor: "loadtest"}))
						return err
					})
				}
				if *think > 0 {
					// Exponential think time around the mean, like real people.
					time.Sleep(time.Duration(r.ExpFloat64() * float64(*think)))
				}
			}
		}(i, c)
	}
	wg.Wait()
	close(stop)
	elapsed := time.Since(start)
	cpu2, _ := procCPU(*pid)

	// Report.
	fmt.Printf("\n%d users, %s steady state, think %s\n", *users, elapsed.Round(time.Millisecond), *think)
	fmt.Printf("throughput: %.0f req/s (%d ok)\n", float64(st.ok.Load())/elapsed.Seconds(), st.ok.Load())
	if *pid > 0 {
		fmt.Printf("server CPU: %.2f cores avg during steady state; peak RSS %.1f MiB\n",
			(cpu2-cpu1)/elapsed.Seconds(), float64(peakRSS.Load())/(1<<20))
	}
	names := make([]string, 0, len(st.lat))
	for n := range st.lat {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Printf("%-18s %9s %9s %9s %9s %9s\n", "rpc", "count", "p50", "p95", "p99", "max")
	var all []time.Duration
	for _, n := range names {
		d := st.lat[n]
		sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
		if n != "Login" {
			all = append(all, d...)
		}
		fmt.Printf("%-18s %9d %9s %9s %9s %9s\n", n, len(d), r(pct(d, .5)), r(pct(d, .95)), r(pct(d, .99)), r(d[len(d)-1]))
	}
	sort.Slice(all, func(a, b int) bool { return all[a] < all[b] })
	if len(all) > 0 {
		fmt.Printf("%-18s %9d %9s %9s %9s %9s\n", "ALL (excl. login)", len(all), r(pct(all, .5)), r(pct(all, .95)), r(pct(all, .99)), r(all[len(all)-1]))
	}
	if len(st.errs) > 0 {
		fmt.Println("errors:")
		for k, v := range st.errs {
			fmt.Printf("  %6d  %s\n", v, k)
		}
	}
}

func r(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(time.Millisecond).String()
	case d >= time.Millisecond:
		return d.Round(10 * time.Microsecond).String()
	default:
		return d.Round(time.Microsecond).String()
	}
}

// procCPU returns the process's user+system CPU seconds from /proc.
func procCPU(pid int) (float64, error) {
	if pid <= 0 {
		return 0, errors.New("no pid")
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	ut, _ := strconv.ParseFloat(f[11], 64)
	stt, _ := strconv.ParseFloat(f[12], 64)
	return (ut + stt) / 100, nil // USER_HZ
}

// procRSS returns the process's resident set size in bytes.
func procRSS(pid int) (int64, error) {
	if pid <= 0 {
		return 0, errors.New("no pid")
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			kb, _ := strconv.ParseInt(strings.Fields(l)[1], 10, 64)
			return kb << 10, nil
		}
	}
	return 0, errors.New("no VmRSS")
}
