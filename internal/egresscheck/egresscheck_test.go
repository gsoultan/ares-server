// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package egresscheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSendsOnlyTokensToConfiguredCanary(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var uas []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.String())
		uas = append(uas, r.UserAgent())
		mu.Unlock()
		if r.ContentLength > 0 {
			t.Errorf("request carried a body")
		}
	}))
	defer srv.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		if _, err := p.Start(buf[:n]); err != nil {
			return
		}
		q, _ := p.Question()
		got <- q.Name.String()
	}()

	s := New(Config{CanaryDomain: "oast.ares.example", CanaryBases: []string{srv.URL}, DNSServer: pc.LocalAddr().String()})
	s.timeout = 300 * time.Millisecond
	tok := "abcdef0123456789"
	outs, err := s.Send(context.Background(), []Token{
		{Channel: TCPHigh, Token: tok, URL: srv.URL + "/c/" + tok},
		{Channel: TCPHigh, Token: tok + "x", URL: srv.URL + "/c/" + tok + "x"},       // second on same channel
		{Channel: HTTPSDirect, Token: tok, URL: "https://attacker.example/c/" + tok}, // not a canary base
		{Channel: TCPHigh + "z", Token: tok},                                         // unknown channel
		{Channel: DNSDirect, Token: tok, Name: tok + ".oast.ares.example"},           // ok
		{Channel: DoH, Token: tok, Name: tok + ".oast.ares.example"},                 // no DoH configured
		{Channel: HTTPSAltPort, Token: "bad token!", URL: srv.URL + "/c/bad"},        // malformed
	})
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	for _, o := range outs {
		if o.Sent {
			sent++
		}
	}
	if sent != 2 {
		t.Fatalf("sent %d, want 2: %+v", sent, outs)
	}
	if len(paths) != 1 || paths[0] != "/c/"+tok || uas[0] != userAgent {
		t.Errorf("http requests=%v uas=%v", paths, uas)
	}
	if name := <-got; !strings.HasPrefix(name, tok+".oast.ares.example") {
		t.Errorf("dns name=%q", name)
	}
	for _, o := range outs[1:4] {
		if o.Refused == "" {
			t.Errorf("expected refusal: %+v", o)
		}
	}
}

func TestUnconfiguredAgentSendsNothing(t *testing.T) {
	if _, err := New(Config{}).Send(context.Background(), []Token{{Channel: TCPHigh, Token: "abcdef0123456789"}}); err != ErrNotConfigured {
		t.Fatalf("err=%v", err)
	}
}
