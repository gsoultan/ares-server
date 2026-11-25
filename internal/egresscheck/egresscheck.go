// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package egresscheck is the agent-side sender for the egress proof (M-25 in
// the ares repository's docs/detection-scenarios-malware-botnet.md).
//
// The server mints one Ares canary token per channel. The agent sends exactly
// one benign request per channel carrying only that token, and the ares
// egressproof module later reads which tokens reached the collaborator. Every
// destination is fixed by the agent's own install configuration (the Ares
// canary domain and base URLs, and an optional resolver and DoH endpoint the
// installer names): a task can choose which tokens to send, never where they
// go. No host data, no payload and no file is ever sent, and no connection is
// kept open.
package egresscheck

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Channel names, matching ares egressproof.
const (
	DNSDirect    = "dns-direct"
	DoH          = "doh"
	HTTPSDirect  = "https-direct"
	HTTPSAltPort = "https-alt-port"
	TCPHigh      = "tcp-high"
)

// Token is one planned send, as the server issues it.
type Token struct {
	Channel string `json:"channel"`
	Token   string `json:"token"`
	Name    string `json:"name,omitempty"` // DNS channels
	URL     string `json:"url,omitempty"`  // HTTP channels
}

// Config is the agent's install-time egress configuration. Only these
// destinations can ever be contacted.
type Config struct {
	CanaryDomain string   // e.g. oast.ares.example (DNS names must sit under it)
	CanaryBases  []string // Ares collaborator base URLs (any port)
	DNSServer    string   // host:port of an external resolver for dns-direct
	DoHURL       string   // RFC 8484 endpoint for doh
}

// Outcome records what the agent did with one token.
type Outcome struct {
	Channel string    `json:"channel"`
	Token   string    `json:"token"`
	SentAt  time.Time `json:"sentAt,omitempty"`
	Sent    bool      `json:"sent"`
	Error   string    `json:"error,omitempty"` // local failure, e.g. connection refused (blocked)
	Refused string    `json:"refused,omitempty"`
}

// ErrNotConfigured is returned when the agent has no canary configuration.
var ErrNotConfigured = errors.New("egresscheck: agent has no canary domain or base configured")

const userAgent = "ares-egress-check/1"

var tokenRe = func(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// Sender sends planned tokens.
type Sender struct {
	cfg     Config
	timeout time.Duration
	// dial and httpDo are replaceable in tests.
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	client *http.Client
}

// New builds a sender. Proxies are disabled on purpose: the check measures
// what leaves the host directly.
func New(cfg Config) *Sender {
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{Proxy: nil, DialContext: d.DialContext, TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true, ResponseHeaderTimeout: 5 * time.Second}
	return &Sender{cfg: cfg, timeout: 8 * time.Second, dial: d.DialContext,
		client: &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Send validates and sends each token once.
func (s *Sender) Send(ctx context.Context, tokens []Token) ([]Outcome, error) {
	if s.cfg.CanaryDomain == "" && len(s.cfg.CanaryBases) == 0 {
		return nil, ErrNotConfigured
	}
	seen := map[string]bool{}
	var out []Outcome
	for _, t := range tokens {
		o := Outcome{Channel: t.Channel, Token: t.Token}
		if seen[t.Channel] {
			o.Refused = "one request per channel"
			out = append(out, o)
			continue
		}
		if err := s.validate(t); err != nil {
			o.Refused = err.Error()
			out = append(out, o)
			continue
		}
		seen[t.Channel] = true
		o.SentAt = time.Now().UTC()
		var err error
		switch t.Channel {
		case DNSDirect:
			err = s.sendDNS(ctx, t.Name)
		case DoH:
			err = s.sendDoH(ctx, t.Name)
		default:
			err = s.sendHTTP(ctx, t.URL)
		}
		o.Sent = true
		if err != nil {
			o.Error = err.Error()
		}
		out = append(out, o)
	}
	return out, nil
}

func (s *Sender) validate(t Token) error {
	if !tokenRe(t.Token) {
		return errors.New("malformed token")
	}
	switch t.Channel {
	case DNSDirect, DoH:
		d := strings.TrimSuffix(strings.ToLower(s.cfg.CanaryDomain), ".")
		if d == "" {
			return errors.New("no canary domain configured on this agent")
		}
		if strings.ToLower(t.Name) != strings.ToLower(t.Token)+"."+d {
			return errors.New("name is not <token>.<canary domain>")
		}
		if t.Channel == DNSDirect && s.cfg.DNSServer == "" {
			return errors.New("no external resolver configured on this agent")
		}
		if t.Channel == DoH && s.cfg.DoHURL == "" {
			return errors.New("no DoH endpoint configured on this agent")
		}
	case HTTPSDirect, HTTPSAltPort, TCPHigh:
		u, err := url.Parse(t.URL)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("malformed URL")
		}
		if u.Path != "/c/"+t.Token {
			return errors.New("URL path is not /c/<token>")
		}
		ok := false
		for _, b := range s.cfg.CanaryBases {
			bu, err := url.Parse(b)
			if err == nil && strings.EqualFold(bu.Scheme, u.Scheme) && strings.EqualFold(bu.Host, u.Host) {
				ok = true
			}
		}
		if !ok {
			return errors.New("destination is not an Ares canary base configured on this agent")
		}
		if t.Channel != TCPHigh && u.Scheme != "https" {
			return errors.New("HTTPS channel needs an https URL")
		}
	default:
		return fmt.Errorf("unknown channel %q", t.Channel)
	}
	return nil
}

func query(name string) ([]byte, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(idb[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

func (s *Sender) sendDNS(ctx context.Context, name string) error {
	q, err := query(name)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := s.dial(cctx, "udp", s.cfg.DNSServer)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 512)
	_, err = conn.Read(buf) // the answer is not needed; the canary records the query
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil // sent; no reply is fine
		}
	}
	return nil
}

func (s *Sender) sendDoH(ctx context.Context, name string) error {
	q, err := query(name)
	if err != nil {
		return err
	}
	u := s.cfg.DoHURL + "?dns=" + base64.RawURLEncoding.EncodeToString(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", userAgent)
	return s.do(req)
}

func (s *Sender) sendHTTP(ctx context.Context, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	return s.do(req)
}

func (s *Sender) do(req *http.Request) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.Body.Close()
}
