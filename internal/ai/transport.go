// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// newHTTPClient builds the client every provider uses. Unlike the offensive
// probes, TLS verification is left ON: these are calls to the operator's own
// trusted AI endpoint, not to a target. The proxy is taken from the environment
// so deployments behind an egress proxy work unchanged.
func newHTTPClient(timeout time.Duration, restrictPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if restrictPrivate && !AllowPrivateEndpoints() {
		// Checked on the resolved address at connect time, so DNS rebinding
		// cannot slip an internal address past the up-front endpoint check. The
		// configured egress proxy itself stays reachable.
		proxies := proxyIPs()
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return ErrPrivateEndpoint
			}
			if proxies[ip.String()] {
				return nil
			}
			if isInternalIP(ip) {
				return ErrPrivateEndpoint
			}
			return nil
		}
	}
	return &http.Client{
		Timeout: timeout,
		// Never follow a redirect to another host with the provider key attached.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

// postJSON marshals body, POSTs it with the given headers, and returns the
// response bytes. On a non-2xx status it returns an *APIError carrying the
// provider's own error text (extracted from the common error shapes) — never
// the request, the headers or the API key.
func postJSON(ctx context.Context, client *http.Client, provider, url string, headers map[string]string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Provider: provider, Status: resp.StatusCode, Message: extractError(data, resp.StatusCode)}
	}
	return data, nil
}

// extractError pulls a human-readable message out of the common provider error
// shapes without exposing anything sensitive.
func extractError(data []byte, status int) string {
	// { "error": { "message": "..." } }  (OpenAI/Azure)
	// { "error": { "message": "...", "type": "..." } } (Anthropic)
	// { "error": "..." }
	// { "message": "..." } (some gateways)
	var probe struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal(data, &probe); err == nil {
		if len(probe.Error) > 0 {
			var obj struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code"`
				Status  string `json:"status"`
			}
			if json.Unmarshal(probe.Error, &obj) == nil && obj.Message != "" {
				return obj.Message
			}
			var s string
			if json.Unmarshal(probe.Error, &s) == nil && s != "" {
				return s
			}
		}
		if probe.Message != "" {
			return probe.Message
		}
	}
	// Fall back to a short, bounded snippet of the body.
	snippet := strings.TrimSpace(string(data))
	if len(snippet) > 300 {
		snippet = snippet[:300] + "…"
	}
	if snippet == "" {
		return "API returned status " + itoa(status)
	}
	return snippet
}
