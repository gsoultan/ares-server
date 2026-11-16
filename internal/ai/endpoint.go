// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package ai

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// EnvAllowPrivateEndpoints, set to "on", lets workspace settings point the AI
// advisor at internal addresses and plain http (a self-hosted model on the
// LAN). Off by default: a workspace member must not be able to aim the server
// at its internal network or cloud metadata service.
const EnvAllowPrivateEndpoints = "ARES_AI_ALLOW_PRIVATE_ENDPOINTS"

// ErrPrivateEndpoint is returned when a workspace-supplied AI endpoint resolves
// to an internal address.
var ErrPrivateEndpoint = errors.New("ai: endpoint resolves to an internal address (set " + EnvAllowPrivateEndpoints + "=on to allow a self-hosted model)")

// AllowPrivateEndpoints reports whether the operator allowed internal AI
// endpoints in workspace settings.
func AllowPrivateEndpoints() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(EnvAllowPrivateEndpoints)), "on")
}

// CheckTenantEndpoint validates an AI base URL that came from a workspace's
// settings: https only, a real host, and (unless allowed) not an internal
// address. The dialer re-checks the resolved address at connect time.
func CheckTenantEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("ai: base URL must be an absolute https URL without credentials")
	}
	allow := AllowPrivateEndpoints()
	switch u.Scheme {
	case "https":
	case "http":
		if !allow {
			return fmt.Errorf("ai: base URL must use https (set %s=on to allow http to a self-hosted model)", EnvAllowPrivateEndpoints)
		}
	default:
		return errors.New("ai: base URL must use https")
	}
	if allow {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if isInternalIP(ip) {
			return ErrPrivateEndpoint
		}
		return nil
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return ErrPrivateEndpoint
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Unresolvable now; the dialer still refuses an internal address later.
		return nil
	}
	for _, ip := range ips {
		if isInternalIP(ip) {
			return ErrPrivateEndpoint
		}
	}
	return nil
}

// cgnat is the carrier-grade NAT range, which net.IP does not class as private.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isInternalIP reports whether an address is loopback, private, link-local
// (which covers cloud metadata at 169.254.169.254), unspecified, multicast or
// shared address space.
func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if a, ok := netip.AddrFromSlice(ip); ok && cgnat.Contains(a.Unmap()) {
		return true
	}
	return false
}

// proxyIPs resolves the configured egress proxies, so the internal-address
// guard does not block the connection to the operator's own proxy.
func proxyIPs() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			out[ip.String()] = true
			continue
		}
		if ips, err := net.LookupIP(u.Hostname()); err == nil {
			for _, ip := range ips {
				out[ip.String()] = true
			}
		}
	}
	return out
}
