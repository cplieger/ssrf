package ssrf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestValidateURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid URLs.
		{"valid https", "https://example.com/file.txt", false},
		{"valid https with path", "https://cdn.example.com/resource/123", false},
		{"public IP allowed", "https://1.2.3.4/file.txt", false},
		{"public IPv6 allowed", "https://[2606:4700::1]/file.txt", false},

		// Scheme rejection.
		{"http rejected", "http://example.com/file.txt", true},
		{"ftp rejected", "ftp://example.com/file.txt", true},
		{"empty scheme rejected", "://example.com/file.txt", true},
		{"no scheme rejected", "example.com/file.txt", true},

		// Host rejection.
		{"empty string", "", true},
		{"empty host", "https://", true},
		{"localhost rejected", "https://localhost/file.txt", true},
		{"localhost uppercase rejected", "https://LOCALHOST/file.txt", true},
		{"localhost trailing dot rejected", "https://localhost./file.txt", true},
		{"localhost double trailing dot rejected", "https://localhost../file.txt", true},
		{"localhost uppercase trailing dot rejected", "https://LOCALHOST./file.txt", true},
		{"only dots rejected", "https://../file.txt", true},
		{"bare hostname rejected", "https://internal/file.txt", true},

		// IPv4 private/reserved.
		{"loopback IP rejected", "https://127.0.0.1/file.txt", true},
		{"private 192.168 rejected", "https://192.168.1.77/file.txt", true},
		{"private 10.x rejected", "https://10.0.0.1/file.txt", true},
		{"private 172.16 rejected", "https://172.16.0.1/file.txt", true},
		{"link-local rejected", "https://169.254.1.1/file.txt", true},
		{"unspecified rejected", "https://0.0.0.0/file.txt", true},

		// RFC 6890 "this host on this network" 0.0.0.0/8 (beyond IsUnspecified).
		{"this-host 0.1.2.3 rejected", "https://0.1.2.3/file.txt", true},
		{"this-host 0.127.0.0.1 rejected", "https://0.127.0.1/file.txt", true},
		{"this-host 0.255.255.255 rejected", "https://0.255.255.255/file.txt", true},
		{"just above this-host 1.0.0.0 allowed", "https://1.0.0.0/file.txt", false},

		// RFC 1112 §4 reserved 240.0.0.0/4 (former Class E).
		{"reserved 240.0.0.1 rejected", "https://240.0.0.1/file.txt", true},
		{"reserved 250.1.2.3 rejected", "https://250.1.2.3/file.txt", true},
		{"broadcast 255.255.255.255 rejected", "https://255.255.255.255/file.txt", true},
		{"just below reserved 239.255.255.255 rejected (multicast)", "https://239.255.255.255/file.txt", true},

		// IPv6 private/reserved.
		{"IPv6 loopback rejected", "https://[::1]/file.txt", true},
		{"IPv6 ULA rejected", "https://[fc00::1]/file.txt", true},
		{"IPv6 link-local rejected", "https://[fe80::1]/file.txt", true},
		{"IPv6 multicast rejected", "https://[ff02::1]/file.txt", true},
		{"IPv6 unspecified rejected", "https://[::]/file.txt", true},

		// IPv4-mapped IPv6 bypass attempts.
		{"IPv4-mapped loopback rejected", "https://[::ffff:127.0.0.1]/file.txt", true},
		{"IPv4-mapped private rejected", "https://[::ffff:192.168.1.1]/file.txt", true},

		// RFC 3056 6to4 wrapper (2002::/16) with embedded IPv4.
		{"6to4 embedded loopback rejected", "https://[2002:7f00:0001::]/file.txt", true},
		{"6to4 embedded private 192.168 rejected", "https://[2002:c0a8:0101::]/file.txt", true},
		{"6to4 embedded private 10.0 rejected", "https://[2002:0a00:0001::]/file.txt", true},
		{"6to4 embedded CGNAT rejected", "https://[2002:6440:0001::]/file.txt", true},
		{"6to4 embedded public 8.8.8.8 allowed", "https://[2002:0808:0808::]/file.txt", false},

		// RFC 6052 NAT64 well-known prefix (64:ff9b::/96).
		{"NAT64 embedded loopback rejected", "https://[64:ff9b::7f00:1]/file.txt", true},
		{"NAT64 embedded private rejected", "https://[64:ff9b::c0a8:101]/file.txt", true},
		{"NAT64 embedded 10.0 rejected", "https://[64:ff9b::a00:1]/file.txt", true},
		{"NAT64 embedded public allowed", "https://[64:ff9b::808:808]/file.txt", false},

		// RFC 4291 §2.5.5.1 deprecated IPv4-compatible IPv6 (::/96).
		{"IPv4-compat loopback rejected", "https://[::127.0.0.1]/file.txt", true},
		{"IPv4-compat private 192.168 rejected", "https://[::192.168.1.1]/file.txt", true},
		{"IPv4-compat private 10 rejected", "https://[::10.0.0.1]/file.txt", true},

		// RFC 6598 shared address space (CGNAT).
		{"CGNAT 100.64 rejected", "https://100.64.0.1/file.txt", true},
		{"CGNAT 100.127 rejected", "https://100.127.255.254/file.txt", true},
		{"non-CGNAT 100.128 allowed", "https://100.128.0.1/file.txt", false},

		// SSRF bypass vectors (documentation-as-tests: Go's url.Parse handles
		// these correctly, but tests prove the SSRF layer doesn't regress).
		{"userinfo bypass rejected", "https://evil@127.0.0.1/file.txt", true},
		{"loopback with port rejected", "https://127.0.0.1:8080/file.txt", true},
		{"private with port rejected", "https://192.168.1.1:443/file.txt", true},
		{"public with port allowed", "https://example.com:443/file.txt", false},
		{"URL with fragment allowed", "https://example.com/file.txt#frag", false},

		// DNS rebinding: ValidateURL accepts public hostnames even if they
		// could resolve to private IPs. SafeTransport's DialContext catches
		// private addresses after DNS resolution; SafeRedirectPolicy catches
		// redirects to literal private IPs or bare names.
		{"DNS rebinding hostname accepted (caught by dial context)", "https://evil.attacker.com/file.txt", false},

		// CGNAT boundary values.
		{"CGNAT first address rejected", "https://100.64.0.0/file.txt", true},
		{"just below CGNAT allowed", "https://100.63.255.255/file.txt", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateURL(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}

func TestIsPublicHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"public domain", "example.com", true},
		{"public IP", "8.8.8.8", true},
		{"public IPv6", "2606:4700::1", true},
		{"localhost", "localhost", false},
		{"localhost trailing dot", "localhost.", false},
		{"localhost double trailing dot", "localhost..", false},
		{"loopback", "127.0.0.1", false},
		{"private", "192.168.1.1", false},
		{"bare hostname", "internal", false},
		{"empty", "", false},
		{"IPv6 ULA", "fc00::1", false},
		{"IPv4-mapped private", "::ffff:10.0.0.1", false},
		{"CGNAT", "100.64.0.1", false},

		// RFC 6890 this-host block beyond IsUnspecified.
		{"this-host 0.1.2.3", "0.1.2.3", false},
		{"this-host 0.127.0.0.1", "0.127.0.1", false},

		// Reserved Class E / broadcast.
		{"reserved 240.0.0.1", "240.0.0.1", false},
		{"broadcast", "255.255.255.255", false},

		// IPv6 transition mechanisms.
		{"6to4 embedded loopback", "2002:7f00:0001::", false},
		{"6to4 embedded private", "2002:c0a8:0101::", false},
		{"6to4 embedded public", "2002:0808:0808::", true},
		{"NAT64 embedded loopback", "64:ff9b::7f00:1", false},
		{"IPv4-compat loopback", "::127.0.0.1", false},

		// IP range boundary values.
		{"172.31.255.255 private", "172.31.255.255", false},
		{"172.32.0.0 public", "172.32.0.0", true},
		{"10.255.255.255 private", "10.255.255.255", false},
		{"192.168.255.255 private", "192.168.255.255", false},
		{"CGNAT boundary 100.63.255.255 public", "100.63.255.255", true},
		{"CGNAT boundary 100.64.0.0 private", "100.64.0.0", false},
		{"CGNAT boundary 100.127.255.255 private", "100.127.255.255", false},
		{"CGNAT boundary 100.128.0.0 public", "100.128.0.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsPublicHost(tt.host)
			if got != tt.want {
				t.Errorf("IsPublicHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestSafeRedirectPolicy_blocks_private_redirect(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://192.168.1.77/internal", http.NoBody)
	err := policy(req, nil)
	if err == nil {
		t.Error("SafeRedirectPolicy() = nil, want error for private redirect")
	}
}

func TestSafeRedirectPolicy_blocks_http_downgrade(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/file.txt", http.NoBody)
	err := policy(req, nil)
	if err == nil {
		t.Error("SafeRedirectPolicy() = nil, want error for http scheme downgrade")
	}
}

func TestSafeRedirectPolicy_allows_public_redirect(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.example.com/file.txt", http.NoBody)
	err := policy(req, nil)
	if err != nil {
		t.Errorf("SafeRedirectPolicy() = %v, want nil for public redirect", err)
	}
}

func TestSafeRedirectPolicy_stops_after_10_redirects(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/file", http.NoBody)
	via := make([]*http.Request, 10)
	err := policy(req, via)
	if err == nil {
		t.Error("SafeRedirectPolicy() = nil, want error after 10 redirects")
	}
}

// Even when a caller supplies a custom next, the 10-redirect cap must
// still apply — next could be a trivial passthrough that has no cap.
func TestSafeRedirectPolicy_caps_redirects_with_custom_next(t *testing.T) {
	t.Parallel()
	called := false
	next := func(_ *http.Request, _ []*http.Request) error {
		called = true
		return nil
	}
	policy := SafeRedirectPolicy(next)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/file", http.NoBody)
	via := make([]*http.Request, 10)
	err := policy(req, via)
	if err == nil {
		t.Error("SafeRedirectPolicy() with custom next = nil, want error at 10-redirect cap")
	}
	if called {
		t.Error("SafeRedirectPolicy() called next past the 10-redirect cap")
	}
}

func TestSafeRedirectPolicy_delegates_to_next(t *testing.T) {
	t.Parallel()
	called := false
	next := func(_ *http.Request, _ []*http.Request) error {
		called = true
		return nil
	}
	policy := SafeRedirectPolicy(next)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/file", http.NoBody)
	err := policy(req, nil)
	if err != nil {
		t.Errorf("SafeRedirectPolicy() = %v, want nil", err)
	}
	if !called {
		t.Error("SafeRedirectPolicy() did not call next function")
	}
}

func TestSafeRedirectPolicy_propagates_next_error(t *testing.T) {
	t.Parallel()
	nextErr := errors.New("custom redirect policy error")
	next := func(_ *http.Request, _ []*http.Request) error {
		return nextErr
	}
	policy := SafeRedirectPolicy(next)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/file", http.NoBody)
	err := policy(req, nil)
	if !errors.Is(err, nextErr) {
		t.Errorf("SafeRedirectPolicy() = %v, want %v", err, nextErr)
	}
}

func TestSafeRedirectPolicy_nil_next_under_limit_allows(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/file", http.NoBody)
	via := make([]*http.Request, 5) // under 10
	err := policy(req, via)
	if err != nil {
		t.Errorf("SafeRedirectPolicy(nil) with %d redirects = %v, want nil", len(via), err)
	}
}

// PBT: ValidateURL and IsPublicHost are consistent. If ValidateURL accepts
// an https URL with a given host, IsPublicHost must also accept that host.
func TestValidateURL_IsPublicHost_consistency(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate domain-like hostnames with at least one dot (to pass bare hostname check).
		label := rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "label")
		tld := rapid.SampledFrom([]string{"com", "org", "net", "io"}).Draw(t, "tld")
		host := label + "." + tld
		url := fmt.Sprintf("https://%s/path", host)

		urlErr := ValidateURL(url)
		hostOK := IsPublicHost(host)

		if urlErr == nil && !hostOK {
			t.Errorf("ValidateURL(%q) = nil but IsPublicHost(%q) = false", url, host)
		}
	})
}

// PBT: ValidateURL always rejects non-https schemes.
func TestValidateURL_rejects_non_https_schemes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		scheme := rapid.SampledFrom([]string{"http", "ftp", "gopher", "file", "ssh", "ws", "wss"}).Draw(t, "scheme")
		url := fmt.Sprintf("%s://example.com/file", scheme)

		err := ValidateURL(url)

		if err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error for non-https scheme", url)
		}
	})
}

// PBT: isPublicAddr rejects all non-public IPv4 addresses.
func TestIsPublicAddr_rejects_all_non_public(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "ipv4")
		addr := netip.AddrFrom4([4]byte(b))
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsMulticast() || addr.IsUnspecified() || sharedAddrSpace.Contains(addr) ||
			thisHostNet.Contains(addr) || reserved240.Contains(addr) {
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false for non-public address", addr)
			}
		}
	})
}

// PBT: isPublicAddr rejects all non-public IPv6 addresses.
// Symmetric to TestIsPublicAddr_rejects_all_non_public for IPv4; closes the
// mutation gap where a flip on !addr.IsLinkLocalUnicast() etc. on the IPv6
// code path could survive because only IPv4 addresses were randomly drawn.
func TestIsPublicAddr_rejects_all_non_public_ipv6(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "ipv6")
		addr := netip.AddrFrom16([16]byte(b))
		// Skip IPv4-mapped forms — those are covered by
		// TestValidateURL_ipv4_mapped_ipv6_consistency and by
		// Unmap() inside validateHost/safeDialContext.
		if addr.Is4In6() || addr.Is4() {
			return
		}
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsMulticast() || addr.IsUnspecified() {
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false for non-public IPv6 address", addr)
			}
		}
	})
}

// PBT: ValidateURL never panics on arbitrary input.
func TestValidateURL_never_panics(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "url")
		_ = ValidateURL(input) // must not panic
	})
}

// PBT: IPv4-mapped IPv6 addresses are rejected consistently with their
// IPv4 equivalents (defense-in-depth for CVE-2024-24790).
func TestValidateURL_ipv4_mapped_ipv6_consistency(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "ipv4")
		addr := netip.AddrFrom4([4]byte(b))
		if !isPublicAddr(addr) {
			mapped := netip.AddrFrom16(addr.As16())
			host := mapped.String()
			url := fmt.Sprintf("https://[%s]/file.txt", host)
			err := ValidateURL(url)
			if err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error for IPv4-mapped IPv6 of non-public %v", url, addr)
			}
		}
	})
}

// --- safeDialContext ---

func TestSafeDialContext_blocks_private_ip_resolution(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil, slog.Default())
	// 127.0.0.1 is a literal IP that resolves to itself (loopback).
	_, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Error("safeDialContext() = nil, want error for loopback IP")
	}
}

func TestSafeDialContext_blocks_private_range(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil, slog.Default())
	_, err := dial(context.Background(), "tcp", "192.168.1.1:443")
	if err == nil {
		t.Error("safeDialContext() = nil, want error for private IP")
	}
}

func TestSafeDialContext_invalid_address_returns_error(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil, slog.Default())
	_, err := dial(context.Background(), "tcp", "no-port")
	if err == nil {
		t.Error("safeDialContext() = nil, want error for invalid address")
	}
}

// The .invalid TLD is RFC 2606 reserved to never resolve; this closes the
// coverage gap on the DNS-lookup-error branch and guards against a silent
// regression that would drop the SSRF error wrapping or return a nil conn
// with a nil error (which callers would treat as a successful connection).
func TestSafeDialContext_dns_lookup_error_is_wrapped(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dial(ctx, "tcp", "invalid-host-does-not-exist-xyz.invalid:443")

	if conn != nil {
		t.Errorf("safeDialContext() returned non-nil conn %v, want nil on DNS error", conn)
	}
	if err == nil {
		t.Fatal("safeDialContext() = nil err, want DNS lookup error")
	}
	if !strings.Contains(err.Error(), "SSRF dial") {
		t.Errorf("safeDialContext() err = %q, want error wrapped with \"SSRF dial\" prefix", err.Error())
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Errorf("safeDialContext() err = %q, want \"DNS lookup failed\" in message", err.Error())
	}
}

func TestSafeTransport_returns_non_nil(t *testing.T) {
	t.Parallel()
	tr := SafeTransport()
	if tr == nil {
		t.Fatal("SafeTransport() returned nil")
	}
	if tr.DialContext == nil {
		t.Error("SafeTransport().DialContext is nil")
	}
	// Proxy must be nil; any proxy would bypass safeDialContext and re-open SSRF.
	if tr.Proxy != nil {
		t.Error("SafeTransport().Proxy != nil, want nil to prevent HTTP(S)_PROXY bypass")
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("SafeTransport().ResponseHeaderTimeout == 0, want a cap to prevent slow-headers stall")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("SafeTransport().IdleConnTimeout == 0, want a bound on idle conn lifetime")
	}
}

// --- Property tests ---

func TestValidateURL_Property_HTTPSRequired(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		host := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.[a-z]{2,4}`).Draw(t, "host")
		path := rapid.StringMatching(`/[a-z0-9/]{0,20}`).Draw(t, "path")

		httpsURL := "https://" + host + path
		httpURL := "http://" + host + path

		// HTTP must always be rejected.
		if err := ValidateURL(httpURL); err == nil {
			t.Errorf("HTTP URL accepted: %s", httpURL)
		}

		// HTTPS with a valid public host should be accepted.
		// (may still fail on DNS resolution, which is fine)
		_ = ValidateURL(httpsURL)
	})
}

// --- Security: Teredo (RFC 4380) embedded IPv4 extraction ---

func TestIsPublicAddr_Teredo_embedded_loopback(t *testing.T) {
	t.Parallel()
	// 2001:0000:xxxx:xxxx:xxxx:xxxx:YYYY:ZZZZ
	// Client IPv4 = XOR(bytes 12-15, 0xFF). 127.0.0.1 = 7f000001
	// XOR'd = 80ffff fe → bytes 12-15 = 0x80, 0xFF, 0xFF, 0xFE
	// Full: 2001:0000:4136:e378:8000:63bf:80ff:fffe
	addr := netip.MustParseAddr("2001:0000:4136:e378:8000:63bf:80ff:fffe")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (Teredo embedding 127.0.0.1)", addr)
	}
}

func TestIsPublicAddr_Teredo_embedded_private_10(t *testing.T) {
	t.Parallel()
	// 10.0.0.1 = 0a000001, XOR'd = f5fffffe
	addr := netip.MustParseAddr("2001:0000:4136:e378:8000:63bf:f5ff:fffe")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (Teredo embedding 10.0.0.1)", addr)
	}
}

func TestIsPublicAddr_Teredo_embedded_link_local(t *testing.T) {
	t.Parallel()
	// 169.254.169.254 = a9fea9fe, XOR'd = 56015601
	addr := netip.MustParseAddr("2001:0000:4136:e378:8000:63bf:5601:5601")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (Teredo embedding 169.254.169.254)", addr)
	}
}

func TestIsPublicAddr_Teredo_embedded_public_allowed(t *testing.T) {
	t.Parallel()
	// 8.8.8.8 = 08080808, XOR'd = f7f7f7f7
	// Server = 8.8.4.4 (public)
	addr := netip.MustParseAddr("2001:0000:0808:0404:8000:63bf:f7f7:f7f7")
	if !isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = false, want true (Teredo embedding 8.8.8.8 with server 8.8.4.4)", addr)
	}
}

func TestIsPublicAddr_Teredo_private_server(t *testing.T) {
	t.Parallel()
	// Server IP = 10.0.0.1 (bytes 4-7), client = 8.8.8.8 XOR'd
	addr := netip.MustParseAddr("2001:0000:0a00:0001:8000:63bf:f7f7:f7f7")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (Teredo with private server 10.0.0.1)", addr)
	}
}

func TestValidateURL_Teredo_embedded_loopback(t *testing.T) {
	t.Parallel()
	err := ValidateURL("https://[2001:0000:4136:e378:8000:63bf:80ff:fffe]/file")
	if err == nil {
		t.Error("ValidateURL() = nil, want error for Teredo embedding 127.0.0.1")
	}
}

// --- Security: RFC 8215 local NAT64 (64:ff9b:1::/48) ---

func TestIsPublicAddr_NAT64Local_embedded_loopback(t *testing.T) {
	t.Parallel()
	// 64:ff9b:1::7f00:1 embeds 127.0.0.1
	addr := netip.MustParseAddr("64:ff9b:1::7f00:1")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (NAT64 local embedding 127.0.0.1)", addr)
	}
}

func TestIsPublicAddr_NAT64Local_embedded_private(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("64:ff9b:1::c0a8:101")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (NAT64 local embedding 192.168.1.1)", addr)
	}
}

func TestIsPublicAddr_NAT64Local_blocked_outright(t *testing.T) {
	t.Parallel()
	// RFC 8215 local-use NAT64 (64:ff9b:1::/48) is blocked outright rather
	// than IPv4-extracted: the /48 RFC 6052 embedding offset differs from the
	// well-known /96, so extracting bytes 12-15 would be a potential SSRF bypass.
	addr := netip.MustParseAddr("64:ff9b:1::808:808")
	if isPublicAddr(addr) {
		t.Errorf("isPublicAddr(%v) = true, want false (local NAT64 blocked outright)", addr)
	}
}

func TestValidateURL_NAT64Local_embedded_loopback(t *testing.T) {
	t.Parallel()
	err := ValidateURL("https://[64:ff9b:1::7f00:1]/file")
	if err == nil {
		t.Error("ValidateURL() = nil, want error for NAT64 local embedding 127.0.0.1")
	}
}

// --- Security: IPv4 non-routable ranges (RFC 5737, RFC 2544, RFC 5736) ---

func TestIsPublicAddr_IPv4_NonRoutable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"IETF Protocol Assignments 192.0.0.1", "192.0.0.1"},
		{"IETF Protocol Assignments 192.0.0.254", "192.0.0.254"},
		{"TEST-NET-1 192.0.2.1", "192.0.2.1"},
		{"TEST-NET-1 192.0.2.255", "192.0.2.255"},
		{"TEST-NET-2 198.51.100.1", "198.51.100.1"},
		{"TEST-NET-2 198.51.100.255", "198.51.100.255"},
		{"TEST-NET-3 203.0.113.1", "203.0.113.1"},
		{"TEST-NET-3 203.0.113.255", "203.0.113.255"},
		{"Benchmarking 198.18.0.1", "198.18.0.1"},
		{"Benchmarking 198.19.255.255", "198.19.255.255"},
		{"6to4 relay 192.88.99.1", "192.88.99.1"},
		{"6to4 relay 192.88.99.255", "192.88.99.255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false", addr)
			}
		})
	}
}

func TestValidateURL_IPv4_NonRoutable(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://192.0.2.1/file",
		"https://198.51.100.1/file",
		"https://203.0.113.1/file",
		"https://198.18.0.1/file",
		"https://192.88.99.1/file",
		"https://192.0.0.1/file",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURL(u); err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error", u)
			}
		})
	}
}

// --- Security: IPv6 non-routable ranges ---

func TestIsPublicAddr_IPv6_NonRoutable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"Discard 100::1", "100::1"},
		{"Discard 100::ffff:ffff:ffff:ffff", "100::ffff:ffff:ffff:ffff"},
		{"Benchmarking 2001:2::1", "2001:2::1"},
		{"Benchmarking 2001:2:0:ffff::", "2001:2:0:ffff::"},
		{"Documentation 2001:db8::1", "2001:db8::1"},
		{"Documentation 2001:db8:ffff:ffff::", "2001:db8:ffff:ffff::"},
		{"Documentation new 3fff::1", "3fff::1"},
		{"Documentation new 3fff:f:ffff::", "3fff:f:ffff::"},
		{"SRv6 SIDs 5f00::1", "5f00::1"},
		{"SRv6 SIDs 5f00:ffff::", "5f00:ffff::"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false", addr)
			}
		})
	}
}

func TestValidateURL_IPv6_NonRoutable(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://[100::1]/file",
		"https://[2001:2::1]/file",
		"https://[2001:db8::1]/file",
		"https://[3fff::1]/file",
		"https://[5f00::1]/file",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURL(u); err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error", u)
			}
		})
	}
}

// --- Structured error types ---

func TestError_Kind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		kind ErrorKind
	}{
		{"bad scheme", "http://example.com/f", KindBadScheme},
		{"empty host", "https:///f", KindEmptyHost},
		{"localhost", "https://localhost/f", KindLocalhost},
		{"bare hostname", "https://internal/f", KindBareHostname},
		{"non-public IP", "https://127.0.0.1/f", KindNonPublicIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateURL(tc.url)
			if err == nil {
				t.Fatalf("ValidateURL(%q) = nil, want error", tc.url)
			}
			var ssrfError *Error
			if !errors.As(err, &ssrfError) {
				t.Fatalf("ValidateURL(%q) error is not *Error: %T", tc.url, err)
			}
			if ssrfError.Kind != tc.kind {
				t.Errorf("ValidateURL(%q) error Kind = %d, want %d", tc.url, ssrfError.Kind, tc.kind)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	t.Parallel()
	err := ValidateURL("not a url at all ://")
	if err == nil {
		t.Skip("URL parsed without error")
	}
	var ssrfError *Error
	if errors.As(err, &ssrfError) {
		// KindInvalidURL should wrap the url.Parse error
		if ssrfError.Kind == KindInvalidURL && ssrfError.Err == nil {
			t.Error("KindInvalidURL should wrap underlying parse error")
		}
	}
}

// --- Exported IsPublicAddr ---

func TestIsPublicAddr_exported(t *testing.T) {
	t.Parallel()
	if !IsPublicAddr(netip.MustParseAddr("8.8.8.8")) {
		t.Error("IsPublicAddr(8.8.8.8) = false, want true")
	}
	if IsPublicAddr(netip.MustParseAddr("127.0.0.1")) {
		t.Error("IsPublicAddr(127.0.0.1) = true, want false")
	}
	if IsPublicAddr(netip.MustParseAddr("192.0.2.1")) {
		t.Error("IsPublicAddr(192.0.2.1) = true, want false (TEST-NET-1)")
	}
	if IsPublicAddr(netip.MustParseAddr("2001:db8::1")) {
		t.Error("IsPublicAddr(2001:db8::1) = true, want false (documentation)")
	}
}

// Regression: IsPublicAddr must reject IPv4-mapped IPv6 forms of non-public
// addresses even when called directly (without prior Unmap by the caller).
// Previously sharedAddrSpace.Contains missed ::ffff:100.64.0.1 because the
// prefix is IPv4 and the address was IPv6.
func TestIsPublicAddr_mapped_CGNAT_regression(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"mapped CGNAT", "::ffff:100.64.0.1"},
		{"mapped CGNAT boundary", "::ffff:100.127.255.255"},
		{"mapped loopback", "::ffff:127.0.0.1"},
		{"mapped private 10", "::ffff:10.0.0.1"},
		{"mapped private 192.168", "::ffff:192.168.1.1"},
		{"mapped link-local", "::ffff:169.254.1.1"},
		{"mapped this-host", "::ffff:0.1.2.3"},
		{"mapped reserved 240", "::ffff:240.0.0.1"},
		{"mapped TEST-NET-1", "::ffff:192.0.2.1"},
		{"mapped benchmarking", "::ffff:198.18.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if IsPublicAddr(addr) {
				t.Errorf("IsPublicAddr(%v) = true, want false", addr)
			}
		})
	}
}

// Positive case: mapped public IPs must still be allowed.
func TestIsPublicAddr_mapped_public_allowed(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("::ffff:8.8.8.8")
	if !IsPublicAddr(addr) {
		t.Errorf("IsPublicAddr(%v) = false, want true", addr)
	}
}

// --- net.Dialer.Control hook (defense-in-depth) ---

func TestSafeControl_blocks_non_tcp(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	err := ctrl("udp4", "8.8.8.8:443", nil)
	if err == nil {
		t.Error("safeControl() = nil, want error for non-TCP network")
	}
}

func TestSafeControl_blocks_private_ip(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	err := ctrl("tcp4", "127.0.0.1:443", nil)
	if err == nil {
		t.Error("safeControl() = nil, want error for loopback IP")
	}
	err = ctrl("tcp4", "10.0.0.1:443", nil)
	if err == nil {
		t.Error("safeControl() = nil, want error for private IP")
	}
}

func TestSafeControl_allows_public_ip(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	err := ctrl("tcp4", "8.8.8.8:443", nil)
	if err != nil {
		t.Errorf("safeControl() = %v, want nil for public IP", err)
	}
	err = ctrl("tcp6", "[2606:4700::1]:443", nil)
	if err != nil {
		t.Errorf("safeControl() = %v, want nil for public IPv6", err)
	}
}

func TestSafeControl_blocks_disallowed_port(t *testing.T) {
	t.Parallel()
	ports := map[uint16]struct{}{443: {}}
	ctrl := safeControl(isPublicAddr, ports, slog.Default())
	err := ctrl("tcp4", "8.8.8.8:80", nil)
	if err == nil {
		t.Error("safeControl() = nil, want error for port 80 when only 443 allowed")
	}
	var ssrfError *Error
	if !errors.As(err, &ssrfError) || ssrfError.Kind != KindBadPort {
		t.Errorf("expected KindBadPort, got %v", err)
	}
}

func TestSafeControl_allows_permitted_port(t *testing.T) {
	t.Parallel()
	ports := map[uint16]struct{}{443: {}, 8443: {}}
	ctrl := safeControl(isPublicAddr, ports, slog.Default())
	err := ctrl("tcp4", "8.8.8.8:443", nil)
	if err != nil {
		t.Errorf("safeControl() = %v, want nil for allowed port 443", err)
	}
	err = ctrl("tcp4", "8.8.8.8:8443", nil)
	if err != nil {
		t.Errorf("safeControl() = %v, want nil for allowed port 8443", err)
	}
}

func TestSafeControl_nil_ports_allows_all(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	err := ctrl("tcp4", "8.8.8.8:12345", nil)
	if err != nil {
		t.Errorf("safeControl() = %v, want nil when no port restrictions", err)
	}
}

// --- Port restrictions (WithAllowedPorts) ---

func TestWithAllowedPorts_blocks_disallowed(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443))
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "8.8.8.8:80")
	if err == nil {
		t.Error("expected error for port 80 when only 443 allowed")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected port-not-allowed error, got: %v", err)
	}
}

func TestWithAllowedPorts_allows_permitted(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443, 80))
	dial := tr.DialContext
	// Port 80 is allowed but connection may fail (timeout) — no SSRF error.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "tcp", "8.8.8.8:80")
	if err != nil && strings.Contains(err.Error(), "not allowed") {
		t.Errorf("port 80 should be allowed, got: %v", err)
	}
}

func TestWithAllowedPorts_empty_allows_all(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts())
	dial := tr.DialContext
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "tcp", "8.8.8.8:12345")
	if err != nil && strings.Contains(err.Error(), "not allowed") {
		t.Errorf("all ports should be allowed, got: %v", err)
	}
}

func TestWithAllowedPorts_default_only_443(t *testing.T) {
	t.Parallel()
	tr := SafeTransport() // default
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "8.8.8.8:80")
	if err == nil {
		t.Error("default should only allow port 443")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected port error, got: %v", err)
	}
}

// --- Scheme allowlist (WithAllowedSchemes) ---

func TestWithAllowedSchemes_rejects_disallowed(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}}
	err := validateURLWithSchemes("http://example.com/f", schemes, slog.Default())
	if err == nil {
		t.Error("expected error for http when only https allowed")
	}
	var ssrfError *Error
	if !errors.As(err, &ssrfError) || ssrfError.Kind != KindBadScheme {
		t.Errorf("expected KindBadScheme, got %v", err)
	}
}

func TestWithAllowedSchemes_allows_http_when_configured(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}, "http": {}}
	err := validateURLWithSchemes("http://example.com/f", schemes, slog.Default())
	if err != nil {
		t.Errorf("http should be allowed, got: %v", err)
	}
}

func TestWithAllowedSchemes_case_insensitive(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}}
	err := validateURLWithSchemes("HTTPS://example.com/f", schemes, slog.Default())
	if err != nil {
		t.Errorf("HTTPS (uppercase) should match, got: %v", err)
	}
}

func TestAllowedSchemes_helper(t *testing.T) {
	t.Parallel()
	s := AllowedSchemes(WithAllowedSchemes("http", "https"))
	if _, ok := s["http"]; !ok {
		t.Error("AllowedSchemes should include http")
	}
	if _, ok := s["https"]; !ok {
		t.Error("AllowedSchemes should include https")
	}
}

func TestSafeRedirectPolicyWithSchemes_blocks_disallowed(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}}
	policy := SafeRedirectPolicyWithSchemes(schemes, nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/f", http.NoBody)
	err := policy(req, nil)
	if err == nil {
		t.Error("redirect to http should be blocked")
	}
}

func TestSafeRedirectPolicyWithSchemes_allows_configured(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}, "http": {}}
	policy := SafeRedirectPolicyWithSchemes(schemes, nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/f", http.NoBody)
	err := policy(req, nil)
	if err != nil {
		t.Errorf("redirect to http should be allowed, got: %v", err)
	}
}

// --- Integration: Control hook fires on actual dial ---

func TestSafeTransport_control_hook_fires(t *testing.T) {
	t.Parallel()
	// With a custom policy that allows everything + custom resolver
	// returning a private IP, the resolve-once layer passes (allow-all policy)
	// but the Control hook should also pass (same policy).
	allowAll := func(_ netip.Addr) bool { return true }
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	tr := SafeTransport(WithPolicy(allowAll), WithResolver(r), WithAllowedPorts())
	dial := tr.DialContext
	// Should attempt dial to 127.0.0.1:1 (will fail to connect, not SSRF error).
	_, err := dial(context.Background(), "tcp", "evil.com:1")
	if err != nil && strings.Contains(err.Error(), "not public") {
		t.Errorf("allow-all policy should pass Control hook, got: %v", err)
	}
}
