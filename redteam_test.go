package ssrf

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// REFACTOR PROBES: ErrorKind rename (Err* -> Kind*), WithLogger, functional opts
// =============================================================================

// Verify errors.As(*Error) + Kind switch still works after rename.
func TestRefactor_ErrorKind_switch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url  string
		kind ErrorKind
	}{
		{"http://example.com/f", KindBadScheme},
		{"https:///f", KindEmptyHost},
		{"https://localhost/f", KindLocalhost},
		{"https://internal/f", KindBareHostname},
		{"https://127.0.0.1/f", KindNonPublicIP},
	}
	for _, tc := range cases {
		err := ValidateURL(tc.url)
		if err == nil {
			t.Fatalf("ValidateURL(%q) = nil", tc.url)
		}
		var se *Error
		if !errors.As(err, &se) {
			t.Fatalf("errors.As failed for %q: %T", tc.url, err)
		}
		switch se.Kind {
		case KindInvalidURL, KindBadScheme, KindEmptyHost, KindLocalhost,
			KindBareHostname, KindNonPublicIP, KindDNSFailed, KindPolicyDenied, KindBadPort:
			// valid
		default:
			t.Errorf("unexpected Kind %d for %q", se.Kind, tc.url)
		}
		if se.Kind != tc.kind {
			t.Errorf("URL %q: got Kind %d, want %d", tc.url, se.Kind, tc.kind)
		}
	}
}

// Verify KindBadPort via dial with port restriction.
func TestRefactor_ErrorKind_BadPort(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(
		&net.Dialer{Timeout: 2 * time.Second},
		isPublicAddr, net.DefaultResolver,
		map[uint16]struct{}{443: {}}, slog.Default(),
	)
	_, err := dial(context.Background(), "tcp", "8.8.8.8:80")
	if err == nil {
		t.Fatal("expected port error")
	}
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("errors.As failed: %T", err)
	}
	if se.Kind != KindBadPort {
		t.Errorf("got Kind %d, want KindBadPort (%d)", se.Kind, KindBadPort)
	}
}

// WithLogger nil-safe: no panic, uses slog.Default().
func TestRefactor_WithLogger_nil_safe(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithLogger(nil))
	if tr == nil || tr.DialContext == nil {
		t.Fatal("SafeTransport(WithLogger(nil)) returned nil or nil DialContext")
	}
	// Attempt a dial that triggers a log - should not panic.
	_, _ = tr.DialContext(context.Background(), "tcp", "127.0.0.1:443")
}

// WithLogger threads to safeControl and safeDialContext.
func TestRefactor_WithLogger_threads_to_control_and_dial(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	tr := SafeTransport(WithLogger(log), WithResolver(r))
	_, _ = tr.DialContext(context.Background(), "tcp", "evil.com:443")
	if !strings.Contains(buf.String(), "ssrf") {
		t.Errorf("custom logger didn't capture ssrf log: %q", buf.String())
	}
}

// Standalone ValidateURL logs via slog.Default (not nil panic).
func TestRefactor_ValidateURL_logs_default(t *testing.T) {
	t.Parallel()
	// Just exercise - must not panic.
	_ = ValidateURL("http://example.com/f")
	_ = ValidateURL("https://localhost/f")
}

// SafeRedirectPolicy still logs via slog.Default.
func TestRefactor_SafeRedirectPolicy_logs_default(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("https://127.0.0.1/internal")
	_ = policy(req, nil) // must not panic
}

// Verify New* constructors (SafeTransport) default parity:
// Default = HTTPS only, port 443 only, isPublicAddr policy, non-nil logger.
func TestRefactor_SafeTransport_defaults(t *testing.T) {
	t.Parallel()
	tr := SafeTransport() // no options
	dial := tr.DialContext
	if dial == nil {
		t.Fatal("DialContext nil")
	}
	// Default port 443 only → port 80 blocked.
	_, err := dial(context.Background(), "tcp", "8.8.8.8:80")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("default should block port 80, got: %v", err)
	}
	// Default scheme HTTPS only.
	err = ValidateURL("http://example.com/f")
	if err == nil {
		t.Error("default ValidateURL should reject http")
	}
	// Default policy blocks private.
	_, err = dial(context.Background(), "tcp", "10.0.0.1:443")
	if err == nil {
		t.Error("default should block private IP")
	}
}

// Option order doesn't matter.
func TestRefactor_Option_order_independence(t *testing.T) {
	t.Parallel()
	var buf1, buf2 bytes.Buffer
	log1 := slog.New(slog.NewTextHandler(&buf1, &slog.HandlerOptions{Level: slog.LevelWarn}))
	log2 := slog.New(slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}

	// Order A: Logger, Resolver, Ports
	tr1 := SafeTransport(WithLogger(log1), WithResolver(r), WithAllowedPorts(443))
	_, _ = tr1.DialContext(context.Background(), "tcp", "evil.com:443")

	// Order B: Ports, Resolver, Logger
	tr2 := SafeTransport(WithAllowedPorts(443), WithResolver(r), WithLogger(log2))
	_, _ = tr2.DialContext(context.Background(), "tcp", "evil.com:443")

	if !strings.Contains(buf1.String(), "ssrf") {
		t.Error("order A: logger didn't capture ssrf log")
	}
	if !strings.Contains(buf2.String(), "ssrf") {
		t.Error("order B: logger didn't capture ssrf log")
	}
}

// No-option case.
func TestRefactor_no_option_works(t *testing.T) {
	t.Parallel()
	tr := SafeTransport()
	if tr == nil || tr.DialContext == nil {
		t.Fatal("SafeTransport() with no options should work")
	}
}

// =============================================================================
// SECURITY RE-ATTACKS
// =============================================================================

// IPv4-mapped CGNAT + all mapped ranges at dial time.
func TestSecurity_IPv4Mapped_CGNAT_dial(t *testing.T) {
	t.Parallel()
	ranges := []string{
		"::ffff:100.64.0.1", // CGNAT
		"::ffff:100.127.255.255",
		"::ffff:127.0.0.1", // loopback
		"::ffff:10.0.0.1",  // private
		"::ffff:172.16.0.1",
		"::ffff:192.168.1.1",
		"::ffff:169.254.1.1",  // link-local
		"::ffff:0.1.2.3",      // this-host
		"::ffff:240.0.0.1",    // reserved
		"::ffff:192.0.2.1",    // TEST-NET-1
		"::ffff:198.51.100.1", // TEST-NET-2
		"::ffff:203.0.113.1",  // TEST-NET-3
		"::ffff:198.18.0.1",   // benchmarking
		"::ffff:192.88.99.1",  // 6to4 relay
		"::ffff:192.0.0.1",    // IETF proto
	}
	for _, ip := range ranges {
		r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr(ip)}}
		tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
		_, err := tr.DialContext(context.Background(), "tcp", "evil.com:443")
		if err == nil {
			t.Errorf("BYPASS: mapped %s passed dial validation", ip)
		}
	}
}

// Teredo extraction attacks.
func TestSecurity_Teredo_extraction(t *testing.T) {
	t.Parallel()
	// Teredo: client IP = XOR(bytes 12-15, 0xFF)
	cases := []struct {
		name string
		ip   string
	}{
		// 127.0.0.1 XOR'd = 80:ff:ff:fe
		{"loopback", "2001:0000:4136:e378:8000:63bf:80ff:fffe"},
		// 10.0.0.1 XOR'd = f5:ff:ff:fe
		{"private 10", "2001:0000:4136:e378:8000:63bf:f5ff:fffe"},
		// 169.254.169.254 XOR'd = 56:01:56:01
		{"link-local metadata", "2001:0000:4136:e378:8000:63bf:5601:5601"},
		// 192.168.1.1 XOR'd = 3f:57:fe:fe
		{"private 192.168", "2001:0000:4136:e378:8000:63bf:3f57:fefe"},
		// 100.64.0.1 (CGNAT) XOR'd = 9b:bf:ff:fe
		{"CGNAT", "2001:0000:4136:e378:8000:63bf:9bbf:fffe"},
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS Teredo %s (%s) passed", tc.name, tc.ip)
		}
	}
}

// Teredo with private SERVER IP (bytes 4-7).
func TestSecurity_Teredo_private_server(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		// Server=10.0.0.1, client=8.8.8.8 XOR'd
		{"server 10.0.0.1", "2001:0000:0a00:0001:8000:63bf:f7f7:f7f7"},
		// Server=192.168.1.1, client=8.8.8.8 XOR'd
		{"server 192.168.1.1", "2001:0000:c0a8:0101:8000:63bf:f7f7:f7f7"},
		// Server=127.0.0.1, client=8.8.8.8 XOR'd
		{"server 127.0.0.1", "2001:0000:7f00:0001:8000:63bf:f7f7:f7f7"},
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS Teredo private server %s passed", tc.name)
		}
	}
}

// NAT64 well-known (64:ff9b::/96) extraction.
func TestSecurity_NAT64_extraction(t *testing.T) {
	t.Parallel()
	cases := []string{
		"64:ff9b::7f00:1",    // 127.0.0.1
		"64:ff9b::a00:1",     // 10.0.0.1
		"64:ff9b::c0a8:101",  // 192.168.1.1
		"64:ff9b::a9fe:a9fe", // 169.254.169.254
		"64:ff9b::6440:1",    // 100.64.0.1 (CGNAT)
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS NAT64 %s passed", ip)
		}
	}
}

// 6to4 (2002::/16) extraction.
func TestSecurity_6to4_extraction(t *testing.T) {
	t.Parallel()
	cases := []string{
		"2002:7f00:0001::", // 127.0.0.1
		"2002:c0a8:0101::", // 192.168.1.1
		"2002:0a00:0001::", // 10.0.0.1
		"2002:6440:0001::", // 100.64.0.1 (CGNAT)
		"2002:a9fe:a9fe::", // 169.254.169.254
		"2002:c000:0201::", // 192.0.2.1 TEST-NET-1
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS 6to4 %s passed", ip)
		}
	}
}

// Dial-time Control re-validation.
func TestSecurity_Control_revalidation(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	privates := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.1.1", "100.64.0.1", "0.1.2.3", "240.0.0.1",
	}
	for _, ip := range privates {
		err := ctrl("tcp4", ip+":443", nil)
		if err == nil {
			t.Errorf("BYPASS Control hook passed %s", ip)
		}
	}
	// IPv6 at control hook
	v6privates := []string{
		"::1", "fc00::1", "fe80::1",
	}
	for _, ip := range v6privates {
		err := ctrl("tcp6", "["+ip+"]:443", nil)
		if err == nil {
			t.Errorf("BYPASS Control hook passed IPv6 %s", ip)
		}
	}
}

// Port allowlist enforcement.
func TestSecurity_port_allowlist(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443))
	dial := tr.DialContext
	blockedPorts := []string{"80", "8080", "22", "3306", "6379", "11211"}
	for _, port := range blockedPorts {
		_, err := dial(context.Background(), "tcp", "8.8.8.8:"+port)
		if err == nil {
			t.Errorf("BYPASS port %s allowed when only 443 permitted", port)
		}
	}
}

// Scheme allowlist enforcement.
func TestSecurity_scheme_allowlist(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}}
	badSchemes := []string{
		"http://example.com/f",
		"ftp://example.com/f",
		"gopher://example.com/f",
		"file:///etc/passwd",
		"dict://evil.com:11211/stat",
	}
	for _, u := range badSchemes {
		err := validateURLWithSchemes(u, schemes, slog.Default())
		if err == nil {
			t.Errorf("BYPASS scheme allowed: %s", u)
		}
	}
}

// DNS rebinding: mock resolver flips from public to private across calls.
func TestSecurity_DNS_rebinding_mock(t *testing.T) {
	t.Parallel()
	// The resolver returns a private IP; safeDialContext must block.
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	_, err := tr.DialContext(context.Background(), "tcp", "evil.com:443")
	if err == nil {
		t.Error("BYPASS DNS rebinding: resolver returning link-local was not blocked")
	}
}

// Concurrent dial with -race (already run under -race flag).
func TestSecurity_concurrent_dial_race(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	dial := tr.DialContext

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, _ = dial(ctx, "tcp", "example.com:443")
		})
	}
	wg.Wait()
}

// IPv4-compat (deprecated ::/96) extraction.
func TestSecurity_IPv4Compat_extraction(t *testing.T) {
	t.Parallel()
	cases := []string{
		"::127.0.0.1",
		"::10.0.0.1",
		"::192.168.1.1",
		"::169.254.169.254",
		"::100.64.0.1",
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS IPv4-compat %s passed", ip)
		}
	}
}

// NAT64 local (64:ff9b:1::/48) blocked outright.
func TestSecurity_NAT64Local_blocked_outright(t *testing.T) {
	t.Parallel()
	cases := []string{
		"64:ff9b:1::808:808", // even public embedded
		"64:ff9b:1::7f00:1",
		"64:ff9b:1::c0a8:101",
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS NAT64 local %s passed", ip)
		}
	}
}

// Helper
func newTestReq(rawURL string) (*http.Request, error) {
	return http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
}
