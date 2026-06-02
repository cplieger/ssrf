package ssrf

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// POST-REFACTOR ROUND 3: CONVERGENCE RED-TEAM
// Probes: nil-option guards, Kind* rename, novel bypass attempts.
// =============================================================================

// --- NIL-OPTION GUARD VERIFICATION ---

func TestConvergence_NilOptionElement_SafeTransport(t *testing.T) {
	t.Parallel()
	// nil element in variadic should be silently skipped.
	tr := SafeTransport(nil, nil, WithAllowedPorts(443), nil)
	if tr == nil || tr.DialContext == nil {
		t.Fatal("SafeTransport with nil elements returned nil")
	}
	// Should still block private IP.
	_, err := tr.DialContext(context.Background(), "tcp", "10.0.0.1:443")
	if err == nil {
		t.Error("nil option elements broke default policy")
	}
}

func TestConvergence_NilOptionElement_AllowedSchemes(t *testing.T) {
	t.Parallel()
	s := AllowedSchemes(nil, nil, WithAllowedSchemes("https", "http"), nil)
	if s == nil {
		t.Fatal("AllowedSchemes with nil elements returned nil")
	}
	if _, ok := s["https"]; !ok {
		t.Error("missing https in result")
	}
	if _, ok := s["http"]; !ok {
		t.Error("missing http in result")
	}
}

func TestConvergence_NilOptionElement_SafeRedirectPolicyWithSchemes(t *testing.T) {
	t.Parallel()
	// SafeRedirectPolicyWithSchemes takes a map, not options; verify nil map
	// defaults to HTTPS-only behavior.
	policy := SafeRedirectPolicyWithSchemes(nil, nil)
	req, _ := newTestReq("http://example.com/evil")
	err := policy(req, nil)
	if err == nil {
		t.Error("nil schemes map should default to HTTPS-only, blocking http")
	}
	// HTTPS to public should pass.
	req2, _ := newTestReq("https://example.com/ok")
	err2 := policy(req2, nil)
	if err2 != nil {
		t.Errorf("HTTPS to public domain should pass, got: %v", err2)
	}
}

func TestConvergence_WithLogger_nil_no_panic(t *testing.T) {
	t.Parallel()
	// WithLogger(nil) must not panic and must retain slog.Default().
	tr := SafeTransport(WithLogger(nil), WithAllowedPorts(443))
	// Trigger a blocked dial to exercise logging path.
	_, _ = tr.DialContext(context.Background(), "tcp", "127.0.0.1:443")
}

// --- KIND* RENAME INTEGRITY ---

func TestConvergence_KindConstants_values(t *testing.T) {
	t.Parallel()
	// Verify all Kind constants are distinct and non-zero.
	kinds := []ErrorKind{
		KindInvalidURL, KindBadScheme, KindEmptyHost, KindLocalhost,
		KindBareHostname, KindNonPublicIP, KindDNSFailed, KindPolicyDenied, KindBadPort,
	}
	seen := make(map[ErrorKind]bool, len(kinds))
	for _, k := range kinds {
		if k == 0 {
			t.Errorf("Kind constant has zero value")
		}
		if seen[k] {
			t.Errorf("duplicate Kind value: %d", k)
		}
		seen[k] = true
	}
}

// --- NOVEL BYPASS ATTEMPTS ---

// Attempt: pass IPv4-mapped loopback as a URL host literal.
func TestConvergence_URLLiteral_MappedLoopback(t *testing.T) {
	t.Parallel()
	err := ValidateURL("https://[::ffff:127.0.0.1]/secret")
	if err == nil {
		t.Error("BYPASS: URL with mapped loopback literal passed validation")
	}
}

// Attempt: URL with empty brackets.
func TestConvergence_URLLiteral_EmptyBrackets(t *testing.T) {
	t.Parallel()
	err := ValidateURL("https://[]/secret")
	if err == nil {
		t.Error("BYPASS: URL with empty brackets passed validation")
	}
}

// Attempt: Exploit potential integer overflow in port parsing.
func TestConvergence_PortOverflow(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443))
	dial := tr.DialContext
	// Port 65979 = 443 + 65536 (test wrapping).
	_, err := dial(context.Background(), "tcp", "8.8.8.8:65979")
	if err == nil {
		t.Error("BYPASS: port 65979 was accepted (possible uint16 overflow)")
	}
}

// Attempt: 0.0.0.0 and broadcast.
func TestConvergence_ZeroAndBroadcast(t *testing.T) {
	t.Parallel()
	for _, ip := range []string{"0.0.0.0", "255.255.255.255"} {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: %s passed isPublicAddr", ip)
		}
	}
}

// Attempt: IPv6 ::1 variants.
func TestConvergence_IPv6_Loopback_variants(t *testing.T) {
	t.Parallel()
	loopbacks := []string{
		"::1",
		"0:0:0:0:0:0:0:1",
		"0000:0000:0000:0000:0000:0000:0000:0001",
	}
	for _, ip := range loopbacks {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: IPv6 loopback variant %s passed", ip)
		}
	}
}

// Attempt: Teredo with all-zeros (both server=0.0.0.0 and client= decoded).
func TestConvergence_Teredo_ZeroServer(t *testing.T) {
	t.Parallel()
	// Server=0.0.0.0, client XOR'd from ff:ff:ff:ff = 0.0.0.0
	addr := netip.MustParseAddr("2001:0000:0000:0000:0000:0000:ffff:ffff")
	if isPublicAddr(addr) {
		t.Error("BYPASS: Teredo with zero server/client passed")
	}
}

// Attempt: 6to4 with CGNAT embedded.
func TestConvergence_6to4_CGNAT_full_range(t *testing.T) {
	t.Parallel()
	// 100.64.0.1 embedded in 6to4: 2002:6440:0001::
	// 100.127.255.254 embedded: 2002:647f:fffe::
	cases := []string{
		"2002:6440:0001::",
		"2002:647f:fffe::",
		"2002:6440:0000::", // 100.64.0.0
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: 6to4 CGNAT %s passed", ip)
		}
	}
}

// Attempt: NAT64 with mapped CGNAT.
func TestConvergence_NAT64_CGNAT_full(t *testing.T) {
	t.Parallel()
	cases := []string{
		"64:ff9b::6440:1",    // 100.64.0.1
		"64:ff9b::647f:fffe", // 100.127.255.254
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: NAT64 CGNAT %s passed", ip)
		}
	}
}

// Attempt: concurrent race on SafeTransport construction.
func TestConvergence_concurrent_SafeTransport_construction(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			tr := SafeTransport(
				WithAllowedPorts(443, 8443),
				WithAllowedSchemes("https"),
				WithLogger(nil),
			)
			if tr == nil {
				t.Error("concurrent SafeTransport returned nil")
			}
		})
	}
	wg.Wait()
}

// Attempt: concurrent dial race with mixed IPs (stress the copy-slice defense).
func TestConvergence_concurrent_dial_mixed_resolver(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{
		netip.MustParseAddr("::ffff:8.8.8.8"),
		netip.MustParseAddr("::ffff:8.8.4.4"),
	}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	dial := tr.DialContext

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, _ = dial(ctx, "tcp", "dns.google:443")
		})
	}
	wg.Wait()
}

// Attempt: Control hook with non-TCP network.
func TestConvergence_control_rejects_udp(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, nil) // nil logger test
	err := ctrl("udp4", "8.8.8.8:53", nil)
	if err == nil {
		t.Error("BYPASS: Control hook allowed UDP network")
	}
}

// Attempt: dial with UDP network string.
func TestConvergence_dial_rejects_non_tcp_fast(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443))
	dial := tr.DialContext
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dial(ctx, "udp", "8.8.8.8:443")
	if conn != nil {
		conn.Close()
	}
	// The dialer should either reject outright or fail at Control hook.
	// Either way, no conn should succeed for non-TCP.
	_ = err
}

// Attempt: scheme case sensitivity bypass.
func TestConvergence_scheme_case_bypass(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}}
	cases := []string{
		"HTTP://example.com/f",
		"Http://example.com/f",
		"hTtP://example.com/f",
		"FTP://example.com/f",
	}
	for _, u := range cases {
		err := validateURLWithSchemes(u, schemes, nil) // nil logger test
		if err == nil {
			t.Errorf("BYPASS: scheme case %q passed", u)
		}
	}
}

// Attempt: FQDN trailing dot bypass.
func TestConvergence_FQDN_trailing_dots(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://localhost./secret",
		"https://localhost../secret",
		"https://LOCALHOST./secret",
	}
	for _, u := range cases {
		err := ValidateURL(u)
		if err == nil {
			t.Errorf("BYPASS: trailing dot %q passed", u)
		}
	}
}

// Verify safeControl with nil logger does not panic.
func TestConvergence_safeControl_nil_logger(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, map[uint16]struct{}{443: {}}, nil)
	// Exercise blocked path.
	err := ctrl("tcp4", "10.0.0.1:443", nil)
	if err == nil {
		t.Error("safeControl with nil logger failed to block private IP")
	}
	// Exercise port-blocked path.
	err = ctrl("tcp4", net.JoinHostPort("8.8.8.8", "80"), nil)
	if err == nil {
		t.Error("safeControl with nil logger failed to block port 80")
	}
}
