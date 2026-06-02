package ssrf

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// ROUND 4: FINAL CONVERGENCE RED-TEAM
// Verifies round-3 nil-logger fix and attempts novel bypasses.
// =============================================================================

// --- NIL LOGGER GUARD VERIFICATION (all 4 internal funcs) ---

func TestR4_nilLogger_validateURLWithSchemes(t *testing.T) {
	t.Parallel()
	// Must not panic with nil logger.
	err := validateURLWithSchemes("https://10.0.0.1/x", nil, nil)
	if err == nil {
		t.Error("expected block for private IP with nil logger")
	}
	// Scheme mismatch path.
	err = validateURLWithSchemes("ftp://example.com", nil, nil)
	if err == nil {
		t.Error("expected block for ftp scheme with nil logger")
	}
}

func TestR4_nilLogger_validateHostWithLogger(t *testing.T) {
	t.Parallel()
	err := validateHostWithLogger("127.0.0.1", nil)
	if err == nil {
		t.Error("expected block for loopback with nil logger")
	}
	err = validateHostWithLogger("localhost", nil)
	if err == nil {
		t.Error("expected block for localhost with nil logger")
	}
}

func TestR4_nilLogger_safeControl(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, map[uint16]struct{}{443: {}}, nil)
	// Block private.
	err := ctrl("tcp4", "192.168.1.1:443", nil)
	if err == nil {
		t.Error("safeControl nil logger failed to block private IP")
	}
}

func TestR4_nilLogger_safeDialContext(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	d := &net.Dialer{Timeout: 2 * time.Second}
	dial := safeDialContext(d, isPublicAddr, r, map[uint16]struct{}{443: {}}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dial(ctx, "tcp", "evil.test:443")
	if err == nil {
		t.Error("safeDialContext nil logger failed to block private IP")
	}
}

// --- BYPASS ATTACKS: MAPPED CGNAT + ALL BLOCKED RANGES ---

func TestR4_mappedCGNAT_IPv4Mapped(t *testing.T) {
	t.Parallel()
	// ::ffff:100.64.x.x = IPv4-mapped CGNAT
	cases := []string{
		"::ffff:100.64.0.1",
		"::ffff:100.127.255.254",
		"::ffff:100.100.100.100",
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: mapped CGNAT %s passed isPublicAddr", ip)
		}
	}
}

func TestR4_allBlockedRanges_comprehensive(t *testing.T) {
	t.Parallel()
	blocked := []string{
		// RFC 1918
		"10.0.0.1", "172.16.0.1", "192.168.0.1",
		// CGNAT
		"100.64.0.1", "100.127.255.254",
		// Loopback
		"127.0.0.1", "127.255.255.255",
		// Link-local
		"169.254.1.1", "fe80::1",
		// This host
		"0.0.0.1", "0.255.255.255",
		// Class E
		"240.0.0.1", "255.255.255.254",
		// Broadcast
		"255.255.255.255",
		// IETF protocol assignments
		"192.0.0.1",
		// TEST-NETs
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		// Benchmarking
		"198.18.0.1", "198.19.255.254",
		// 6to4 relay anycast
		"192.88.99.1",
		// IPv6 discard
		"100::1",
		// IPv6 benchmarking
		"2001:2::1",
		// Documentation
		"2001:db8::1", "3fff::1",
		// SRv6 SIDs
		"5f00::1",
		// Multicast
		"224.0.0.1", "ff02::1",
		// Unspecified
		"0.0.0.0", "::",
		// IPv6 loopback
		"::1",
		// IPv6 private (ULA)
		"fd00::1", "fc00::1",
	}
	for _, ip := range blocked {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: blocked range IP %s passed isPublicAddr", ip)
		}
	}
}

// --- TEREDO/NAT64/6TO4 EXTRACTION ---

func TestR4_teredo_extraction_privateServer(t *testing.T) {
	t.Parallel()
	// Teredo: 2001:0000:<server4bytes>:<flags>:<portXOR>:<clientXOR>
	// Server = 10.0.0.1 = 0a000001, client = 8.8.8.8 XOR ffff = f7f7f7f7
	addr := netip.MustParseAddr("2001:0000:0a00:0001:0000:0000:f7f7:f7f7")
	if isPublicAddr(addr) {
		t.Error("BYPASS: Teredo with private server 10.0.0.1 passed")
	}
}

func TestR4_teredo_extraction_privateClient(t *testing.T) {
	t.Parallel()
	// Server = 8.8.8.8, client = 192.168.1.1 XOR ffff = 3f57fefe
	addr := netip.MustParseAddr("2001:0000:0808:0808:0000:0000:3f57:fefe")
	if isPublicAddr(addr) {
		t.Error("BYPASS: Teredo with private client 192.168.1.1 passed")
	}
}

func TestR4_nat64_extraction_private(t *testing.T) {
	t.Parallel()
	// 64:ff9b::<private IPv4>
	cases := []string{
		"64:ff9b::a00:1",    // 10.0.0.1
		"64:ff9b::c0a8:101", // 192.168.1.1
		"64:ff9b::ac10:1",   // 172.16.0.1
		"64:ff9b::7f00:1",   // 127.0.0.1
		"64:ff9b::6440:1",   // 100.64.0.1 (CGNAT)
		"64:ff9b::a9fe:101", // 169.254.1.1 (link-local)
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: NAT64 %s with private embedded passed", ip)
		}
	}
}

func TestR4_6to4_extraction_allPrivate(t *testing.T) {
	t.Parallel()
	// 2002:<IPv4 bytes>::
	cases := []string{
		"2002:0a00:0001::", // 10.0.0.1
		"2002:ac10:0001::", // 172.16.0.1
		"2002:c0a8:0101::", // 192.168.1.1
		"2002:7f00:0001::", // 127.0.0.1
		"2002:6440:0001::", // 100.64.0.1 CGNAT
		"2002:a9fe:0101::", // 169.254.1.1 link-local
		"2002:c000:0201::", // 192.0.2.1 TEST-NET-1
		"2002:c612:0001::", // 198.18.0.1 benchmarking
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: 6to4 %s with private/reserved embedded passed", ip)
		}
	}
}

func TestR4_ipv4compat_extraction(t *testing.T) {
	t.Parallel()
	// ::10.0.0.1 (IPv4-compatible, deprecated RFC 4291)
	cases := []string{
		"::10.0.0.1",
		"::127.0.0.1",
		"::192.168.1.1",
		"::100.64.0.1",
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: IPv4-compatible %s passed", ip)
		}
	}
}

func TestR4_nat64Local_blocked_outright(t *testing.T) {
	t.Parallel()
	// 64:ff9b:1::/48 is blocked outright (non-standard embedding offset)
	cases := []string{
		"64:ff9b:1::1",
		"64:ff9b:1:ffff::1",
		"64:ff9b:1:abcd::8.8.8.8",
	}
	for _, ip := range cases {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: NAT64 local %s passed (should be blocked outright)", ip)
		}
	}
}

// --- DIAL-TIME CONTROL RE-VALIDATION ---

func TestR4_dialControl_revalidation_rebind(t *testing.T) {
	t.Parallel()
	// Simulate DNS rebinding: resolver returns public IP, but the Control hook
	// sees a private IP (simulated by calling Control directly).
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	// Control should block if actual IP is private.
	privateIPs := []string{"10.0.0.1:443", "192.168.1.1:80", "127.0.0.1:443", "100.64.0.1:443"}
	for _, addr := range privateIPs {
		err := ctrl("tcp4", addr, nil)
		if err == nil {
			t.Errorf("BYPASS: Control hook allowed private IP %s", addr)
		}
	}
}

// --- PORT/SCHEME ALLOWLIST WITH CASE FOLDING ---

func TestR4_scheme_caseFolding_exhaustive(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}, "http": {}}
	blocked := []string{
		"FTP://example.com/f",
		"Ftp://example.com/f",
		"GOPHER://example.com/f",
		"file:///etc/passwd",
		"FILE:///etc/passwd",
		"javascript:alert(1)",
		"JAVASCRIPT:alert(1)",
		"data:text/html,<script>",
	}
	for _, u := range blocked {
		err := validateURLWithSchemes(u, schemes, slog.Default())
		if err == nil {
			t.Errorf("BYPASS: scheme %q passed validation", u)
		}
	}
	// Allowed cases (case-insensitive match).
	allowed := []string{
		"HTTPS://example.com/ok",
		"Https://example.com/ok",
		"HTTP://example.com/ok",
		"Http://example.com/ok",
	}
	for _, u := range allowed {
		err := validateURLWithSchemes(u, schemes, slog.Default())
		if err != nil {
			t.Errorf("scheme %q should be allowed, got: %v", u, err)
		}
	}
}

func TestR4_port_allowlist_enforcement(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443, 8443))
	dial := tr.DialContext
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Port 80 should be blocked.
	_, err := dial(ctx, "tcp", "8.8.8.8:80")
	if err == nil {
		t.Error("BYPASS: port 80 passed with allowlist [443,8443]")
	}
	// Port 22 should be blocked.
	_, err = dial(ctx, "tcp", "8.8.8.8:22")
	if err == nil {
		t.Error("BYPASS: port 22 passed with allowlist [443,8443]")
	}
}

// --- DNS REBINDING DEFENSE (resolver flip) ---

func TestR4_dnsRebinding_controlHookDefense(t *testing.T) {
	t.Parallel()
	// The Control hook validates at socket time. If somehow the dialer
	// connects to a different IP, Control blocks it.
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	// Simulate rebind: original resolve was 8.8.8.8 but connection goes to 10.0.0.1
	err := ctrl("tcp4", "10.0.0.1:443", nil)
	if err == nil {
		t.Error("BYPASS: Control hook failed to catch DNS rebind to private IP")
	}
}

// --- CONCURRENT DIAL RACE ---

func TestR4_concurrent_dial_race(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	dial := tr.DialContext

	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			conn, _ := dial(ctx, "tcp", "example.com:443")
			if conn != nil {
				conn.Close()
			}
		})
	}
	wg.Wait()
}

// --- WithLogger nil guard ---

func TestR4_WithLogger_nil_retains_default(t *testing.T) {
	t.Parallel()
	// WithLogger(nil) should be ignored, retaining slog.Default().
	tr := SafeTransport(WithLogger(nil))
	if tr == nil {
		t.Fatal("SafeTransport with WithLogger(nil) returned nil")
	}
	// Exercise the logging path with a blocked IP.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := tr.DialContext(ctx, "tcp", "10.0.0.1:443")
	if err == nil {
		t.Error("WithLogger(nil) broke default policy")
	}
}

// --- WithPolicy nil guard ---

func TestR4_WithPolicy_nil_retains_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithPolicy(nil))
	if tr == nil {
		t.Fatal("SafeTransport with WithPolicy(nil) returned nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := tr.DialContext(ctx, "tcp", "10.0.0.1:443")
	if err == nil {
		t.Error("WithPolicy(nil) broke default policy")
	}
}

// --- WithResolver nil guard ---

func TestR4_WithResolver_nil_retains_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithResolver(nil))
	if tr == nil {
		t.Fatal("SafeTransport with WithResolver(nil) returned nil")
	}
}

// --- WithDialer nil guard ---

func TestR4_WithDialer_nil_retains_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithDialer(nil))
	if tr == nil {
		t.Fatal("SafeTransport with WithDialer(nil) returned nil")
	}
}

// --- Edge: double-mapped IPv6 addresses ---

func TestR4_doubleMapped_IPv6(t *testing.T) {
	t.Parallel()
	// Ensure ::ffff:127.0.0.1 is blocked (Unmap handles this).
	mapped := []string{
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:192.168.1.1",
		"::ffff:172.16.0.1",
		"::ffff:100.64.0.1",
		"::ffff:169.254.1.1",
		"::ffff:0.0.0.1",
		"::ffff:240.0.0.1",
	}
	for _, ip := range mapped {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("BYPASS: mapped address %s passed isPublicAddr", ip)
		}
	}
}
