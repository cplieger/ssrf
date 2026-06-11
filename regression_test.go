package ssrf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Regression: safeDialContext must not mutate the slice returned by the
// resolver. A caching resolver (or the mock in tests) may return the same
// backing array to concurrent callers; in-place Unmap caused a data race.
func TestRegression_concurrent_dial_no_race(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443, 80))
	dial := tr.DialContext

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, _ = dial(ctx, "tcp", "example.com:443")
		})
	}
	wg.Wait()
}

// Regression: safeDialContext must reject invalid port strings when port
// restrictions are configured, rather than silently skipping validation.
func TestRegression_dial_invalid_port_rejected(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(
		&net.Dialer{Timeout: 2 * time.Second},
		isPublicAddr,
		net.DefaultResolver,
		map[uint16]struct{}{443: {}},
	)
	cases := []struct {
		name string
		addr string
	}{
		{"overflow", "8.8.8.8:65536"},
		{"negative", "8.8.8.8:-1"},
		{"alpha", "8.8.8.8:abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := dial(context.Background(), "tcp", tc.addr)
			if err == nil {
				t.Errorf("dial(%q) = nil, want error for invalid port", tc.addr)
			}
			var ssrfError *Error
			if !errors.As(err, &ssrfError) {
				t.Fatalf("dial(%q) error = %v, want *ssrf.Error", tc.addr, err)
			}
			if ssrfError.Kind != KindBadPort {
				t.Errorf("dial(%q) Kind = %v, want KindBadPort", tc.addr, ssrfError.Kind)
			}
			if !strings.Contains(err.Error(), "port") {
				t.Errorf("dial(%q) error = %q, want port-related error", tc.addr, err.Error())
			}
		})
	}
}

// Verify: mapped IPv6 of every blocked range is rejected at all check paths.
func TestRegression_mapped_all_ranges_control_hook(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil)
	cases := []struct {
		name string
		ip   string
	}{
		{"mapped loopback", "::ffff:127.0.0.1"},
		{"mapped private 10", "::ffff:10.0.0.1"},
		{"mapped private 172.16", "::ffff:172.16.0.1"},
		{"mapped private 192.168", "::ffff:192.168.1.1"},
		{"mapped CGNAT", "::ffff:100.64.0.1"},
		{"mapped link-local", "::ffff:169.254.1.1"},
		{"mapped this-host", "::ffff:0.1.2.3"},
		{"mapped reserved 240", "::ffff:240.0.0.1"},
		{"mapped TEST-NET-1", "::ffff:192.0.2.1"},
		{"mapped TEST-NET-2", "::ffff:198.51.100.1"},
		{"mapped TEST-NET-3", "::ffff:203.0.113.1"},
		{"mapped benchmarking", "::ffff:198.18.0.1"},
		{"mapped 6to4 relay", "::ffff:192.88.99.1"},
		{"mapped IETF proto", "::ffff:192.0.0.1"},
		{"mapped broadcast", "::ffff:255.255.255.255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ctrl("tcp6", net.JoinHostPort(tc.ip, "443"), nil)
			if err == nil {
				t.Errorf("safeControl did not block %s", tc.ip)
			}
		})
	}
}

// Verify: resolver returning mapped addresses is blocked at dial layer.
func TestRegression_mapped_all_ranges_dial(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"mapped loopback", "::ffff:127.0.0.1"},
		{"mapped private 10", "::ffff:10.0.0.1"},
		{"mapped private 172.16", "::ffff:172.16.0.1"},
		{"mapped private 192.168", "::ffff:192.168.1.1"},
		{"mapped CGNAT", "::ffff:100.64.0.1"},
		{"mapped link-local", "::ffff:169.254.1.1"},
		{"mapped this-host", "::ffff:0.1.2.3"},
		{"mapped reserved 240", "::ffff:240.0.0.1"},
		{"mapped TEST-NET-1", "::ffff:192.0.2.1"},
		{"mapped TEST-NET-2", "::ffff:198.51.100.1"},
		{"mapped TEST-NET-3", "::ffff:203.0.113.1"},
		{"mapped benchmarking", "::ffff:198.18.0.1"},
		{"mapped 6to4 relay", "::ffff:192.88.99.1"},
		{"mapped IETF proto", "::ffff:192.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr(tc.ip)}}
			tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
			dial := tr.DialContext
			_, err := dial(context.Background(), "tcp", "evil.com:443")
			if err == nil {
				t.Errorf("dial did not block resolver returning %s", tc.ip)
			}
		})
	}
}

// Verify: resolver returning mixed public+private IPs blocks the request.
func TestRegression_resolver_mixed_ips_blocked(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("10.0.0.1"),
	}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "evil.com:443")
	if err == nil {
		t.Error("resolver returning mixed public+private IPs should be blocked")
	}
}

// Verify: Control hook blocks IPv6 with zone IDs.
func TestRegression_control_hook_zone_id(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil)
	err := ctrl("tcp6", "[fe80::1%eth0]:443", nil)
	if err == nil {
		t.Error("Control hook did not block link-local with zone ID")
	}
}

// Regression: a caller-supplied net.Dialer.ControlContext must NOT bypass
// the SSRF socket-time re-validation hook. net.Dialer semantics give a
// non-nil ControlContext precedence over Control, so safeDialContext clears
// ControlContext before installing safeControl as Control. This proves the
// caller hook never runs and that safeControl fires (the connect is
// re-validated) -- the DNS-rebinding/TOCTOU defense-in-depth layer.
func TestRegression_dialer_controlcontext_cleared(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	callerHookRan := false
	policyCalls := 0
	countPolicy := func(_ netip.Addr) bool {
		mu.Lock()
		policyCalls++
		mu.Unlock()
		return true
	}

	caller := &net.Dialer{
		Timeout: 250 * time.Millisecond,
		ControlContext: func(_ context.Context, _, _ string, _ syscall.RawConn) error {
			mu.Lock()
			callerHookRan = true
			mu.Unlock()
			return nil
		},
	}

	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	dial := safeDialContext(caller, countPolicy, r, map[uint16]struct{}{9: {}})

	// Loopback:9 fails to connect (no service), but both Control hooks fire
	// at socket creation before the connect, which is all this asserts.
	_, _ = dial(context.Background(), "tcp", "rebind.example:9")

	mu.Lock()
	defer mu.Unlock()
	if callerHookRan {
		t.Error("caller-supplied ControlContext ran; safeControl was bypassed (ControlContext not cleared)")
	}
	if policyCalls != 2 {
		t.Errorf("policy calls = %d, want 2 (1 resolve-loop validation + 1 safeControl re-validation); safeControl hook did not fire", policyCalls)
	}
}

// Regression: safeDialContext caps dial attempts at maxDialIPs (8) even when
// the resolver returns more policy-passing IPs, bounding total dial time
// against an attacker-controlled resolver. Every resolved IP is still
// validated (fail-closed); the cap only limits how many of the validated set
// are dialed. Counts SSRF-policy invocations: the resolve-once loop calls the
// policy once per resolved IP (all 20 pass), then safeControl calls it once
// per dial attempt, so (total - resolved) == the number of dial attempts.
func TestRegression_caps_dial_attempts_at_maxDialIPs(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	policyCalls := 0
	countPolicy := func(_ netip.Addr) bool {
		mu.Lock()
		policyCalls++
		mu.Unlock()
		return true
	}

	const resolved = 20
	ips := make([]netip.Addr, resolved)
	for i := range ips {
		ips[i] = netip.AddrFrom4([4]byte{127, 0, 0, byte(i + 1)})
	}
	r := &mockResolver{ips: ips}

	dial := safeDialContext(
		&net.Dialer{Timeout: 250 * time.Millisecond},
		countPolicy,
		r,
		map[uint16]struct{}{9: {}},
	)

	// All 20 loopback IPs pass the (allow-all) policy in the resolve-once loop;
	// the dialer then attempts at most maxDialIPs of them on loopback:9 (no
	// service -> each attempt fails fast and the loop continues).
	_, _ = dial(context.Background(), "tcp", "many-ips.example:9")

	mu.Lock()
	total := policyCalls
	mu.Unlock()

	dialAttempts := total - resolved
	if dialAttempts != 8 {
		t.Errorf("dial attempts = %d, want 8 (maxDialIPs cap); total policy calls=%d resolved=%d", dialAttempts, total, resolved)
	}
}
