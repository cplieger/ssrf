package ssrf

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
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
		slog.Default(),
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
			if !strings.Contains(err.Error(), "port") {
				t.Errorf("dial(%q) error = %q, want port-related error", tc.addr, err.Error())
			}
			_ = ssrfError
		})
	}
}

// Verify: mapped IPv6 of every blocked range is rejected at all check paths.
func TestRegression_mapped_all_ranges_control_hook(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
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
	ctrl := safeControl(isPublicAddr, nil, slog.Default())
	err := ctrl("tcp6", "[fe80::1%eth0]:443", nil)
	if err == nil {
		t.Error("Control hook did not block link-local with zone ID")
	}
}
