package ssrf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// budgetResolver answers a DNS lookup only when the context it is handed
// carries at least minBudget of remaining time. It lets a test assert the
// size of the DNS-lookup timeout budget that safeDialContext grants, without
// depending on wall-clock sleeps.
type budgetResolver struct {
	ips       []netip.Addr
	minBudget time.Duration
}

func (b budgetResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	dl, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("DNS context carried no deadline")
	}
	if remaining := time.Until(dl); remaining < b.minBudget {
		return nil, fmt.Errorf("DNS budget too short: %v remaining, need >= %v", remaining, b.minBudget)
	}
	return b.ips, nil
}

// loopbackIPs builds n distinct 127.0.0.x addresses for dial-cap fixtures.
func loopbackIPs(n int) []netip.Addr {
	ips := make([]netip.Addr, n)
	for i := range ips {
		ips[i] = netip.AddrFrom4([4]byte{127, 0, 0, byte(i + 1)})
	}
	return ips
}

// --- safeDialContext (resolve-once validation) ---

func TestSafeDialContext_blocks_private_ip_resolution(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil)
	_, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Error("safeDialContext() = nil, want error for loopback IP")
	}
}

func TestSafeDialContext_blocks_private_range(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil)
	_, err := dial(context.Background(), "tcp", "192.168.1.1:443")
	if err == nil {
		t.Error("safeDialContext() = nil, want error for private IP")
	}
}

func TestSafeDialContext_invalid_address_returns_error(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil)
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
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, net.DefaultResolver, nil)
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

func TestSafeDialContext_empty_resolution_blocked(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: nil}
	tr := SafeTransport(WithResolver(r))
	_, err := tr.DialContext(context.Background(), "tcp", "evil.com:443")
	if err == nil {
		t.Fatal("DialContext() = nil, want error when resolver returns no IPs")
	}
	var ssrfError *Error
	if !errors.As(err, &ssrfError) || ssrfError.Kind != KindDNSFailed {
		t.Errorf("DialContext() error = %v, want KindDNSFailed", err)
	}
	if !strings.Contains(err.Error(), "no IPs resolved") {
		t.Errorf("DialContext() error = %q, want no IPs resolved message", err.Error())
	}
}

func TestSafeDialContext_context_cancelled_before_dial(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dial := safeDialContext(&net.Dialer{Timeout: 2 * time.Second}, isPublicAddr, r, nil)

	_, err := dial(ctx, "tcp", "example.com:443")

	if err == nil {
		t.Fatal("safeDialContext with cancelled context = nil, want context cancelled error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("safeDialContext err = %v, want wrapped context.Canceled", err)
	}
}

// A disallowed-but-valid port (80 when only 443 is permitted) must surface
// KindBadPort at the dial layer's fail-fast port check.
func TestSafeDialContext_disallowed_port_kind(t *testing.T) {
	t.Parallel()
	dial := safeDialContext(
		&net.Dialer{Timeout: 2 * time.Second},
		isPublicAddr, net.DefaultResolver,
		map[uint16]struct{}{443: {}},
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

// safeDialContext must give the DNS lookup a generous (5s) timeout budget.
// A resolver that needs at least 1s of budget succeeds under real code but
// fails if the 5*time.Second budget is shrunk to 5/time.Second (== 0), which
// would make every DNS lookup time out immediately.
func TestSafeDialContext_gives_dns_lookup_a_generous_budget(t *testing.T) {
	t.Parallel()

	allowAll := func(netip.Addr) bool { return true }
	r := budgetResolver{minBudget: time.Second, ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	dial := safeDialContext(&net.Dialer{Timeout: 250 * time.Millisecond}, allowAll, r, map[uint16]struct{}{1: {}})

	_, err := dial(context.Background(), "tcp", "slow-dns.example:1")

	if err == nil {
		t.Fatalf("dial(slow-dns.example:1) = nil err, want a dial failure on loopback:1")
	}
	var sErr *Error
	if errors.As(err, &sErr) && sErr.Kind == KindDNSFailed {
		t.Errorf("dial(slow-dns.example:1) = KindDNSFailed (%v); want the DNS lookup to succeed under the 5s budget", err)
	}
}

// safeDialContext caps dial attempts only when the resolved set is strictly
// larger than maxDialIPs. At exactly maxDialIPs the full set is dialed and no
// "ssrf dial capped" warning is emitted; one IP over the limit triggers the
// cap and the warning. This pins the boundary so flipping `>` to `>=` (which
// would cap and warn at exactly maxDialIPs) is caught.
//
// Not parallel: it swaps slog.Default() to capture the cap warning.
func TestSafeDialContext_caps_dial_attempts_only_above_maxDialIPs(t *testing.T) {
	allowAll := func(netip.Addr) bool { return true }

	cases := []struct {
		name     string
		resolved int
		wantCap  bool
	}{
		{"exactly maxDialIPs is not capped", maxDialIPs, false},
		{"one over maxDialIPs is capped", maxDialIPs + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			r := &mockResolver{ips: loopbackIPs(tc.resolved)}
			dial := safeDialContext(&net.Dialer{Timeout: 100 * time.Millisecond}, allowAll, r, map[uint16]struct{}{1: {}})

			_, _ = dial(context.Background(), "tcp", "many.example:1")

			gotCap := strings.Contains(buf.String(), "ssrf dial capped")
			if gotCap != tc.wantCap {
				t.Errorf("resolved=%d: %q logged = %v, want %v (log=%q)", tc.resolved, "ssrf dial capped", gotCap, tc.wantCap, buf.String())
			}
		})
	}
}

// --- safeControl (defense-in-depth re-validation at socket time) ---

func TestSafeControl_blocks_non_tcp(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil)
	err := ctrl("udp4", "8.8.8.8:443", nil)
	if err == nil {
		t.Error("safeControl() = nil, want error for non-TCP network")
	}
}

// TestSafeControl_blocks_private_ips_table re-validates a representative IP from
// each non-public IPv4 range plus IPv6 loopback/ULA/link-local at the Control
// hook — the socket-time DNS-rebinding/TOCTOU backstop. Folds the red-team
// Control re-validation rounds.
func TestSafeControl_blocks_private_ips_table(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil)
	v4 := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.1.1", "100.64.0.1", "0.1.2.3", "240.0.0.1",
	}
	for _, ip := range v4 {
		if err := ctrl("tcp4", ip+":443", nil); err == nil {
			t.Errorf("safeControl(tcp4, %s) = nil, want error", ip)
		}
	}
	v6 := []string{"::1", "fc00::1", "fe80::1"}
	for _, ip := range v6 {
		if err := ctrl("tcp6", "["+ip+"]:443", nil); err == nil {
			t.Errorf("safeControl(tcp6, %s) = nil, want error", ip)
		}
	}
}

func TestSafeControl_allows_public_ip(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil)
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
	ctrl := safeControl(isPublicAddr, ports)
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
	ctrl := safeControl(isPublicAddr, ports)
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
	ctrl := safeControl(isPublicAddr, nil)
	err := ctrl("tcp4", "8.8.8.8:12345", nil)
	if err != nil {
		t.Errorf("safeControl() = %v, want nil when no port restrictions", err)
	}
}

func TestSafeControl_rejects_malformed_inputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		ports   map[uint16]struct{}
		network string
		address string
	}{
		{"no port", nil, "tcp4", "no-port-here"},
		{"non-ip host", nil, "tcp4", "example.com:443"},
		{"non-ip host with port allowlist", map[uint16]struct{}{443: {}}, "tcp4", "example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := safeControl(isPublicAddr, tc.ports)
			err := ctrl(tc.network, tc.address, nil)
			if err == nil {
				t.Errorf("safeControl(%q, %q) = nil, want error", tc.network, tc.address)
			}
			var ssrfError *Error
			if !errors.As(err, &ssrfError) {
				t.Errorf("safeControl(%q, %q) error is not *Error: %T", tc.network, tc.address, err)
			}
		})
	}
}

func TestSafeControl_unparseable_port_with_allowlist(t *testing.T) {
	t.Parallel()
	ports := map[uint16]struct{}{443: {}}
	ctrl := safeControl(isPublicAddr, ports)

	err := ctrl("tcp4", "8.8.8.8:notaport", nil)

	if err == nil {
		t.Fatal("safeControl(tcp4, 8.8.8.8:notaport) = nil, want error for unparseable port")
	}
	var ssrfError *Error
	if !errors.As(err, &ssrfError) || ssrfError.Kind != KindBadPort {
		t.Errorf("safeControl(tcp4, 8.8.8.8:notaport) Kind = %v, want KindBadPort", err)
	}
}

// Control hook blocks an IPv6 link-local literal carrying a zone ID.
func TestRegression_control_hook_zone_id(t *testing.T) {
	t.Parallel()
	ctrl := safeControl(isPublicAddr, nil)
	err := ctrl("tcp6", "[fe80::1%eth0]:443", nil)
	if err == nil {
		t.Error("Control hook did not block link-local with zone ID")
	}
}

// Control hook re-validates IPv4-mapped IPv6 forms of every blocked range
// (the socket-time backstop must Unmap before classifying).
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

// safeDialContext must reject invalid port strings when port restrictions are
// configured, rather than silently skipping validation.
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

// Resolver returning mapped IPv6 of every blocked range is blocked at the
// dial layer (Unmap before classification).
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
		{"mapped CGNAT boundary", "::ffff:100.127.255.255"},
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

// Resolver returning a mix of public and private IPs must block the whole
// request (fail closed on the first non-public resolved IP).
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

// safeDialContext must not mutate the slice returned by the resolver. A caching
// resolver (or the mock) may return the same backing array to concurrent
// callers; in-place Unmap caused a data race.
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

// A caller-supplied net.Dialer.ControlContext must NOT bypass the SSRF
// socket-time re-validation hook. net.Dialer semantics give a non-nil
// ControlContext precedence over Control, so safeDialContext clears
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

// safeDialContext caps dial attempts at maxDialIPs (8) even when the resolver
// returns more policy-passing IPs, bounding total dial time. Every resolved IP
// is still validated (fail-closed); the cap only limits how many of the
// validated set are dialed. Counts SSRF-policy invocations: the resolve-once
// loop calls the policy once per resolved IP (all 20 pass), then safeControl
// calls it once per dial attempt, so (total - resolved) == the dial attempts.
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
