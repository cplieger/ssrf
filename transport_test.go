package ssrf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// mockResolver implements Resolver for testing WithResolver: it returns a fixed
// IP set (and optional error) for any queried name. Shared across the
// transport, dialer, and keep-alive test files.
type mockResolver struct {
	err error
	ips []netip.Addr
}

func (m *mockResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return m.ips, m.err
}

// --- WithAddressPolicy ---

func TestWithAddressPolicy_blocks_specific_host(t *testing.T) {
	t.Parallel()
	blocked := netip.MustParseAddr("8.8.8.8")
	policy := func(addr netip.Addr) bool {
		return addr != blocked
	}
	tr := SafeTransport(WithAddressPolicy(policy))
	dial := tr.DialContext

	_, err := dial(context.Background(), "tcp", "8.8.8.8:443")
	if err == nil {
		t.Error("expected error for policy-blocked IP 8.8.8.8, got nil")
	}
}

func TestWithAddressPolicy_allows_normally_blocked_ip(t *testing.T) {
	t.Parallel()
	allowAll := func(_ netip.Addr) bool { return true }
	tr := SafeTransport(WithAddressPolicy(allowAll))
	dial := tr.DialContext

	// 127.0.0.1 is normally blocked; with allow-all policy it should
	// attempt the dial (will fail to connect, but the SSRF check passes).
	_, err := dial(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "not public") {
		t.Errorf("allow-all policy still blocked 127.0.0.1: %v", err)
	}
}

func TestWithAddressPolicy_nil_uses_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAddressPolicy(nil))
	dial := tr.DialContext

	_, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Error("nil policy should fall back to default; expected error for loopback")
	}
}

func TestWithAddressPolicy_deny_all(t *testing.T) {
	t.Parallel()
	denyAll := func(_ netip.Addr) bool { return false }
	tr := SafeTransport(WithAddressPolicy(denyAll))
	dial := tr.DialContext

	_, err := dial(context.Background(), "tcp", "1.1.1.1:443")
	if err == nil {
		t.Error("deny-all policy should block 1.1.1.1, got nil")
	}
	if !strings.Contains(err.Error(), "not public") {
		t.Errorf("expected SSRF policy error, got: %v", err)
	}
}

func TestWithAddressPolicy_and_WithDialer_combined(t *testing.T) {
	t.Parallel()
	allowed := netip.MustParseAddr("198.41.0.4")
	policy := func(addr netip.Addr) bool { return addr == allowed }
	d := &net.Dialer{Timeout: 50 * time.Millisecond}

	tr := SafeTransport(WithAddressPolicy(policy), WithDialer(d))
	dial := tr.DialContext

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 1.1.1.1 should be blocked by the custom policy.
	_, err := dial(ctx, "tcp", "1.1.1.1:443")
	if err == nil {
		t.Error("custom policy should block 1.1.1.1")
	}
	if !strings.Contains(err.Error(), "not public") {
		t.Errorf("expected SSRF policy error for 1.1.1.1, got: %v", err)
	}

	// 198.41.0.4 should pass policy (but may fail to connect — timeout).
	_, err = dial(ctx, "tcp", "198.41.0.4:80")
	if err != nil && strings.Contains(err.Error(), "not public") {
		t.Errorf("custom policy should allow 198.41.0.4, got SSRF error: %v", err)
	}
}

// A custom WithAddressPolicy denial reports KindPolicyDenied (the documented
// "custom policy rejected the IP" kind). 1.1.1.1 resolves to itself (literal
// IP, no DNS), so the resolve-loop policy check denies it before any socket
// opens.
func TestSafeTransport_custom_policy_denial_kind(t *testing.T) {
	t.Parallel()
	denyAll := func(_ netip.Addr) bool { return false }
	tr := SafeTransport(WithAddressPolicy(denyAll))
	_, err := tr.DialContext(context.Background(), "tcp", "1.1.1.1:443")
	var ssrfError *Error
	if !errors.As(err, &ssrfError) {
		t.Fatalf("DialContext() error = %v, want *ssrf.Error", err)
	}
	if ssrfError.Kind != KindPolicyDenied {
		t.Errorf("custom-policy denial Kind = %d, want KindPolicyDenied (%d)", ssrfError.Kind, KindPolicyDenied)
	}
}

// The default policy (no WithAddressPolicy) must keep emitting KindNonPublicIP,
// not KindPolicyDenied — the denyKind wiring must not alter default behavior.
func TestSafeTransport_default_policy_denial_kind(t *testing.T) {
	t.Parallel()
	tr := SafeTransport()
	_, err := tr.DialContext(context.Background(), "tcp", "10.0.0.1:443")
	var ssrfError *Error
	if !errors.As(err, &ssrfError) {
		t.Fatalf("DialContext() error = %v, want *ssrf.Error", err)
	}
	if ssrfError.Kind != KindNonPublicIP {
		t.Errorf("default-policy denial Kind = %d, want KindNonPublicIP (%d)", ssrfError.Kind, KindNonPublicIP)
	}
}

// --- WithDialer ---

func TestWithDialer_custom_timeout(t *testing.T) {
	t.Parallel()
	d := &net.Dialer{Timeout: 1 * time.Millisecond}
	tr := SafeTransport(WithDialer(d))
	if tr.DialContext == nil {
		t.Fatal("SafeTransport(WithDialer(...)).DialContext is nil")
	}
}

func TestWithDialer_records_calls(t *testing.T) {
	t.Parallel()
	d := &net.Dialer{Timeout: 50 * time.Millisecond}
	tr := SafeTransport(WithDialer(d))
	dial := tr.DialContext

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 198.41.0.4 is a public IP (a.root-servers.net) that won't respond on port 80.
	_, err := dial(ctx, "tcp", "198.41.0.4:80")
	if err == nil {
		t.Error("expected timeout/connection error to non-responding IP, got nil")
	}
}

func TestWithDialer_nil_uses_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithDialer(nil))
	if tr == nil {
		t.Fatal("SafeTransport(WithDialer(nil)) returned nil")
	}
}

// --- WithResolver ---

func TestWithResolver_custom(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	tr := SafeTransport(WithResolver(r))
	if tr.DialContext == nil {
		t.Fatal("SafeTransport(WithResolver(...)).DialContext is nil")
	}
}

func TestWithResolver_blocks_private(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	tr := SafeTransport(WithResolver(r))
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "evil.com:443")
	if err == nil {
		t.Error("expected error for resolver returning private IP")
	}
	if !strings.Contains(err.Error(), "not public") {
		t.Errorf("expected SSRF error, got: %v", err)
	}
}

func TestWithResolver_nil_uses_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithResolver(nil))
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Error("nil resolver should use default; expected error for loopback")
	}
}

// Resolver returning the link-local cloud-metadata IP must be blocked at the
// dial layer (the resolve-once SSRF check), simulating a DNS-rebinding answer.
func TestSafeDialContext_blocks_resolver_metadata_ip(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
	tr := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	_, err := tr.DialContext(context.Background(), "tcp", "evil.com:443")
	if err == nil {
		t.Error("resolver returning link-local metadata IP was not blocked")
	}
}

// --- SafeTransport construction / options ---

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
	// Exact-value pins: a shrunk multiplier (10*time.Second -> 10/time.Second
	// = 0) would silently disable these caps. 0 means "no timeout", which
	// re-opens a slow-TLS-handshake / slow-100-continue stall vector.
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("SafeTransport().TLSHandshakeTimeout = %v, want 10s cap on the TLS handshake", tr.TLSHandshakeTimeout)
	}
	if tr.ExpectContinueTimeout != time.Second {
		t.Errorf("SafeTransport().ExpectContinueTimeout = %v, want 1s before sending the request body", tr.ExpectContinueTimeout)
	}
}

// A nil TransportOption element in the variadic must be skipped (not
// dereferenced, which would panic), and the default policy must still block
// private IPs.
func TestSafeTransport_nil_option_element(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(nil, nil, WithAllowedPorts(443), nil)
	if tr == nil || tr.DialContext == nil {
		t.Fatal("SafeTransport with nil elements returned nil")
	}
	_, err := tr.DialContext(context.Background(), "tcp", "10.0.0.1:443")
	if err == nil {
		t.Error("nil option elements broke default policy")
	}
}

// TransportOption application is order-independent: a resolver returning a private IP is
// blocked whether WithResolver precedes or follows WithAllowedPorts.
func TestSafeTransport_option_order_independent(t *testing.T) {
	t.Parallel()
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}

	tr1 := SafeTransport(WithResolver(r), WithAllowedPorts(443))
	_, err1 := tr1.DialContext(context.Background(), "tcp", "evil.com:443")

	tr2 := SafeTransport(WithAllowedPorts(443), WithResolver(r))
	_, err2 := tr2.DialContext(context.Background(), "tcp", "evil.com:443")

	if err1 == nil {
		t.Error("order A: private IP from resolver was not blocked")
	}
	if err2 == nil {
		t.Error("order B: private IP from resolver was not blocked")
	}
}

func TestSafeTransport_control_hook_fires(t *testing.T) {
	t.Parallel()
	allowAll := func(_ netip.Addr) bool { return true }
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	tr := SafeTransport(WithAddressPolicy(allowAll), WithResolver(r), WithAnyPort())
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "evil.com:1")
	if err != nil && strings.Contains(err.Error(), "not public") {
		t.Errorf("allow-all policy should pass Control hook, got: %v", err)
	}
}

// --- Port allowlist (WithAllowedPorts) ---

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
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "tcp", "8.8.8.8:80")
	if err != nil && strings.Contains(err.Error(), "not allowed") {
		t.Errorf("port 80 should be allowed, got: %v", err)
	}
}

// An empty WithAllowedPorts() call must retain the 443-only default, never
// silently widen to all ports (an accidentally-empty config slice must not
// remove a security boundary).
func TestWithAllowedPorts_empty_retains_default(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts())
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "8.8.8.8:12345")
	if err == nil {
		t.Error("empty WithAllowedPorts() should retain the 443-only default")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected port-not-allowed error, got: %v", err)
	}
}

func TestWithAnyPort_allows_all(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAnyPort())
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
	tr := SafeTransport()
	dial := tr.DialContext
	_, err := dial(context.Background(), "tcp", "8.8.8.8:80")
	if err == nil {
		t.Error("default should only allow port 443")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected port error, got: %v", err)
	}
}

// TestSafeTransport_port_allowlist_blocks_common blocks a spread of common
// service ports when only 443 is permitted (stronger than the single-port case).
func TestSafeTransport_port_allowlist_blocks_common(t *testing.T) {
	t.Parallel()
	tr := SafeTransport(WithAllowedPorts(443))
	dial := tr.DialContext
	blockedPorts := []string{"80", "8080", "22", "3306", "6379", "11211"}
	for _, port := range blockedPorts {
		_, err := dial(context.Background(), "tcp", "8.8.8.8:"+port)
		if err == nil {
			t.Errorf("port %s allowed when only 443 permitted, want blocked", port)
		}
	}
}
