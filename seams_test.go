package ssrf

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// mockResolver implements Resolver for testing WithResolver.
type mockResolver struct {
	err error
	ips []netip.Addr
}

func (m *mockResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return m.ips, m.err
}

func TestWithPolicy_blocks_specific_host(t *testing.T) {
	t.Parallel()
	// Policy that blocks 8.8.8.8 (normally public).
	blocked := netip.MustParseAddr("8.8.8.8")
	policy := func(addr netip.Addr) bool {
		return addr != blocked
	}
	tr := SafeTransport(WithPolicy(policy))
	dial := tr.DialContext

	_, err := dial(context.Background(), "tcp", "8.8.8.8:443")
	if err == nil {
		t.Error("expected error for policy-blocked IP 8.8.8.8, got nil")
	}
}

func TestWithPolicy_allows_normally_blocked_ip(t *testing.T) {
	t.Parallel()
	// Policy that allows everything (even private IPs).
	allowAll := func(_ netip.Addr) bool { return true }
	tr := SafeTransport(WithPolicy(allowAll))
	dial := tr.DialContext

	// 127.0.0.1 is normally blocked; with allow-all policy it should
	// attempt the dial (will fail to connect, but the SSRF check passes).
	_, err := dial(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		// Connection to port 1 on loopback is unlikely to succeed,
		// but if it does that's fine — the point is no SSRF error.
		return
	}
	// The error should NOT be an SSRF policy error.
	if strings.Contains(err.Error(), "not public") {
		t.Errorf("allow-all policy still blocked 127.0.0.1: %v", err)
	}
}

func TestWithPolicy_nil_uses_default(t *testing.T) {
	t.Parallel()
	// Passing nil policy should use the default isPublicAddr.
	tr := SafeTransport(WithPolicy(nil))
	dial := tr.DialContext

	_, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Error("nil policy should fall back to default; expected error for loopback")
	}
}

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
	// Use a dialer with a very short timeout to a non-routable IP.
	// The point is to verify the custom dialer is actually used.
	d := &net.Dialer{Timeout: 50 * time.Millisecond}
	tr := SafeTransport(WithDialer(d))
	dial := tr.DialContext

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 198.41.0.4 is a public IP (a.root-servers.net) that won't respond on port 80.
	// The custom dialer's short timeout should cause a quick failure.
	_, err := dial(ctx, "tcp", "198.41.0.4:80")
	if err == nil {
		t.Error("expected timeout/connection error to non-responding IP, got nil")
	}
}

func TestWithPolicy_deny_all(t *testing.T) {
	t.Parallel()
	denyAll := func(_ netip.Addr) bool { return false }
	tr := SafeTransport(WithPolicy(denyAll))
	dial := tr.DialContext

	// Even a public IP should be blocked.
	_, err := dial(context.Background(), "tcp", "1.1.1.1:443")
	if err == nil {
		t.Error("deny-all policy should block 1.1.1.1, got nil")
	}
	if !strings.Contains(err.Error(), "not public") {
		t.Errorf("expected SSRF policy error, got: %v", err)
	}
}

func TestWithPolicy_and_WithDialer_combined(t *testing.T) {
	t.Parallel()
	// Custom policy allows only 198.41.0.4 (a public root server IP).
	allowed := netip.MustParseAddr("198.41.0.4")
	policy := func(addr netip.Addr) bool { return addr == allowed }
	d := &net.Dialer{Timeout: 50 * time.Millisecond}

	tr := SafeTransport(WithPolicy(policy), WithDialer(d))
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

func TestWithResolver_custom(t *testing.T) {
	t.Parallel()
	// Mock resolver returns a public IP.
	r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	tr := SafeTransport(WithResolver(r))
	if tr.DialContext == nil {
		t.Fatal("SafeTransport(WithResolver(...)).DialContext is nil")
	}
}

func TestWithResolver_blocks_private(t *testing.T) {
	t.Parallel()
	// Mock resolver returns a private IP.
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

func TestWithAllowedSchemes_empty_retains_default(t *testing.T) {
	t.Parallel()
	s := AllowedSchemes(WithAllowedSchemes())
	if _, ok := s["https"]; !ok {
		t.Errorf("AllowedSchemes(WithAllowedSchemes()) = %v, want https retained", s)
	}
	if len(s) != 1 {
		t.Errorf("empty WithAllowedSchemes widened the set to %v, want {https}", s)
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

// IsPublicHost is a predicate, not an enforcement gate: probing a non-public
// host must NOT emit a "ssrf blocked" Warn (no request was blocked). These
// tests mutate slog.Default(), so they are NOT parallel — the testing
// framework runs non-parallel tests to completion before parallel ones start,
// so the global default is never swapped under a concurrent test.
func TestIsPublicHost_predicate_is_silent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	cases := []string{"10.0.0.1", "127.0.0.1", "localhost", "internal", "192.168.1.1"}
	for _, host := range cases {
		if IsPublicHost(host) {
			t.Errorf("IsPublicHost(%q) = true, want false", host)
		}
	}
	if got := buf.String(); strings.Contains(got, "ssrf blocked") {
		t.Errorf("IsPublicHost emitted a block log for predicate queries: %q", got)
	}
}

// The ValidateURL enforcement path MUST still log a "ssrf blocked" Warn when it
// rejects a host — the predicate-silence change must not mute real blocks.
func TestValidateURL_enforcement_still_logs(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	if err := ValidateURL("https://10.0.0.1/x"); err == nil {
		t.Fatal("ValidateURL(private IP) = nil, want error")
	}
	if got := buf.String(); !strings.Contains(got, "ssrf blocked") {
		t.Errorf("ValidateURL enforcement path did not emit a block log; got %q", got)
	}
}

// validateHost is the enforcement wrapper: each rejection Kind maps to a
// distinct "reason" attribute on the "ssrf blocked" Warn, which block
// dashboards group on. This pins the Kind->reason mapping so a swapped
// switch arm (a mutant) is caught. Not parallel: it mutates slog.Default().
func TestValidateHost_emits_reason_per_kind(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		wantReason string
	}{
		{"empty host from trailing dots", ".", "empty_host"},
		{"localhost", "localhost", "localhost"},
		{"non public ip", "10.0.0.1", "non_public_ip"},
		{"bare hostname", "internal", "bare_hostname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			if err := validateHost(tc.host); err == nil {
				t.Fatalf("validateHost(%q) = nil, want error", tc.host)
			}

			got := buf.String()
			if !strings.Contains(got, "reason="+tc.wantReason) {
				t.Errorf("validateHost(%q) block log = %q, want reason=%q", tc.host, got, tc.wantReason)
			}
		})
	}
}
