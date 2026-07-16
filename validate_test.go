package ssrf

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
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
		{"empty IPv6 brackets rejected", "https://[]/secret", true},
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
		{"loopback trailing whitespace", "127.0.0.1 ", false},
		{"private", "192.168.1.1", false},
		{"bare hostname", "internal", false},
		{"empty", "", false},
		{"IPv6 ULA", "fc00::1", false},
		{"IPv4-mapped private", "::ffff:10.0.0.1", false},
		{"CGNAT", "100.64.0.1", false},

		// Bracketed URL-authority IPv6 syntax (l-f1): IsPublicHost mirrors
		// url.Hostname() bracket-stripping, so a bracketed IPv4-mapped/embedded
		// internal literal is rejected while a genuinely public bracketed IPv6
		// literal still passes — staying consistent with ValidateURL.
		{"bracketed IPv4-mapped private rejected", "[::ffff:192.168.1.1]", false},
		{"bracketed IPv4-mapped loopback rejected", "[::ffff:127.0.0.1]", false},
		{"bracketed embedded-IPv4 documentation rejected", "[2001:db8::1.2.3.4]", false},
		{"bracketed public IPv6 accepted", "[2606:4700:4700::1111]", true},

		// Trailing-dot-after-bracket bypass (h-f1): a trailing FQDN dot after
		// the closing bracket must not defeat the bracket-strip guard and let a
		// bracketed internal literal fall through as PUBLIC.
		{"bracketed IPv4-mapped private trailing dot rejected", "[::ffff:192.168.1.1].", false},
		{"bracketed IPv4-mapped loopback trailing dot rejected", "[::ffff:127.0.0.1].", false},
		{"bracketed IPv4-mapped private double trailing dot rejected", "[::ffff:10.0.0.1]..", false},
		{"bracketed public IPv6 trailing dot accepted", "[2606:4700:4700::1111].", true},

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

// Regression (h-f1): ValidateURL must reject non-canonical IPv4 encodings.
// netip.ParseAddr is strict and rejects dotted-octal/hex/short/oversized
// inet_aton forms, so before the looksLikeNumericIPv4 gate they slipped past
// the "has a dot => hostname" arm and ValidateURL returned nil — yet glibc
// getaddrinfo resolves e.g. 0177.0.0.1 / 0x7f.0.0.1 / 127.1 to 127.0.0.1,
// reaching internal addresses for a consumer using ValidateURL standalone.
func TestValidateURL_rejects_noncanonical_ipv4(t *testing.T) {
	t.Parallel()
	rejected := []string{
		"https://0177.0.0.1/x",    // dotted-octal loopback
		"https://0x7f.0.0.1/x",    // dotted-hex loopback (mixed hex/decimal labels)
		"https://127.1/x",         // short-form loopback
		"https://169.254.16962/x", // oversized inet_aton link-local
		"https://192.168.257/x",   // oversized inet_aton private
		// Fully dotted-hex loopback encodings: every label is a 0x-prefixed hex
		// integer, so each octet is classified by the hex-digit scanner (unlike
		// the mixed encoding above, whose decimal octets bypass it). glibc
		// getaddrinfo reads each of these as 127.0.0.x, so all must be rejected
		// as non-canonical IPv4 encodings. The low/high hex digit in the final
		// label (0, 9, a, F) exercises both ends of the decimal, lowercase, and
		// uppercase hex-digit ranges.
		"https://0x7f.0x0.0x0.0x1/x", // 127.0.0.1
		"https://0x7f.0x0.0x0.0x9/x", // 127.0.0.9
		"https://0x7f.0x0.0x0.0xa/x", // 127.0.0.10
		"https://0x7f.0x0.0x0.0xF/x", // 127.0.0.15
	}
	for _, u := range rejected {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURL(u); err == nil {
				t.Errorf("ValidateURL(%q) = nil, want rejection of non-canonical IPv4 encoding", u)
			}
		})
	}

	// Legitimate hosts must still pass: a real DNS name never has an all-numeric
	// label set. 8.8.8.8.in-addr.arpa is the reverse-DNS form (non-numeric
	// trailing labels), 1and1.com has an alphanumeric first label.
	allowed := []string{
		"https://example.com/x",
		"https://1and1.com/x",
		"https://8.8.8.8.in-addr.arpa/x",
	}
	for _, u := range allowed {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURL(u); err != nil {
				t.Errorf("ValidateURL(%q) = %v, want nil (legitimate host)", u, err)
			}
		})
	}
}

func TestIsNumericLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		label string
		want  bool
	}{
		{"empty label", "", false},
		{"decimal", "127", true},
		{"lowercase hex", "0x7f", true},
		{"uppercase X prefix and digits", "0XAB", true},
		{"invalid hex digit", "0xZZ", false},
		{"0x prefix only", "0x", false},
		{"decimal with letter", "1a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isNumericLabel(tc.label); got != tc.want {
				t.Errorf("isNumericLabel(%q) = %v, want %v", tc.label, got, tc.want)
			}
		})
	}
}

// --- Scheme allowlist (URLPolicy.Validate) ---

func TestURLPolicyValidate_rejects_disallowed(t *testing.T) {
	t.Parallel()
	err := NewURLPolicy("https").Validate("http://example.com/f")
	if err == nil {
		t.Error("expected error for http when only https allowed")
	}
	var ssrfError *Error
	if !errors.As(err, &ssrfError) || ssrfError.Kind != KindBadScheme {
		t.Errorf("expected KindBadScheme, got %v", err)
	}
}

func TestURLPolicyValidate_allows_http_when_configured(t *testing.T) {
	t.Parallel()
	err := NewURLPolicy("https", "http").Validate("http://example.com/f")
	if err != nil {
		t.Errorf("http should be allowed, got: %v", err)
	}
}

func TestURLPolicyValidate_case_insensitive(t *testing.T) {
	t.Parallel()
	err := NewURLPolicy("https").Validate("HTTPS://example.com/f")
	if err != nil {
		t.Errorf("HTTPS (uppercase) should match, got: %v", err)
	}
}

// NewURLPolicy lowercases constructor arguments, so an uppercase scheme
// configures the same policy as its lowercase form.
func TestNewURLPolicy_folds_constructor_schemes(t *testing.T) {
	t.Parallel()
	err := NewURLPolicy("HTTPS", "HTTP").Validate("http://example.com/f")
	if err != nil {
		t.Errorf("constructor scheme case should be folded, got: %v", err)
	}
}

// The zero-value URLPolicy validates HTTPS-only, matching ValidateURL.
func TestURLPolicy_zero_value_validates_https_only(t *testing.T) {
	t.Parallel()
	var policy URLPolicy
	if err := policy.Validate("http://example.com/f"); err == nil {
		t.Error("zero-value URLPolicy should block http")
	}
	if err := policy.Validate("https://example.com/f"); err != nil {
		t.Errorf("zero-value URLPolicy should allow https, got: %v", err)
	}
}

// URLPolicy.Validate matches schemes case-insensitively: disallowed schemes
// are blocked in any case, and allowed schemes pass in any case. Folds the
// red-team scheme-casing rounds into one table; "dict" exercises a gopher-class
// SSRF scheme that must stay blocked under an http/https allowlist.
func TestURLPolicyValidate_scheme_casefolding(t *testing.T) {
	t.Parallel()
	policy := NewURLPolicy("https", "http")
	blocked := []string{
		"FTP://example.com/f",
		"Ftp://example.com/f",
		"GOPHER://example.com/f",
		"file:///etc/passwd",
		"FILE:///etc/passwd",
		"javascript:alert(1)",
		"JAVASCRIPT:alert(1)",
		"data:text/html,<script>",
		"dict://evil.com:11211/stat",
	}
	for _, u := range blocked {
		if err := policy.Validate(u); err == nil {
			t.Errorf("scheme %q passed validation, want blocked", u)
		}
	}
	allowed := []string{
		"HTTPS://example.com/ok",
		"Https://example.com/ok",
		"HTTP://example.com/ok",
		"Http://example.com/ok",
	}
	for _, u := range allowed {
		if err := policy.Validate(u); err != nil {
			t.Errorf("scheme %q should be allowed, got: %v", u, err)
		}
	}
}

// Under an https-only allowlist, every case variant of a non-https scheme must
// be rejected (the comparison lowercases the scheme before the set lookup).
func TestURLPolicyValidate_case_variants_blocked_https_only(t *testing.T) {
	t.Parallel()
	policy := NewURLPolicy("https")
	cases := []string{
		"HTTP://example.com/f",
		"Http://example.com/f",
		"hTtP://example.com/f",
		"FTP://example.com/f",
	}
	for _, u := range cases {
		if err := policy.Validate(u); err == nil {
			t.Errorf("scheme case %q passed, want blocked under https-only", u)
		}
	}
}

// A URL whose host is empty brackets ("[]") must be rejected, not treated as a
// public host.
func TestValidateURL_empty_brackets_rejected(t *testing.T) {
	t.Parallel()
	if err := ValidateURL("https://[]/secret"); err == nil {
		t.Error("ValidateURL(https://[]/secret) = nil, want error for empty brackets")
	}
}

// --- Enforcement vs predicate logging ---

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

// ValidateURL is the enforcement path: each rejection Kind maps to a distinct
// "reason" attribute on the "ssrf blocked" Warn (emitted by
// validateURLWithSchemes), which block dashboards group on. This pins the
// Kind->reason mapping so a swapped map entry (a mutant) is caught. Not
// parallel: it mutates slog.Default().
func TestValidateURL_emits_reason_per_kind(t *testing.T) {
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

			if err := ValidateURL("https://" + tc.host); err == nil {
				t.Fatalf("ValidateURL(https://%s) = nil, want error", tc.host)
			}

			got := buf.String()
			if !strings.Contains(got, "reason="+tc.wantReason) {
				t.Errorf("ValidateURL(https://%s) block log = %q, want reason=%q", tc.host, got, tc.wantReason)
			}
		})
	}
}

// Direct IsPublicHost predicate coverage (l-f2): the suite pins non-canonical
// numeric IPv4 encodings and interior-whitespace shapes through ValidateURL and
// a one-way fuzz oracle, but never asserts the predicate itself returns false
// for them. This pins both guards directly, so removing the looksLikeNumericIPv4
// gate or the interior-whitespace check fails here even if the enforcement-path
// tests are untouched.
func TestIsPublicHost_rejects_noncanonical_ipv4_and_whitespace(t *testing.T) {
	t.Parallel()
	cases := []string{
		"0177.0.0.1",            // dotted-octal loopback
		"0x7f.0.0.1",            // dotted-hex loopback (mixed hex/decimal labels)
		"127.1",                 // short-form loopback
		"169.254.16962",         // oversized inet_aton link-local
		"192.168.257",           // oversized inet_aton private
		"0x7f.0x0.0x0.0x1",      // fully dotted-hex loopback
		"127.0.0.1 example.com", // interior whitespace
		"example .com",          // interior whitespace
		"example.com\t.evil",    // interior tab
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			if IsPublicHost(host) {
				t.Errorf("IsPublicHost(%q) = true, want false", host)
			}
		})
	}
}
