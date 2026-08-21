package ssrf

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/cplieger/runesafe/v2"
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

		// Bracketed URL-authority IPv6 syntax. IsPublicHost takes a HOST, not a
		// URL authority, so every bracketed form is now refused rather than
		// silently reinterpreted. This is a deliberate behavior change: the
		// bracket-strip it replaced was the shape that bypassed smokescreen's
		// deny list (CVE-2022-29188), and ValidateURL never reaches here with
		// brackets because url.Hostname() removes them first. A direct caller
		// passing raw authority syntax uses url.Hostname or net.SplitHostPort.
		{"bracketed IPv4-mapped private rejected", "[::ffff:192.168.1.1]", false},
		{"bracketed IPv4-mapped loopback rejected", "[::ffff:127.0.0.1]", false},
		{"bracketed embedded-IPv4 documentation rejected", "[2001:db8::1.2.3.4]", false},
		{"bracketed public IPv6 rejected as authority syntax", "[2606:4700:4700::1111]", false},

		// The same, with a trailing dot. Previously these needed a dedicated
		// double-trim guard so a dot after the closing bracket could not defeat
		// the bracket strip; refusing brackets outright retires that guard.
		{"bracketed IPv4-mapped private trailing dot rejected", "[::ffff:192.168.1.1].", false},
		{"bracketed IPv4-mapped loopback trailing dot rejected", "[::ffff:127.0.0.1].", false},
		{"bracketed IPv4-mapped private double trailing dot rejected", "[::ffff:10.0.0.1]..", false},
		{"bracketed public IPv6 trailing dot rejected", "[2606:4700:4700::1111].", false},

		// The unbracketed literals the bracketed forms above used to reach.
		{"unbracketed public IPv6 accepted", "2606:4700:4700::1111", true},
		{"unbracketed public IPv6 trailing dot accepted", "2606:4700:4700::1111.", true},

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

// endsInNumber implements WHATWG's "ends in a number" checker, which decides
// whether a name's rightmost label makes the whole name an IPv4 address rather
// than a domain. It replaced isNumericLabel, whose cases are carried over here.
//
// The two spec details worth pinning, because both differ from the old helper:
// "0x" ALONE qualifies (the spec says "zero or more ASCII hex digits", so the
// hex tail may be empty), and a digit-LEADING label that is not fully numeric
// does not qualify, which is what keeps a private zone like "svc.3internal"
// resolvable.
func TestEndsInNumber(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		label string
		want  bool
	}{
		{"empty label", "", false},
		{"decimal", "127", true},
		{"single digit", "1", true},
		{"oversized inet_aton part", "16962", true},
		{"lowercase hex", "0x7f", true},
		{"uppercase X prefix and digits", "0XAB", true},
		{"invalid hex digit", "0xZZ", false},
		{"0x prefix only is a number per the spec", "0x", true},
		{"decimal with letter", "1a", false},
		{"digit-leading private TLD", "3internal", false},
		{"real TLD", "com", false},
		{"IDN A-label TLD", "xn--p1ai", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := endsInNumber(tc.label); got != tc.want {
				t.Errorf("endsInNumber(%q) = %v, want %v", tc.label, got, tc.want)
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
	if ssrfError, ok := errors.AsType[*Error](err); !ok || ssrfError.Kind != KindBadScheme {
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
// configures the same policy as its lowercase form. The fold covers the whole
// ASCII letter range, both ends included: a scheme spelled with the last letter
// of the alphabet has to match as readily as one spelled with the first, and the
// digits and separators of a registered scheme have to survive the fold
// untouched. The constructor side is the side that matters, because url.Parse
// has already lowercased the scheme by the time Validate compares it.
func TestNewURLPolicy_folds_constructor_schemes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		schemes []string
		url     string
	}{
		{"http_and_https", []string{"HTTPS", "HTTP"}, "http://example.com/f"},
		{"every_ascii_letter", []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}, "abcdefghijklmnopqrstuvwxyz://example.com/f"},
		// A registered scheme mixing the last letter of the alphabet with digits
		// and a dot (Z39.50 over TLS, RFC 2056).
		{"digits_and_dot_around_letters", []string{"Z39.50S"}, "z39.50s://example.com/f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := NewURLPolicy(tt.schemes...).Validate(tt.url); err != nil {
				t.Errorf("NewURLPolicy(%q).Validate(%q) = %v, want nil", tt.schemes, tt.url, err)
			}
		})
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

// --- The validation path is silent ---

// Every entry point on the validation path returns its verdict and logs
// nothing. Validation computes: the *Error carries Kind, Host, Msg and Err, so
// the caller already holds everything a log line could say, and whether to
// record it is the caller's decision.
//
// Two things depend on this. A predicate with a hidden write to a global sink
// is the defect Google's global-state guidance names for library providers, and
// the caller cannot see, configure or silence that sink. And the text these
// paths would log is caller-supplied, so a hostile host would reach a JSON
// handler with its C1 and Bidi_Control runes intact (slog escapes only what
// JSON requires). Refusing to log is what closes both, and it costs nothing the
// returned error does not already carry.
//
// This test mutates slog.Default(), so it is NOT parallel — the testing
// framework runs non-parallel tests to completion before parallel ones start,
// so the global default is never swapped under a concurrent test. It captures
// at Debug so a line at ANY level fails it, not just a Warn.
func TestValidationPathIsSilent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	hosts := []string{"10.0.0.1", "127.0.0.1", "localhost", "internal", "192.168.1.1"}
	for _, host := range hosts {
		if IsPublicHost(host) {
			t.Errorf("IsPublicHost(%q) = true, want false", host)
		}
		if err := ValidateURL("https://" + host); err == nil {
			t.Errorf("ValidateURL(https://%s) = nil, want error", host)
		}
		if err := (URLPolicy{}).Validate("https://" + host); err == nil {
			t.Errorf("URLPolicy{}.Validate(https://%s) = nil, want error", host)
		}
		if err := NewURLPolicy("http").Validate("http://" + host); err == nil {
			t.Errorf("NewURLPolicy(\"http\").Validate(http://%s) = nil, want error", host)
		}
	}
	if got := buf.String(); got != "" {
		t.Errorf("the validation path emitted %q, want no output: a validator returns "+
			"its verdict and lets the caller decide whether to record it", got)
	}
}

// A rejected host's Msg must not carry raw control runes. The host reaches Msg
// through fmt.Sprintf, and %q escapes every rune the four unsafe classes cover,
// which is why the interpolations use it — Google recommends %q for exactly
// this, "output intended for humans where the input value could possibly be
// empty or contain control characters".
//
// This is the wider of the two exposures: Msg travels to every consumer that
// prints the error, including sinks that are not slog and do no escaping.
//
// It calls hostValidationError rather than ValidateURL because url.Parse
// rejects a raw control character in a URL, so these branches are only
// reachable through the host-level entry point ([IsPublicHost] shares this
// core). Each case asserts the Kind it expects: two earlier versions of this
// test were vacuous — the first appended a newline, which the then-existing
// interior-whitespace gate caught first, and the second appended U+007F, which
// url.Parse rejected before any host branch ran. Both passed with the fix
// reverted, so the Kind assertion is what keeps this test honest.
func TestErrorMsgEscapesControlRunes(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		host string
		kind ErrorKind
	}{
		// Every host carrying an unsafe rune now lands on the canonical-host
		// gate, which refuses non-ASCII before any structural check. That is
		// one branch instead of the two this test used to straddle, and its
		// message interpolates with %q like the rest.
		"bare hostname, RLO":         {"internal\u202e", KindInvalidHost},
		"bare hostname, arabic mark": {"internal\u061c", KindInvalidHost},
		"interior tab":               {"example.com\t\u202e", KindInvalidHost},
		"interior space":             {"example.com \u202e", KindInvalidHost},
		// An ASCII-only structural refusal takes the same %q path, so the
		// escaping is pinned for a host with no unsafe rune in it too.
		"ascii control via authority syntax": {"example.com[\u007f]", KindInvalidHost},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			verr := hostValidationError(tc.host)
			if verr == nil {
				t.Fatalf("hostValidationError(%q) = nil, want a rejection: the case must "+
					"witness a rejecting branch to be measuring one", tc.host)
			}
			if verr.Kind != tc.kind {
				t.Fatalf("hostValidationError(%q) Kind = %d, want %d: the fixture landed on "+
					"a different branch than the one under test", tc.host, verr.Kind, tc.kind)
			}
			for _, r := range verr.Msg {
				if runesafe.IsUnsafeSingleLine(r) {
					t.Errorf("hostValidationError(%q) Msg = %q, want no unsafe rune; "+
						"found U+%04X", tc.host, verr.Msg, r)
				}
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

// equalASCIIFold must fold the ASCII letters and nothing else. The Unicode
// launderings below are the whole point: strings.EqualFold accepts them and
// this package must not, because a host's grammar is ASCII (RFC 1035; an
// internationalized name arrives as an "xn--" A-label).
func TestEqualASCIIFold(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		s, u string
		want bool
	}{
		{"identical", "localhost", "localhost", true},
		{"upper vs lower", "LOCALHOST", "localhost", true},
		{"mixed case", "LocalHost", "localhost", true},
		{"different length", "localhos", "localhost", false},
		{"different letter", "localhoxt", "localhost", false},
		{"long s launders under Unicode folding", "localho\u017ft", "localhost", false},
		{"kelvin sign launders under Unicode folding", "\u212Aafka", "kafka", false},
		{"dotted capital I launders under strings.ToLower", "\u0130nternal", "internal", false},
		{"Unicode 17 fold pair U+0390/U+1FD3", "\u0390", "\u1FD3", false},
		{"Unicode 17 fold pair U+03B0/U+1FE3", "\u03B0", "\u1FE3", false},
		{"Unicode 17 fold pair U+FB05/U+FB06", "\uFB05", "\uFB06", false},
		{"empty vs empty", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := equalASCIIFold(tc.s, tc.u); got != tc.want {
				t.Errorf("equalASCIIFold(%q, %q) = %v, want %v", tc.s, tc.u, got, tc.want)
			}
		})
	}
}

// The launderings above must actually launder, or the divergence cases are
// stale and assert nothing. Note the two relations are NOT interchangeable and
// the guard therefore splits by relation: U+0130 lowercases to "i" but does not
// FOLD with it, while U+212A does both. Measured on go1.26.7 and go1.27.0,
// U+0130 and U+212A are the only two non-ASCII runes whose strings.ToLower image
// is pure ASCII. The three pairs began folding in Unicode 17 (Go 1.27), which is
// why the go directive is the floor for this test.
func TestEqualASCIIFold_divergesFromUnicodeFolding(t *testing.T) {
	t.Parallel()
	folds := [][2]string{
		{"localho\u017ft", "localhost"},
		{"\u212Aafka", "kafka"},
		{"\u0390", "\u1FD3"},
		{"\u03B0", "\u1FE3"},
		{"\uFB05", "\uFB06"},
	}
	for _, p := range folds {
		if !strings.EqualFold(p[0], p[1]) {
			t.Errorf("strings.EqualFold(%q, %q) = false; this input no longer launders, so the divergence case is stale", p[0], p[1])
		}
	}
	lowers := [][2]string{
		{"\u0130nternal", "internal"},
		{"\u212Aafka", "kafka"},
	}
	for _, p := range lowers {
		if strings.ToLower(p[0]) != p[1] {
			t.Errorf("strings.ToLower(%q) = %q, want %q; this input no longer launders, so the divergence case is stale", p[0], strings.ToLower(p[0]), p[1])
		}
	}
	// The distinction itself, pinned: a rune can launder under one relation and
	// not the other, which is why neither strings.ToLower nor strings.EqualFold
	// can stand in for the other at a security comparison.
	if strings.EqualFold("\u0130nternal", "internal") {
		t.Error(`strings.EqualFold("\u0130nternal", "internal") = true; U+0130 now folds as well as lowercases, so the ToLower-only case is stale`)
	}
}

// No single-rune substitution into "localhost" is ever accepted, whichever fold
// relation is used. This is the invariant the EqualFold -> equalASCIIFold change
// rests on: measured over all 1,114,112 code points at all nine positions, the
// two relations disagree on exactly one input ("localho\u017ft") and the
// accept/reject verdict does not move for it — only the Kind, from KindLocalhost
// to the more accurate KindBareHostname.
func TestHostValidation_noRuneSubstitutionIntoLocalhostIsAccepted(t *testing.T) {
	t.Parallel()
	const base = "localhost"
	divergences := 0
	for r := rune(0); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF { // surrogates are not scalar values
			continue
		}
		sub := string(r)
		for i := range base {
			letter := base[i : i+1]
			uni, ascii := strings.EqualFold(sub, letter), equalASCIIFold(sub, letter)
			if !uni && !ascii {
				continue // not a fold candidate here; the other gates own it
			}
			if uni != ascii {
				divergences++
			}
			cand := base[:i] + sub + base[i+1:]
			if verr := hostValidationError(cand); verr == nil {
				t.Fatalf("hostValidationError(%q) = nil (U+%04X at %d), want a rejection", cand, r, i)
			}
		}
	}
	if divergences != 1 {
		t.Errorf("fold relations disagree on %d substitutions, want exactly 1 (localho\\u017ft)", divergences)
	}
}

// A laundered localhost stays rejected; it is simply named for what it is.
func TestHostValidation_localhostKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		want ErrorKind
	}{
		{"localhost", KindLocalhost},
		{"LOCALHOST", KindLocalhost},
		{"LocalHost", KindLocalhost},
		// The root label is stripped in normalization, ahead of the localhost
		// fold, precisely so this keeps its specific diagnostic.
		{"localhost.", KindLocalhost},
		// Under Unicode folding this was KindLocalhost. It is not localhost —
		// no resolver maps it to loopback — and it is now refused one step
		// earlier, as a non-ASCII host, rather than as a bare hostname.
		{"localho\u017ft", KindInvalidHost},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			verr := hostValidationError(tc.host)
			if verr == nil {
				t.Fatalf("hostValidationError(%q) = nil, want a rejection", tc.host)
			}
			if verr.Kind != tc.want {
				t.Errorf("hostValidationError(%q) Kind = %d, want %d", tc.host, verr.Kind, tc.want)
			}
		})
	}
}
