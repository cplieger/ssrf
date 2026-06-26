// Package ssrf provides URL validation and a hardened HTTP transport to prevent
// server-side request forgery (SSRF). Use this package to vet any URL before
// making an outbound HTTP request.
//
// Trust model: DNS resolution is delegated to net.DefaultResolver (or a custom
// resolver via [WithResolver]). safeDialContext resolves a hostname once and
// hands the resolved literal IPs to the dialer. Additionally, a [net.Dialer]
// Control hook validates the actually-connected IP at socket creation time,
// providing defense-in-depth against DNS rebinding/TOCTOU attacks even if the
// resolve-once layer is somehow bypassed.
//
// # Unsupported by design (SKIP list)
//
// The following features are intentionally NOT implemented:
//   - Custom allow/deny IP lists: WithPolicy(func(netip.Addr) bool) already provides this.
//   - Hostname allowlist/denylist: Application-layer policy, not core SSRF defense.
//   - Happy Eyeballs (RFC 8305): Security library prioritizes correctness over speed.
//   - Response body size limit: Use io.LimitReader at the application layer.
//   - Blanket 2001::/23 block: Overly broad; we block specific non-routable sub-ranges.
//   - ISATAP embedded IPv4: Uses fe80::/64 (already blocked) or routable prefixes.
//   - DNS-over-HTTPS/TLS resolver: WithResolver enables plugging in any implementation.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const schemeHTTPS = "https"

// maxRedirects is the maximum number of redirect hops a SafeRedirectPolicy
// will follow before refusing further redirects.
const maxRedirects = 10

// maxDialIPs caps how many already-validated resolved IPs the dialer will
// attempt, bounding total dial time against an attacker-controlled resolver
// returning many policy-passing IPs that all blackhole. Every resolved IP is
// still validated before dialing (fail-closed); this only limits dial attempts
// among the validated set. Defense-in-depth, matching smokescreen/safeurl.
const maxDialIPs = 8

// ErrorKind classifies SSRF validation failures. Consumers can use
// errors.As(*Error) and switch on Kind for programmatic handling,
// mirroring doyensec/safeurl's typed error approach.
type ErrorKind int

const (
	// KindInvalidURL indicates the URL could not be parsed.
	KindInvalidURL ErrorKind = iota + 1
	// KindBadScheme indicates the URL scheme is not allowed.
	KindBadScheme
	// KindEmptyHost indicates the URL has no host component.
	KindEmptyHost
	// KindLocalhost indicates the URL points to localhost.
	KindLocalhost
	// KindBareHostname indicates a hostname without dots (e.g. "internal").
	KindBareHostname
	// KindNonPublicIP indicates the resolved IP is not globally routable.
	KindNonPublicIP
	// KindDNSFailed indicates DNS resolution failed.
	KindDNSFailed
	// KindPolicyDenied indicates the custom policy rejected the IP.
	KindPolicyDenied
	// KindBadPort indicates the port is not in the allowed set.
	KindBadPort
	// KindTooManyRedirects indicates a redirect chain exceeded the hop limit.
	KindTooManyRedirects
)

// Error is a structured SSRF validation error with a machine-readable Kind.
type Error struct {
	// Err is the underlying error, if any.
	Err error
	// Msg is a human-readable description.
	Msg string
	// Host is the hostname or IP that triggered the error (may be empty).
	Host string
	Kind ErrorKind
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

func ssrfErr(kind ErrorKind, host, msg string, err error) *Error {
	return &Error{Kind: kind, Host: host, Msg: msg, Err: err}
}

// Policy controls whether a resolved IP address is allowed or denied.
// Return true to allow the connection, false to block it.
// The default policy (used when none is provided) is [IsPublicAddr].
type Policy func(addr netip.Addr) bool

// Resolver abstracts DNS resolution for testing and custom environments.
// The standard library's [net.Resolver] satisfies this interface.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Option configures [SafeTransport].
type Option func(*transportConfig)

type transportConfig struct {
	policy         Policy
	dialer         *net.Dialer
	resolver       Resolver
	allowedPorts   map[uint16]struct{}
	schemes        map[string]struct{}
	policyIsCustom bool
}

// WithPolicy sets a custom allow/deny policy for resolved IP addresses.
// The policy is called after unmapping IPv4-mapped IPv6 addresses.
// A nil policy is ignored (the default [IsPublicAddr] policy is retained).
func WithPolicy(p Policy) Option {
	return func(c *transportConfig) {
		if p != nil {
			c.policy = p
			c.policyIsCustom = true
		}
	}
}

// WithDialer sets a custom [net.Dialer] used for outbound connections.
// The dialer's DialContext is wrapped with SSRF-safe DNS resolution;
// callers can customize Timeout, KeepAlive, and other dialer fields.
// A nil dialer is ignored (the default dialer is retained).
//
// The dialer's Control hook is always overwritten with the SSRF socket-time
// IP re-validation hook and cannot be supplied by the caller; this is the
// defense-in-depth layer against DNS rebinding and must not be bypassed.
func WithDialer(d *net.Dialer) Option {
	return func(c *transportConfig) {
		if d != nil {
			c.dialer = d
		}
	}
}

// WithResolver sets a custom DNS resolver for hostname resolution.
// Useful for testing or environments with custom resolvers (e.g., CoreDNS sidecar).
// A nil resolver is ignored (net.DefaultResolver is retained).
func WithResolver(r Resolver) Option {
	return func(c *transportConfig) {
		if r != nil {
			c.resolver = r
		}
	}
}

// WithAllowedPorts sets the ports that outbound connections may target.
// By default only port 443 is allowed (matching HTTPS-only posture).
// Pass an empty slice to allow all ports. Mirrors doyensec/safeurl AllowedPorts.
//
// FAIL-OPEN asymmetry: an empty call here WIDENS to all ports -- the opposite
// of [WithAllowedSchemes] (empty = no-op, HTTPS-only retained) and of a non-nil
// empty [SafeRedirectPolicyWithSchemes] map (fail-closed, blocks every scheme).
// Guard against an accidentally-empty config slice at the call site:
// WithAllowedPorts(cfgPorts...) silently disables port restriction when
// cfgPorts is empty, rather than retaining the 443-only default.
func WithAllowedPorts(ports ...uint16) Option {
	return func(c *transportConfig) {
		if len(ports) == 0 {
			c.allowedPorts = nil // nil = all ports allowed
			return
		}
		m := make(map[uint16]struct{}, len(ports))
		for _, p := range ports {
			m[p] = struct{}{}
		}
		c.allowedPorts = m
	}
}

// WithAllowedSchemes sets the URL schemes used by [AllowedSchemes] and
// [SafeRedirectPolicyWithSchemes]. (ValidateURL itself is HTTPS-only.)
// By default only "https" is allowed. Mirrors doyensec/safeurl AllowedSchemes.
// Schemes are compared case-insensitively.
// Passing no schemes is a no-op: unlike WithAllowedPorts, an empty call does
// NOT widen the set to "all schemes" -- the HTTPS-only default is retained,
// since allowing arbitrary schemes would defeat the SSRF posture.
//
// NOTE: this option has NO effect when passed to [SafeTransport] -- the
// transport gates at the IP/port layer only and never inspects the scheme
// set. Use it with [AllowedSchemes] (feed the result into
// [SafeRedirectPolicyWithSchemes]) to gate redirect-hop schemes.
func WithAllowedSchemes(schemes ...string) Option {
	return func(c *transportConfig) {
		if len(schemes) == 0 {
			return
		}
		m := make(map[string]struct{}, len(schemes))
		for _, s := range schemes {
			m[strings.ToLower(s)] = struct{}{}
		}
		c.schemes = m
	}
}

// ValidateURL checks that a URL uses HTTPS and points to a public host.
// Rejects HTTP (cleartext), non-HTTP schemes, loopback, private, and
// link-local addresses. Hostnames without dots (bare names like
// "localhost" or "internal") are also rejected.
func ValidateURL(raw string) error {
	return validateURLWithSchemes(raw, nil)
}

// validateURLWithSchemes validates a URL against a set of allowed schemes.
// If schemes is nil, only HTTPS is allowed.
func validateURLWithSchemes(raw string, schemes map[string]struct{}) error {
	u, err := url.Parse(raw)
	if err != nil {
		slog.Default().Warn("ssrf blocked", "reason", "invalid_url", "error", err)
		return ssrfErr(KindInvalidURL, "", "invalid URL", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if schemes == nil {
		if scheme != schemeHTTPS {
			slog.Default().Warn("ssrf blocked", "reason", "scheme", "scheme", u.Scheme)
			return ssrfErr(KindBadScheme, "", fmt.Sprintf("URL scheme must be https, got %q", u.Scheme), nil)
		}
	} else {
		if _, ok := schemes[scheme]; !ok {
			slog.Default().Warn("ssrf blocked", "reason", "scheme", "scheme", u.Scheme)
			return ssrfErr(KindBadScheme, "", fmt.Sprintf("URL scheme %q is not allowed", u.Scheme), nil)
		}
	}
	host := u.Hostname()
	if host == "" {
		slog.Default().Warn("ssrf blocked", "reason", "empty_host")
		return ssrfErr(KindEmptyHost, "", "URL has empty host", nil)
	}
	return validateHost(host)
}

// IsPublicHost checks that a hostname is not a private/loopback/CGNAT address.
// Returns false for localhost, bare hostnames, RFC 1918/link-local IPs,
// and RFC 6598 shared address space.
//
// As a predicate it is SILENT: unlike the [ValidateURL] enforcement path, a
// false result emits no "ssrf blocked" log line, so callers can probe host
// publicness (e.g. pre-filtering a list) without polluting block dashboards.
func IsPublicHost(host string) bool {
	return hostValidationError(host) == nil
}

// IsPublicAddr reports whether addr is a globally routable unicast address.
// Rejects loopback, private (RFC 1918/RFC 4193), link-local, multicast,
// unspecified, shared (RFC 6598 CGNAT), "this host" (0.0.0.0/8), former
// Class E (240.0.0.0/4), non-routable documentation/benchmarking ranges
// (RFC 5737, RFC 2544, RFC 6666, RFC 3849, RFC 9637, RFC 9602), and
// embedded IPv4 inside 6to4, NAT64, Teredo, or IPv4-compatible wrappers.
func IsPublicAddr(addr netip.Addr) bool {
	return isPublicAddr(addr)
}

// hostValidationError returns the SSRF *Error describing why host is not a
// public hostname, or nil if it is public. It performs NO logging — it is the
// shared classification core. The enforcement wrapper [validateHost] logs a
// "ssrf blocked" Warn on rejection; the [IsPublicHost] predicate uses this core
// directly and stays silent (a query is not a block).
func hostValidationError(host string) *Error {
	// URL-authority bracket syntax wraps IPv6 literals ("[::1]",
	// "[2606:4700:4700::1111]", "[::ffff:192.168.1.1]"). netip.ParseAddr rejects
	// the brackets, so a bracketed IPv4-mapped/embedded-IPv4 internal literal
	// whose dotted tail satisfies the contains-a-dot hostname gate below would
	// otherwise be misclassified PUBLIC by IsPublicHost. Strip a single matching
	// bracket pair and classify the inner literal, mirroring url.Hostname()
	// (which ValidateURL already applies before reaching here): a genuinely
	// public IPv6 literal stays public, an internal one is correctly rejected.
	// ValidateURL never reaches here with brackets; this guards direct
	// IsPublicHost callers passing raw URL-authority syntax.
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}

	// Strip all trailing dots (FQDN notation).
	host = strings.TrimRight(host, ".")
	if host == "" {
		return ssrfErr(KindEmptyHost, host, "empty host", nil)
	}

	if strings.EqualFold(host, "localhost") {
		return ssrfErr(KindLocalhost, host, "URL points to localhost", nil)
	}

	// Parse as IP first.
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !isPublicAddr(addr) {
			return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("URL points to non-public IP: %s", host), nil)
		}
		return nil
	}

	// Reject non-canonical IPv4 encodings (dotted-octal "0177.0.0.1",
	// dotted-hex "0x7f.0.0.1", short-form "127.1", oversized inet_aton
	// "192.168.257"). netip.ParseAddr is strict and rejects all of these, so
	// without this gate they fall through to the dotted-hostname arm below and
	// ValidateURL returns nil — yet a libc resolver (glibc getaddrinfo) resolves
	// them to internal addresses. A real DNS name never has an all-numeric label
	// set, so that is a reliable signature for these alternate encodings.
	if looksLikeNumericIPv4(host) {
		return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("URL host is a non-canonical IP encoding: %s", host), nil)
	}

	// Not an IP; must be a hostname with at least one dot.
	if !strings.Contains(host, ".") {
		return ssrfErr(KindBareHostname, host, fmt.Sprintf("URL points to bare hostname: %s", host), nil)
	}
	return nil
}

// looksLikeNumericIPv4 reports whether every dot-separated label of host is a
// decimal/octal/hex integer — the signature of a non-canonical IPv4 encoding
// (dotted-octal, dotted-hex, or oversized inet_aton form) that netip.ParseAddr
// rejects but a libc resolver would accept. Dotless forms (fewer than two
// labels) are left to the bare-hostname gate.
func looksLikeNumericIPv4(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false // dotless forms handled by the bare-hostname gate
	}
	for _, l := range labels {
		if !isNumericLabel(l) {
			return false
		}
	}
	return true
}

// isNumericLabel reports whether l is a non-empty string of decimal digits
// or a 0x-prefixed hex literal. It intentionally OVER-matches relative to
// inet_aton (it also accepts forms inet_aton rejects, e.g. invalid-octal
// "08" or out-of-range "257"): looksLikeNumericIPv4 uses it only to DETECT
// and reject a non-canonical IPv4 encoding, never to parse one, so a
// fail-closed superset is safe. Do NOT tighten it toward strict inet_aton
// semantics -- a narrowed form would fall through to the dotted-hostname
// arm and reach the resolver.
func isNumericLabel(l string) bool {
	if l == "" {
		return false
	}
	if len(l) > 2 && l[0] == '0' && (l[1] == 'x' || l[1] == 'X') {
		return isHexDigits(l[2:])
	}
	return isDecimalDigits(l)
}

// isHexDigits reports whether every rune in s is a hexadecimal digit. An empty
// s reports true (vacuous); isNumericLabel only calls it with a non-empty tail.
func isHexDigits(s string) bool {
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// isHexDigit reports whether c is a hexadecimal digit (0-9, a-f, A-F).
func isHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isDecimalDigits reports whether every rune in s is a decimal digit (0-9).
func isDecimalDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// reasonLabel maps an ErrorKind to the bounded, low-cardinality "reason"
// label emitted by the host-validation path ([validateHost], via [ValidateURL]),
// the redirect policy, and the policy-denial branch of the socket-level paths
// ([safeControl], [safeDialContext]) -- which pass KindNonPublicIP by default or
// KindPolicyDenied under a custom [WithPolicy]. The socket-level paths' structural
// rejections and port checks (checkAllowedPort) intentionally emit their own
// finer-grained inline labels (e.g. "no_ips_resolved", "disallowed_network",
// "unparseable_ip", "invalid_address", "dns_failed", "port_not_allowed") that do
// NOT flow through this helper. Every reason value is a bounded snake_case constant
// so Loki/Grafana can aggregate blocks by reason. Keep this switch in sync with the
// Kinds routed through it: a new Kind emitted by any of those paths needs a case
// here, else it silently degrades to "blocked". Never embed hosts/IPs in any reason
// label.
func reasonLabel(kind ErrorKind) string {
	switch kind {
	case KindInvalidURL:
		return "invalid_url"
	case KindBadScheme:
		return "scheme"
	case KindEmptyHost:
		return "empty_host"
	case KindLocalhost:
		return "localhost"
	case KindBareHostname:
		return "bare_hostname"
	case KindNonPublicIP:
		return "non_public_ip"
	case KindDNSFailed:
		return "dns_failed"
	case KindPolicyDenied:
		return "policy_denied"
	case KindBadPort:
		return "bad_port"
	case KindTooManyRedirects:
		return "too_many_redirects"
	default:
		return "blocked"
	}
}

// validateHost is the enforcement wrapper around [hostValidationError]: on
// rejection it emits a "ssrf blocked" Warn (the ValidateURL / redirect-policy
// path, where a block is a real security event) and returns the error; it
// returns nil for a public host. Predicate callers use hostValidationError
// directly to stay silent — see [IsPublicHost].
func validateHost(host string) error {
	verr := hostValidationError(host)
	if verr == nil {
		return nil
	}
	reason := reasonLabel(verr.Kind)
	slog.Default().Warn("ssrf blocked", "host", verr.Host, "reason", reason)
	return verr
}

// --- Blocked ranges ---

// IPv4 ranges not globally reachable (RFC 6890 + RFC 5737 + RFC 2544).
var (
	sharedAddrSpace = netip.MustParsePrefix("100.64.0.0/10")   // RFC 6598 CGNAT
	thisHostNet     = netip.MustParsePrefix("0.0.0.0/8")       // RFC 6890 "this host"
	reserved240     = netip.MustParsePrefix("240.0.0.0/4")     // RFC 1112 Class E
	ietfProtoAssign = netip.MustParsePrefix("192.0.0.0/24")    // RFC 5736 IETF Protocol Assignments
	testNet1        = netip.MustParsePrefix("192.0.2.0/24")    // RFC 5737 TEST-NET-1
	testNet2        = netip.MustParsePrefix("198.51.100.0/24") // RFC 5737 TEST-NET-2
	testNet3        = netip.MustParsePrefix("203.0.113.0/24")  // RFC 5737 TEST-NET-3
	benchmarking4   = netip.MustParsePrefix("198.18.0.0/15")   // RFC 2544 Benchmarking
	sixToFourRelay  = netip.MustParsePrefix("192.88.99.0/24")  // RFC 7526 deprecated 6to4 relay
)

// IPv6 ranges not globally reachable.
var (
	discardOnly   = netip.MustParsePrefix("100::/64")      // RFC 6666 Discard-Only
	benchmarking6 = netip.MustParsePrefix("2001:2::/48")   // RFC 5180 Benchmarking
	documentation = netip.MustParsePrefix("2001:db8::/32") // RFC 3849 Documentation
	doc6New       = netip.MustParsePrefix("3fff::/20")     // RFC 9637 Documentation (2024)
	srv6SIDs      = netip.MustParsePrefix("5f00::/16")     // RFC 9602 SRv6 SIDs (2024)
	siteLocal     = netip.MustParsePrefix("fec0::/10")     // RFC 3879 deprecated site-local
)

// IPv6 transition mechanism prefixes.
var (
	sixToFour      = netip.MustParsePrefix("2002::/16")      // RFC 3056 6to4
	nat64Wellknown = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052 NAT64
	nat64Local     = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215 local NAT64
	teredoPrefix   = netip.MustParsePrefix("2001::/32")      // RFC 4380 Teredo
	ipv4Compat     = netip.MustParsePrefix("::/96")          // RFC 4291 §2.5.5.1 deprecated
)

// isPublicAddr returns true only for globally routable unicast addresses.
func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	// Unmap IPv4-mapped IPv6 (::ffff:x.x.x.x) so all subsequent checks
	// operate on the canonical IPv4 form. Without this, IPv4 prefix checks
	// (e.g. sharedAddrSpace) would miss mapped addresses.
	addr = addr.Unmap()
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		sharedAddrSpace.Contains(addr) ||
		thisHostNet.Contains(addr) ||
		reserved240.Contains(addr) {
		return false
	}

	if isNonRoutableRange(addr) {
		return false
	}

	return embeddedIPv4IsPublic(addr)
}

// isNonRoutableRange checks documentation/benchmarking/discard ranges.
// addr must already be unmapped (callers guarantee this via isPublicAddr).
func isNonRoutableRange(addr netip.Addr) bool {
	if addr.Is4() {
		return isNonRoutableV4(addr)
	}
	if addr.Is6() {
		return isNonRoutableV6(addr)
	}
	return false
}

// isNonRoutableV4 reports whether addr is in an IPv4 documentation,
// benchmarking, IETF-protocol-assignment, or deprecated 6to4-relay range.
func isNonRoutableV4(addr netip.Addr) bool {
	return ietfProtoAssign.Contains(addr) ||
		testNet1.Contains(addr) ||
		testNet2.Contains(addr) ||
		testNet3.Contains(addr) ||
		benchmarking4.Contains(addr) ||
		sixToFourRelay.Contains(addr)
}

// isNonRoutableV6 reports whether addr is in an IPv6 discard, benchmarking,
// documentation, SRv6-SID, deprecated site-local, or local-NAT64 range.
//
// nat64Local (RFC 8215 64:ff9b:1::/48) is blocked outright: its RFC 6052 /48
// IPv4-embedding offset differs from the well-known /96, so extracting bytes
// 12-15 would risk an SSRF bypass.
func isNonRoutableV6(addr netip.Addr) bool {
	return discardOnly.Contains(addr) ||
		benchmarking6.Contains(addr) ||
		documentation.Contains(addr) ||
		doc6New.Contains(addr) ||
		srv6SIDs.Contains(addr) ||
		siteLocal.Contains(addr) ||
		nat64Local.Contains(addr)
}

// embeddedIPv4IsPublic validates IPv4 addresses embedded in IPv6 transition
// mechanism wrappers (6to4, NAT64, Teredo, IPv4-compatible).
func embeddedIPv4IsPublic(addr netip.Addr) bool {
	if sixToFour.Contains(addr) {
		// RFC 3056: 2002:V4ADDR::/48 -- 32-bit IPv4 is bytes 2-5 (after 0x2002).
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		if !isPublicAddr(embedded) {
			return false
		}
	}
	if nat64Wellknown.Contains(addr) {
		// RFC 6052 sec 2.2: for the /96 well-known prefix IPv4 is the last 32 bits, bytes 12-15.
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if !isPublicAddr(embedded) {
			return false
		}
	}
	if teredoPrefix.Contains(addr) {
		// RFC 4380 sec 4: bytes 4-7 = Teredo server IPv4; bytes 12-15 = client IPv4
		// stored bitwise-inverted (XOR 0xffffffff / ^0xFF per byte) so it is obscured
		// in the packet header. The inversion is load-bearing: without it an attacker
		// could encode an internal client IP as its bitwise inverse and pass the check.
		b := addr.As16()
		clientIP := netip.AddrFrom4([4]byte{b[12] ^ 0xFF, b[13] ^ 0xFF, b[14] ^ 0xFF, b[15] ^ 0xFF})
		if !isPublicAddr(clientIP) {
			return false
		}
		serverIP := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
		if !isPublicAddr(serverIP) {
			return false
		}
	}
	if ipv4Compat.Contains(addr) && !addr.IsUnspecified() {
		// RFC 4291 sec 2.5.5.1: deprecated IPv4-compatible ::a.b.c.d -- IPv4 is bytes 12-15.
		// IsUnspecified guard excludes :: (all-zeros).
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if !isPublicAddr(embedded) {
			return false
		}
	}
	return true
}

// SafeRedirectPolicy returns an http.Client CheckRedirect function that
// validates each redirect target URL against SSRF rules.
func SafeRedirectPolicy(
	next func(req *http.Request, via []*http.Request) error,
) func(req *http.Request, via []*http.Request) error {
	return SafeRedirectPolicyWithSchemes(nil, next)
}

// SafeRedirectPolicyWithSchemes returns a redirect policy that validates
// against the given allowed schemes (for use with [WithAllowedSchemes]).
//
// Scheme-set semantics: a nil schemes map means HTTPS-only; a non-nil but
// empty map blocks every scheme (fail-closed) and rejects all redirects.
// Source a safe non-empty set from [AllowedSchemes] rather than building
// the map inline -- unlike WithAllowedSchemes, an empty map here is not
// widened to the HTTPS default.
func SafeRedirectPolicyWithSchemes(
	schemes map[string]struct{},
	next func(req *http.Request, via []*http.Request) error,
) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			slog.Default().Warn("ssrf redirect blocked",
				"reason", "too_many_redirects", "hops", len(via))
			return ssrfErr(KindTooManyRedirects, "", fmt.Sprintf("stopped after %d redirects", maxRedirects), nil)
		}
		if err := validateURLWithSchemes(req.URL.String(), schemes); err != nil {
			// Propagate the inner Kind so a caller inspecting
			// errors.As(&ssrf.Error).Kind sees the real reason (bad scheme,
			// empty host, non-public IP, ...) rather than a blanket value.
			kind := KindNonPublicIP
			if ie, ok := errors.AsType[*Error](err); ok {
				kind = ie.Kind
			}
			slog.Default().Warn("ssrf redirect blocked",
				"url", req.URL.Redacted(), "reason", reasonLabel(kind), "error", err)
			return ssrfErr(kind, req.URL.Hostname(), "redirect blocked (SSRF): "+err.Error(), err)
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
}

// checkAllowedPort verifies portStr is one of the permitted ports. A nil
// allowedPorts allows all ports. stage ("control" or "dial") selects the
// log/message context so both validation layers share one definition while
// keeping their distinct diagnostics. Returns a KindBadPort error on an
// unparseable or disallowed port.
func checkAllowedPort(allowedPorts map[uint16]struct{}, host, portStr, stage string) error {
	if allowedPorts == nil {
		return nil
	}
	p, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil {
		slog.Default().Warn("ssrf "+stage+" blocked", "host", host, "port", portStr, "reason", "bad_port")
		return ssrfErr(KindBadPort, host, fmt.Sprintf("SSRF %s: invalid port %q", stage, portStr), parseErr)
	}
	if _, ok := allowedPorts[uint16(p)]; !ok {
		slog.Default().Warn("ssrf "+stage+" blocked", "host", host, "port", uint16(p), "reason", "port_not_allowed")
		return ssrfErr(KindBadPort, host, fmt.Sprintf("SSRF %s: port %d is not allowed", stage, p), nil)
	}
	return nil
}

// safeControl returns a net.Dialer Control function that validates the
// actually-connected IP address at socket creation time. This is the
// canonical defense-in-depth against DNS rebinding/TOCTOU, mirroring
// doyensec/safeurl and Stripe smokescreen's approach. The Control hook
// fires after DNS resolution but before the TCP handshake completes.
//
// denyKind is an optional override for the ErrorKind emitted when policy
// rejects the connected IP; it defaults to KindNonPublicIP. SafeTransport
// passes KindPolicyDenied when a custom WithPolicy is in effect, so a
// custom-policy denial surfaces the documented KindPolicyDenied. Structural
// rejections (disallowed network, unparseable IP) always use KindNonPublicIP.
func safeControl(policy Policy, allowedPorts map[uint16]struct{}, denyKind ...ErrorKind) func(network, address string, c syscall.RawConn) error {
	policyDenyKind := KindNonPublicIP
	if len(denyKind) > 0 {
		policyDenyKind = denyKind[0]
	}
	return func(network, address string, _ syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" {
			slog.Default().Warn("ssrf control blocked", "network", network, "reason", "disallowed_network")
			return ssrfErr(KindNonPublicIP, "", fmt.Sprintf("SSRF control: disallowed network %q", network), nil)
		}

		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			slog.Default().Warn("ssrf control blocked", "address", address, "reason", "invalid_address")
			return ssrfErr(KindInvalidURL, "", fmt.Sprintf("SSRF control: invalid address %q", address), err)
		}

		// Validate port at dial time.
		if err := checkAllowedPort(allowedPorts, host, portStr, "control"); err != nil {
			return err
		}

		// Validate IP at dial time (defense-in-depth).
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			slog.Default().Warn("ssrf control blocked", "ip", host, "reason", "unparseable_ip")
			return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("SSRF control: cannot parse IP %q", host), parseErr)
		}
		addr = addr.Unmap()
		if !policy(addr) {
			slog.Default().Warn("ssrf control blocked",
				"ip", addr.String(), "reason", reasonLabel(policyDenyKind))
			return ssrfErr(policyDenyKind, host, fmt.Sprintf("SSRF control: IP %s is not public", addr), nil)
		}
		return nil
	}
}

// safeDialContext returns a DialContext function that resolves DNS and
// validates all resolved IPs against the given policy before connecting.
// The dialer also has a Control hook for defense-in-depth validation.
//
// denyKind is an optional override for the ErrorKind emitted when policy
// rejects a resolved IP; it defaults to KindNonPublicIP and is forwarded to
// safeControl so both validation layers report the same kind. SafeTransport
// passes KindPolicyDenied when a custom WithPolicy is in effect.
func safeDialContext(dialer *net.Dialer, policy Policy, resolver Resolver, allowedPorts map[uint16]struct{}, denyKind ...ErrorKind) func(ctx context.Context, network, addr string) (net.Conn, error) {
	policyDenyKind := KindNonPublicIP
	if len(denyKind) > 0 {
		policyDenyKind = denyKind[0]
	}
	// Clone the caller-supplied dialer so installing the SSRF Control hook never
	// mutates a *net.Dialer the caller passed via WithDialer (and may share across
	// transports with differing policy/port configs). Clear ControlContext on the
	// copy: when set it takes precedence over Control (net.Dialer semantics), which
	// would silently bypass this layer if a caller supplied it via WithDialer.
	d := *dialer
	d.ControlContext = nil
	d.Control = safeControl(policy, allowedPorts, policyDenyKind)
	dialer = &d

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			slog.Default().Warn("ssrf dial blocked", "address", addr, "reason", "invalid_address")
			return nil, ssrfErr(KindInvalidURL, "", fmt.Sprintf("SSRF dial: invalid address %q", addr), err)
		}

		// Validate port at resolve time (fail fast).
		if portErr := checkAllowedPort(allowedPorts, host, port, "dial"); portErr != nil {
			return nil, portErr
		}

		safe, err := resolveAndValidate(ctx, resolver, policy, host, policyDenyKind)
		if err != nil {
			return nil, err
		}
		return dialValidatedIPs(ctx, dialer, network, host, port, safe)
	}
}

// resolveAndValidate resolves host with a bounded DNS timeout, then unmaps and
// policy-validates EVERY returned IP, failing closed on the first non-public
// one. It returns a freshly allocated slice (never aliasing the resolver's
// cached return value) so the caller can cap dial attempts without affecting
// which IPs are validated.
func resolveAndValidate(ctx context.Context, resolver Resolver, policy Policy, host string, policyDenyKind ErrorKind) ([]netip.Addr, error) {
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := resolver.LookupNetIP(dnsCtx, "ip", host)
	cancel()
	if err != nil {
		slog.Default().Warn("ssrf dial blocked", "host", host, "reason", "dns_failed", "error", err)
		return nil, ssrfErr(KindDNSFailed, host, fmt.Sprintf("SSRF dial: DNS lookup failed for %q", host), err)
	}
	if len(ips) == 0 {
		slog.Default().Warn("ssrf dial blocked", "host", host, "reason", "no_ips_resolved")
		return nil, ssrfErr(KindDNSFailed, host, fmt.Sprintf("SSRF dial: no IPs resolved for %q", host), nil)
	}

	// Copy the slice so we never mutate the resolver's cached return value.
	safe := make([]netip.Addr, len(ips))
	for i := range ips {
		safe[i] = ips[i].Unmap()
		if !policy(safe[i]) {
			slog.Default().Warn("ssrf dial blocked",
				"host", host, "resolved_ip", safe[i].String(), "reason", reasonLabel(policyDenyKind))
			return nil, ssrfErr(policyDenyKind, host, fmt.Sprintf("SSRF dial: resolved IP %s for %q is not public", safe[i], host), nil)
		}
	}
	return safe, nil
}

// dialValidatedIPs connects to the already-validated addresses in safe, capping
// the number of dial ATTEMPTS at maxDialIPs to bound total dial time against an
// attacker-controlled resolver returning many policy-passing-but-blackholed
// IPs. The cap never gates validation (every address in safe was already
// policy-checked); it only limits how many are dialed.
func dialValidatedIPs(ctx context.Context, dialer *net.Dialer, network, host, port string, safe []netip.Addr) (net.Conn, error) {
	// maxDialIPs is applied ONLY here, after resolveAndValidate validated every
	// resolved IP and failed closed on the first non-public one. Do NOT hoist
	// this truncation into validation to skip validating IPs we won't dial: a
	// resolver returning a few public IPs followed by internal ones would then
	// succeed. The cap bounds dial *attempts* among the already-validated set;
	// it must never gate which IPs get validated.
	dialList := safe
	if len(dialList) > maxDialIPs {
		slog.Default().Warn("ssrf dial capped",
			"host", host, "resolved", len(safe), "dialing", maxDialIPs)
		dialList = dialList[:maxDialIPs]
	}
	var lastErr error
	for _, ip := range dialList {
		if ctx.Err() != nil {
			slog.Default().Debug("ssrf dial aborted",
				"host", host, "reason", "context_cancelled", "error", ctx.Err())
			return nil, fmt.Errorf("SSRF dial: context cancelled: %w", ctx.Err())
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	slog.Default().Debug("ssrf dial failed",
		"host", host, "ips_tried", len(dialList), "error", lastErr)
	return nil, fmt.Errorf("SSRF dial: all %d IPs for %q failed: %w", len(dialList), host, lastErr)
}

// SafeTransport returns an *http.Transport hardened against SSRF and
// DNS rebinding. Use [WithPolicy], [WithDialer], [WithResolver],
// [WithAllowedPorts], and [WithAllowedSchemes] to customize.
func SafeTransport(opts ...Option) *http.Transport {
	cfg := transportConfig{
		policy: isPublicAddr,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		resolver:     net.DefaultResolver,
		allowedPorts: map[uint16]struct{}{443: {}},
		schemes:      map[string]struct{}{schemeHTTPS: {}},
	}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	// A custom WithPolicy denial reports KindPolicyDenied (the documented
	// "custom policy rejected the IP" kind); the default isPublicAddr policy
	// keeps reporting KindNonPublicIP.
	denyKind := KindNonPublicIP
	if cfg.policyIsCustom {
		denyKind = KindPolicyDenied
	}
	return &http.Transport{
		DialContext:           safeDialContext(cfg.dialer, cfg.policy, cfg.resolver, cfg.allowedPorts, denyKind),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
	}
}

// AllowedSchemes returns the scheme set from the transport config, for use
// with [SafeRedirectPolicyWithSchemes]. The default (no options) is the
// HTTPS-only set {"https"}; the result is always non-nil.
func AllowedSchemes(opts ...Option) map[string]struct{} {
	cfg := transportConfig{
		schemes: map[string]struct{}{schemeHTTPS: {}},
	}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg.schemes
}
