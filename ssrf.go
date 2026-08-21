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
//   - Custom allow/deny IP lists: WithAddressPolicy(func(netip.Addr) bool) already provides this.
//   - Hostname allowlist/denylist: Application-layer policy, not core SSRF defense.
//   - Happy Eyeballs (RFC 8305): Security library prioritizes correctness over speed.
//   - Response body size limit: Use io.LimitReader at the application layer.
//   - Blanket 2001::/23 block: Overly broad; we block specific non-routable sub-ranges.
//   - ISATAP embedded IPv4: Uses fe80::/64 (already blocked) or routable prefixes.
//   - DNS-over-HTTPS/TLS resolver: WithResolver enables plugging in any implementation.
package ssrf

import (
	"context"
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
	"unicode/utf8"

	"github.com/cplieger/runesafe/v2"
)

const schemeHTTPS = "https"

// DNS presentation-form limits, RFC 1035. maxDNSName is the 255-octet wire limit
// minus the root label's length byte and terminating zero, which is the familiar
// 253 characters a name occupies when written down without its trailing dot.
// A host at either bound is accepted, so no resolvable name is ever refused for
// length; only a value that could not be a name is.
const (
	maxDNSName  = 253
	maxDNSLabel = 63
)

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
	// KindInvalidHost indicates the host is not a canonical host at all: it
	// carries a byte no DNS label may hold, or an IP literal carries a zone
	// identifier. Distinct from KindNonPublicIP, which means a well-formed host
	// that points somewhere private. Appended last so the iota values above it
	// keep the numbers consumers already branch on.
	KindInvalidHost
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

// AddressPolicy controls whether a resolved IP address is allowed or denied.
// Return true to allow the connection, false to block it.
// The default policy (used when none is provided) is [IsPublicAddr].
type AddressPolicy func(addr netip.Addr) bool

// Resolver abstracts DNS resolution for testing and custom environments.
// The standard library's [net.Resolver] satisfies this interface.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// TransportOption configures [SafeTransport].
type TransportOption func(*transportConfig)

type transportConfig struct {
	policy         AddressPolicy
	dialer         *net.Dialer
	resolver       Resolver
	allowedPorts   map[uint16]struct{}
	policyIsCustom bool
}

// WithAddressPolicy sets a custom allow/deny policy for resolved IP addresses.
// The policy is called after unmapping IPv4-mapped IPv6 addresses.
// A nil policy is ignored (the default [IsPublicAddr] policy is retained).
func WithAddressPolicy(p AddressPolicy) TransportOption {
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
func WithDialer(d *net.Dialer) TransportOption {
	return func(c *transportConfig) {
		if d != nil {
			c.dialer = d
		}
	}
}

// WithResolver sets a custom DNS resolver for hostname resolution.
// Useful for testing or environments with custom resolvers (e.g., CoreDNS sidecar).
// A nil resolver is ignored (net.DefaultResolver is retained).
func WithResolver(r Resolver) TransportOption {
	return func(c *transportConfig) {
		if r != nil {
			c.resolver = r
		}
	}
}

// WithAllowedPorts sets the ports that outbound connections may target.
// By default only port 443 is allowed (matching the HTTPS-only posture).
// Passing no ports retains that default. Later calls replace the set, so this
// is last-wins with itself.
//
// There is deliberately no way to switch the port check off. A caller whose
// peer lives on a port it cannot enumerate ahead of time should build its
// transport once the destination IS known and pass that one port — pinning the
// destination it already validated is a stronger check than any standing
// permissive policy, and it keeps the widest setting off this library's
// surface. Mirrors doyensec/safeurl AllowedPorts, which likewise ships no
// escape hatch.
func WithAllowedPorts(ports ...uint16) TransportOption {
	return func(c *transportConfig) {
		if len(ports) == 0 {
			return
		}
		m := make(map[uint16]struct{}, len(ports))
		for _, p := range ports {
			m[p] = struct{}{}
		}
		c.allowedPorts = m
	}
}

// URLPolicy validates URL schemes and hosts before requests or redirect hops.
// The zero value allows HTTPS only, so it is ready for use without a constructor.
// A URLPolicy performs no DNS lookup; pair it with [SafeTransport] when making
// requests so resolved and connected addresses are validated at the dial boundary.
type URLPolicy struct {
	allowedSchemes map[string]struct{}
}

// NewURLPolicy returns a URL policy allowing the given schemes. With no
// schemes it returns the HTTPS-only default.
//
// Scheme matching is case-insensitive over ASCII and byte-exact outside it,
// which is the whole of RFC 3986's scheme grammar. Folding it over Unicode would
// mean a scheme the grammar excludes could match an allowed one: strings.ToLower
// maps U+212A KELVIN SIGN to "k", so "\u212Aafka" would satisfy an allowed
// "kafka".
func NewURLPolicy(schemes ...string) URLPolicy {
	if len(schemes) == 0 {
		return URLPolicy{}
	}
	allowed := make(map[string]struct{}, len(schemes))
	for _, scheme := range schemes {
		allowed[lowerASCIIString(scheme)] = struct{}{}
	}
	return URLPolicy{allowedSchemes: allowed}
}

// Validate checks that raw uses an allowed scheme and points to a public host.
func (p URLPolicy) Validate(raw string) error {
	return validateURLWithSchemes(raw, p.allowedSchemes)
}

// ValidateURL checks that a URL uses HTTPS and points to a public host.
// Rejects HTTP (cleartext), non-HTTP schemes, loopback, private, and
// link-local addresses. Hostnames without dots (bare names like
// "localhost" or "internal") are also rejected.
func ValidateURL(raw string) error {
	return validateURLWithSchemes(raw, nil)
}

// classifyURL is the classification core: it returns the *Error describing why
// u is unsafe (nil if safe). Like every function on the validation path it
// performs no logging; see [validateURLWithSchemes] for why.
//
// It judges the parsed URL it is handed. That is deliberate: the redirect policy
// validates the very *url.URL net/http is about to dial, not a re-parse of its
// text, so the check and the use cannot land on two different objects. Measured
// on go1.27.0 over 36 adversarial seeds plus 400,000 randomized authorities,
// url.Parse(u.String()) preserved Scheme, Hostname and Port in every case — the
// round trip was faithful, and taking the parsed URL directly means that no
// longer has to be re-established on each toolchain.
//
// If schemes is nil, only HTTPS is allowed. Scheme matching folds over ASCII
// (see [lowerASCIIString]) rather than through strings.ToLower, because u may be
// caller-constructed rather than parsed and its Scheme can then hold bytes
// RFC 3986's grammar excludes.
func classifyURL(u *url.URL, schemes map[string]struct{}) *Error {
	scheme := lowerASCIIString(u.Scheme)
	if schemes == nil {
		if scheme != schemeHTTPS {
			return ssrfErr(KindBadScheme, "", fmt.Sprintf("URL scheme must be https, got %q", u.Scheme), nil)
		}
	} else if _, ok := schemes[scheme]; !ok {
		return ssrfErr(KindBadScheme, "", fmt.Sprintf("URL scheme %q is not allowed", u.Scheme), nil)
	}
	host := u.Hostname()
	if host == "" {
		return ssrfErr(KindEmptyHost, "", "URL has empty host", nil)
	}
	return hostValidationError(host)
}

// classifyURLWithSchemes parses raw and hands the result to [classifyURL],
// returning the concrete *Error. [validateURLWithSchemes] is the wrapper that
// converts it to the error interface. If schemes is nil, only HTTPS is allowed.
func classifyURLWithSchemes(raw string, schemes map[string]struct{}) *Error {
	u, err := url.Parse(raw)
	if err != nil {
		return ssrfErr(KindInvalidURL, "", "invalid URL", err)
	}
	return classifyURL(u, schemes)
}

// validateURLWithSchemes validates a URL against a set of allowed schemes,
// converting the *Error from [classifyURLWithSchemes] to the error interface.
// If schemes is nil, only HTTPS is allowed.
//
// It does NOT log, and that is deliberate. Validation computes a verdict and
// returns it fully described in the *Error — Kind, Host, Msg and Err — so the
// caller already holds everything a log line could carry, and whether to record
// it belongs to the caller rather than to this package. Emitting here would give
// a pure predicate a side channel into a global sink the caller cannot see,
// configure, or silence. Only the transport half logs, because its rejections
// fire inside net/http where the error can be retried or wrapped past
// recognition before any caller sees it. [IsPublicHost] is silent for the same
// reason, and every entry point on this path behaves the same way.
//
// The explicit nil check is load-bearing: `return classifyURLWithSchemes(...)`
// would put a typed nil *Error into a non-nil error interface, so every valid
// URL would report a failure. Do not collapse it.
func validateURLWithSchemes(raw string, schemes map[string]struct{}) error {
	if verr := classifyURLWithSchemes(raw, schemes); verr != nil {
		return verr
	}
	return nil
}

// IsPublicHost checks that a hostname is not a private/loopback/CGNAT address.
// Returns false for localhost, bare hostnames, RFC 1918/link-local IPs,
// and RFC 6598 shared address space.
//
// Like [ValidateURL] it emits no log line: the whole validation path returns
// its verdict and lets the caller decide whether to record it.
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

// normalizeHostForValidation trims and canonicalizes host for the public-host
// classification core, returning the cleaned host or the *Error for the
// whitespace and empty-host rejections it detects along the way (nil error when
// host is well-formed enough to classify).
func normalizeHostForValidation(host string) (string, *Error) {
	// Trim surrounding ASCII whitespace. The canonical-host gate would refuse a
	// space anyway (it is not a legal host byte), so this is a compatibility
	// affordance for a padded but otherwise well-formed host, not a security
	// measure. Interior whitespace is left for that gate to refuse.
	host = strings.TrimSpace(host)

	// A single trailing dot is the root label, and RFC 1034 presentation syntax
	// admits it: "example.com." and "example.com" name the same node, and WHATWG
	// treats both as valid ("The example.com and example.com. domains are not
	// equivalent and typically treated as distinct"). Strip exactly one, and do
	// it HERE, before the localhost fold in [hostValidationError], so that
	// "localhost." still reports KindLocalhost rather than degrading to a
	// generic refusal.
	//
	// A trailing dot also DISABLES resolver search-list suffixing
	// (resolv.conf(5)), so the dotted spelling is the safer one against
	// ndots expansion. Refusing it would push callers toward the riskier form.
	//
	// Two or more trailing dots are not presentation syntax; they leave an empty
	// label, which the gate refuses.
	host = strings.TrimSuffix(host, ".")

	if host == "" {
		return host, ssrfErr(KindEmptyHost, host, "empty host", nil)
	}
	return host, nil
}

// canonicalHostError is the CLOSED terminal gate: it returns nil only for a host
// this package positively recognizes, and an *Error for everything else. It is
// what replaced a permissive "contains a dot, therefore a public hostname" arm.
//
// The arm it replaced was the root cause of a family of bypasses, each closed
// individually as it was found: non-canonical IPv4 encodings, bracketed IPv6,
// trailing dots, interior whitespace. Two more were found in 2026-08 and are the
// reason this gate exists, both of which reach a private literal through
// STANDARD IDNA processing rather than through anything exotic:
//
//   - Format characters UTS-46 deletes. "127.0.0.1\u200b" (ZWSP) and the same
//     with U+00AD, U+2060, U+FEFF or U+180B all map to exactly "127.0.0.1" with
//     no error, and "169.254.169.254\u200b" maps to the cloud metadata address.
//   - Characters UTS-46 maps to ASCII digits. "\uff11\uff16\uff19.254.169.254"
//     (fullwidth digits) maps to "169.254.169.254"; "\u2460.\u2461.\u2462.\u2463"
//     (circled digits) maps to "1.2.3.4". WHATWG names this class
//     IPv4-non-ASCII-input.
//
// Enumerating those runes would be endless, so the gate inverts the question:
// only ASCII letters, digits, hyphen and underscore may appear in a label, which
// refuses every rune in both families with one condition and refuses the next
// such family without an edit.
//
// SCOPE, and it is narrower than it looks: this is SYNTACTIC closure. A
// well-formed public-looking name that RESOLVES to a private address still
// passes, by design — "metadata.google.internal" and "a.localhost" are the
// canonical examples. Only [SafeTransport]'s post-resolution checks stop those.
func canonicalHostError(host string) *Error {
	// Refuse non-ASCII outright rather than converting. A U-label such as
	// "bücher.de" is not reachable by a Go consumer at all: measured on
	// go1.27.0, net.Resolver refuses it before emitting a packet, while its
	// A-label "xn--bcher-kva.de" resolves normally. Converting here would also
	// couple the verdict to THIS package's Unicode tables while the consumer's
	// client uses its own, and a validator that canonicalizes differently from
	// its client is the shape of a real bypass class. A caller holding a U-label
	// converts it to an A-label before validating.
	//
	// This check is a DIAGNOSTIC, not the guard. The label byte class below
	// already refuses every non-ASCII byte, so deleting this loop would not open
	// a hole; what it would lose is the message naming the remedy, and the
	// correct Kind for a SINGLE-LABEL U-label ("bücher" reports KindInvalidHost
	// with this check and KindBareHostname without it, which is a worse answer
	// because the problem is not the missing dot). Verified by mutation.
	for i := range len(host) {
		if host[i] >= utf8.RuneSelf {
			return ssrfErr(KindInvalidHost, host,
				fmt.Sprintf("URL host is not ASCII, supply an A-label: %q", host), nil)
		}
	}

	// Authority syntax is not a host. url.Hostname() and net.SplitHostPort both
	// strip brackets, so ValidateURL never reaches here with them; a direct
	// IsPublicHost caller passing raw authority syntax is refused rather than
	// silently reinterpreted. Stripping them was how smokescreen's deny list was
	// bypassed (CVE-2022-29188).
	if strings.ContainsAny(host, "[]") {
		return ssrfErr(KindInvalidHost, host,
			fmt.Sprintf("URL host carries authority syntax, pass a bare host: %q", host), nil)
	}

	// The DNS presentation-form limit. Checked before splitting so an
	// attacker-sized host costs one comparison.
	if len(host) > maxDNSName {
		return ssrfErr(KindInvalidHost, host,
			fmt.Sprintf("URL host exceeds %d bytes", maxDNSName), nil)
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ssrfErr(KindBareHostname, host, fmt.Sprintf("URL points to bare hostname: %q", host), nil)
	}
	for _, label := range labels {
		if verr := hostLabelError(host, label); verr != nil {
			return verr
		}
	}

	// A name whose rightmost label is numeric is an IPv4 encoding, not a domain.
	// This is what catches the alternate encodings netip.ParseAddr rejects but a
	// libc resolver accepts: dotted-octal "0177.0.0.1", dotted-hex "0x7f.0.0.1",
	// short-form "127.1", oversized inet_aton "192.168.257".
	if endsInNumber(labels[len(labels)-1]) {
		return ssrfErr(KindNonPublicIP, host,
			fmt.Sprintf("URL host is a non-canonical IP encoding: %q", host), nil)
	}
	return nil
}

// hostLabelError returns the *Error describing why label is not a legal DNS
// label, or nil if it is. host is carried only so the message names the whole
// host the caller passed rather than the fragment that failed.
func hostLabelError(host, label string) *Error {
	if label == "" || len(label) > maxDNSLabel {
		return ssrfErr(KindInvalidHost, host,
			fmt.Sprintf("URL host has an empty or oversized label: %q", host), nil)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return ssrfErr(KindInvalidHost, host,
			fmt.Sprintf("URL host has a label bounded by a hyphen: %q", host), nil)
	}
	for i := range len(label) {
		if !isHostLabelByte(label[i]) {
			return ssrfErr(KindInvalidHost, host,
				fmt.Sprintf("URL host is not a canonical DNS name: %q", host), nil)
		}
	}
	return nil
}

// isHostLabelByte reports whether c may appear in a DNS label.
//
// Letters, digits and hyphen are RFC 1034's set. Underscore is admitted
// deliberately, and the two authorities disagree about it: WHATWG omits it from
// both the forbidden-host and forbidden-domain code point sets, while
// x/net/idna's Lookup profile refuses it under UTS-46 UseSTD3ASCIIRules. It is
// admitted here because refusing it has no security value (underscore cannot be
// mapped to a dot or a digit, and cannot form an IP literal) while a Go consumer
// CAN reach such a host: measured, net.Resolver puts "a_b.example.com" on the
// wire, unlike a U-label, which it refuses before sending anything.
func isHostLabelByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}

// endsInNumber reports whether a name's rightmost label makes the whole name an
// IPv4 address rather than a domain. It implements WHATWG's "ends in a number"
// checker: the label is all ASCII digits, or it is "0x"/"0X" followed by zero or
// more ASCII hex digits.
//
// https://url.spec.whatwg.org/#ends-in-a-number-checker
//
// A stricter rule was considered and rejected: "the rightmost label must begin
// with an ASCII letter" gives an identical verdict on every dangerous input and
// on every real TLD, and differs only by ALSO refusing digit-leading
// non-numeric labels ("3internal", "4chan"). That is compatibility cost for no
// security gain, and it would tie this grammar to today's root-zone inventory
// rather than to a published rule.
//
// The sibling webhttp library carries its own numeric-IPv4 heuristic (inside
// CanonicalHost's hostname validation) with a deliberately DIFFERENT reject set:
// webhttp keys an exact-match inbound Host allowlist with no resolution, so it
// accepts dotted-hex forms like "0x7f.0.0.1" as plain textual labels, while this
// outbound classifier must reject them because they reach a resolver. The two
// must NOT be unified — see CanonicalHost's doc for the inbound rationale.
func endsInNumber(label string) bool {
	if label == "" {
		return false
	}
	if isDecimalDigits(label) {
		return true
	}
	// "0x" alone qualifies: the spec says "zero or more ASCII hex digits".
	if len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
		return isHexDigits(label[2:])
	}
	return false
}

// hostValidationError returns the SSRF *Error describing why host is not a
// public hostname, or nil if it is public. It performs NO logging — it is the
// shared classification core behind both [ValidateURL] and the [IsPublicHost]
// predicate, and the whole validation path is silent by design
// ([validateURLWithSchemes] carries the reasoning).
func hostValidationError(host string) *Error {
	host, verr := normalizeHostForValidation(host)
	if verr != nil {
		return verr
	}

	if equalASCIIFold(host, "localhost") {
		return ssrfErr(KindLocalhost, host, "URL points to localhost", nil)
	}

	// Parse as IP first.
	if addr, err := netip.ParseAddr(host); err == nil {
		// A zone identifier scopes an address to one interface, so it is
		// meaningless on a globally routable address and cannot be dialed as
		// written by a normal client. netip.ParseAddr accepts one only on IPv6,
		// which is why "2606:4700::1111%eth0" reaches here at all while
		// "127.0.0.1%eth0" does not (that one fails to parse and is caught by
		// the canonical-host gate below). Refusing here closes the IPv6 half:
		// without it, isPublicAddr judges the address and reports a zoned
		// global address PUBLIC. RFC 6874 permits a zone in a URI only for
		// link-local, and WHATWG omits zone support from URL host parsing
		// outright ("Support for <zone_id> is intentionally omitted").
		if addr.Zone() != "" {
			return ssrfErr(KindInvalidHost, host,
				fmt.Sprintf("URL host carries a zone identifier: %q", host), nil)
		}
		addr = addr.Unmap()
		if !isPublicAddr(addr) {
			return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("URL points to non-public IP: %q", host), nil)
		}
		return nil
	}

	// Not an IP literal, so the closed gate decides. Everything it does not
	// positively recognize is refused; there is no permissive fallthrough.
	return canonicalHostError(host)
}

// isHexDigits reports whether every rune in s is a hexadecimal digit. An empty
// s reports true (vacuous), which is what endsInNumber wants for the bare "0x"
// form the WHATWG rule admits.
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

// equalASCIIFold reports whether s and t are equal under ASCII-only case
// folding: bytes 'A'-'Z' fold to 'a'-'z' and every other byte must match
// exactly.
//
// It exists because strings.EqualFold applies Unicode simple folding, which is
// the wrong relation for a host judged against a fixed literal. Every grammar
// this package folds is ASCII by definition — a DNS label per RFC 1035 (an
// internationalized name arrives as an "xn--" A-label) and a URL scheme per
// RFC 3986 — so folding wider than the grammar can only admit input the grammar
// already excludes. Under Unicode folding "localhoſt" (U+017F LATIN SMALL
// LETTER LONG S) equals "localhost", so a classifier built on EqualFold names a
// host localhost that no resolver maps to loopback.
//
// In this package that direction happens to be safe — naming localhost REJECTS
// — but it makes a security verdict depend on the toolchain's fold table, which
// has to be re-established by measurement on every Go upgrade. Folding over
// ASCII makes the independence structural instead. Measured over all 1,114,112
// code points on go1.26.7 and go1.27.0: U+017F is the only non-ASCII rune that
// fold-equals any letter of "localhost", so Unicode 17's three changed
// SimpleFold pairs (U+0390/U+1FD3, U+03B0/U+1FE3, U+FB05/U+FB06) move nothing
// here — but nothing in the fold table guarantees that of the next release.
//
// Byte length is a sound early exit precisely because the comparison is
// bytewise: folding never changes a byte's width, so differing lengths cannot
// fold equal.
func equalASCIIFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := range len(s) {
		if lowerASCII(s[i]) != lowerASCII(t[i]) {
			return false
		}
	}
	return true
}

// lowerASCIIString returns s with every ASCII uppercase letter lowercased and
// every other byte returned unchanged. It is the map-key counterpart to
// [equalASCIIFold], used to canonicalize a URL scheme on both sides of the
// allowed-scheme lookup so the two agree byte for byte.
//
// strings.ToLower is the wrong tool for the same reason [equalASCIIFold] gives:
// it is a Unicode display transform, and exactly two non-ASCII runes fold into
// ASCII under it (U+0130 to "i", U+212A to "k", measured on go1.26.7 and
// go1.27.0), so it would let a scheme outside RFC 3986's grammar match an
// allowed one.
func lowerASCIIString(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = lowerASCII(b[i])
	}
	return string(b)
}

// lowerASCII returns c lowercased if it is an ASCII uppercase letter, else c.
// Bytes above 0x7F are returned unchanged, which is what keeps the comparisons
// built on it byte-exact outside ASCII.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// reasonLabels is the bounded, low-cardinality label table backing
// [reasonLabel]. Keep it in sync with the Kinds routed through that helper: a
// new Kind without an entry here silently degrades to "blocked". Every value is
// a snake_case constant and never embeds a host or IP.
var reasonLabels = map[ErrorKind]string{
	KindInvalidURL:       "invalid_url",
	KindBadScheme:        "scheme",
	KindEmptyHost:        "empty_host",
	KindLocalhost:        "localhost",
	KindBareHostname:     "bare_hostname",
	KindNonPublicIP:      "non_public_ip",
	KindDNSFailed:        "dns_failed",
	KindPolicyDenied:     "policy_denied",
	KindBadPort:          "bad_port",
	KindTooManyRedirects: "too_many_redirects",
	KindInvalidHost:      "invalid_host",
}

// reasonLabel maps an ErrorKind to the bounded, low-cardinality "reason" label
// emitted by the redirect policy and by the policy-denial branch of the
// socket-level paths ([safeControl], [safeDialContext]) -- which pass
// KindNonPublicIP by default or KindPolicyDenied under a custom
// [WithAddressPolicy]. The validation entry points do not log
// ([validateURLWithSchemes] carries the reasoning), but every Kind they produce
// still reaches this table through the redirect policy, which re-validates each
// hop with [classifyURL] and labels the inner Kind. So the table stays
// exhaustive; TestReasonLabel_exhaustive fails on a missing entry.
// The socket-level paths' structural rejections and port checks
// (checkAllowedPort) intentionally emit their own finer-grained inline labels
// (e.g. "no_ips_resolved", "disallowed_network", "unparseable_ip",
// "invalid_address", "dns_failed", "port_not_allowed") that do NOT flow through
// this helper. A Kind with no entry in the [reasonLabels] table degrades to
// "blocked"; add an entry there when a routed path emits a new Kind. Never
// embed hosts/IPs in any reason label.
func reasonLabel(kind ErrorKind) string {
	if label, ok := reasonLabels[kind]; ok {
		return label
	}
	return "blocked"
}

// --- Log attribute shaping ---

// Byte bounds for the untrusted text this package writes to a log attribute.
// Each is the longest LEGAL value for its key, so a well-formed value is never
// truncated and only a malformed one is cut — and on these paths every logged
// value is malformed by definition, because the log line exists to record a
// refusal.
//
// The bounds are per key rather than one number for all of them: a redirect
// URL legitimately runs past a host's ceiling, and a port's text is five digits
// at most, so a single bound would either truncate good data or fail to bound
// the shortest field.
const (
	// maxHostLog is RFC 1035's maximum DNS name length (253 characters as
	// presented, 255 on the wire including the root label and its length
	// byte), so no resolvable host is ever truncated.
	maxHostLog = 253
	// maxAddrLog is a host, ":", and the longest port text ("65535").
	maxAddrLog = maxHostLog + len(":") + len("65535")
	// maxURLLog bounds a redirect target. A URL has no ceiling in RFC 3986, so
	// this is the de-facto browser and proxy limit; it keeps one refusal inside
	// a log pipeline's per-line budget.
	maxURLLog = 2048
	// maxPortLog bounds the raw port TEXT, which is only ever logged when it
	// failed to parse as a uint16 and is therefore not a port at all.
	maxPortLog = 8
	// maxErrLog bounds a wrapped error's rendered text. It can quote the host:
	// net.DNSError carries the name it could not resolve, so a resolver error
	// is as attacker-shaped as the host itself.
	maxErrLog = 512
)

// hostForLog returns host sanitized and bounded for use as a log attribute
// value.
//
// Every log site on the transport path routes its untrusted text through one of
// these helpers instead of calling runesafe directly. That keeps one policy per
// key in one place, so a site added later cannot silently pick a different
// bound, and it keeps the choice of preset out of the call site.
//
// The preset is [runesafe.SanitizeSingleLineBounded] rather than a plain byte
// cap because a cap alone is not enough: slog's JSONHandler escapes only what
// JSON requires (below U+0020), so C1 controls, Unicode Bidi_Control and
// U+2028/U+2029 reach a JSON log sink intact. It is not the [runesafe.Untrusted]
// type either, whose LogValue resolves to the unbounded multi-line form.
func hostForLog(host string) string {
	return runesafe.SanitizeSingleLineBounded(host, maxHostLog)
}

// addrForLog returns a "host:port" address sanitized and bounded for a log
// attribute value. See [hostForLog] for the policy.
func addrForLog(addr string) string {
	return runesafe.SanitizeSingleLineBounded(addr, maxAddrLog)
}

// urlForLog returns a URL sanitized and bounded for a log attribute value. Pass
// the output of (*url.URL).Redacted so userinfo is stripped before this point;
// this helper bounds and sanitizes, it does not redact. See [hostForLog] for
// the policy.
func urlForLog(raw string) string {
	return runesafe.SanitizeSingleLineBounded(raw, maxURLLog)
}

// portForLog returns unparseable port text sanitized and bounded for a log
// attribute value. See [hostForLog] for the policy.
func portForLog(port string) string {
	return runesafe.SanitizeSingleLineBounded(port, maxPortLog)
}

// errTextForLog renders err and returns it sanitized and bounded for a log
// attribute value, or "" for a nil err. It returns a STRING rather than the
// error so the sanitized form is what every handler encodes: an error logged as
// itself is rendered by the handler, which would put the raw text back.
// See [hostForLog] for the policy.
func errTextForLog(err error) string {
	if err == nil {
		return ""
	}
	return runesafe.SanitizeSingleLineBounded(err.Error(), maxErrLog)
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
	if isStdlibBlockedAddr(addr) || isBaseBlockedAddr(addr) || isNonRoutableRange(addr) {
		return false
	}

	return embeddedIPv4IsPublic(addr)
}

// isStdlibBlockedAddr reports whether addr falls in a range the netip stdlib
// predicates already classify as non-global: loopback, private (RFC 1918 /
// RFC 4193), link-local unicast, multicast, or unspecified. addr must already
// be unmapped (callers guarantee this via isPublicAddr).
func isStdlibBlockedAddr(addr netip.Addr) bool {
	return addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified()
}

// isBaseBlockedAddr reports whether addr is in the RFC 6598 CGNAT shared
// space, the RFC 6890 "this host" 0.0.0.0/8 net, or the RFC 1112 reserved
// 240.0.0.0/4 former Class E range. addr must already be unmapped (callers
// guarantee this via isPublicAddr).
func isBaseBlockedAddr(addr netip.Addr) bool {
	return sharedAddrSpace.Contains(addr) ||
		thisHostNet.Contains(addr) ||
		reserved240.Contains(addr)
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
// mechanism wrappers (6to4, NAT64, Teredo, IPv4-compatible). For each wrapper
// whose prefix contains addr, the embedded IPv4 is extracted and re-validated
// through isPublicAddr; a wrapper whose prefix does not match contributes no
// constraint. Byte extraction is cheap and pure, so it is done unconditionally
// and the result is consulted only when the wrapper is active.
func embeddedIPv4IsPublic(addr netip.Addr) bool {
	b := addr.As16()
	// RFC 3056: 2002:V4ADDR::/48 -- 32-bit IPv4 is bytes 2-5 (after 0x2002).
	if !embeddedAddrIsPublic(sixToFour.Contains(addr), netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})) {
		return false
	}
	// RFC 6052 sec 2.2: for the /96 well-known prefix IPv4 is the last 32 bits, bytes 12-15.
	if !embeddedAddrIsPublic(nat64Wellknown.Contains(addr), netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})) {
		return false
	}
	// RFC 4380 sec 4: bytes 4-7 = Teredo server IPv4; bytes 12-15 = client IPv4
	// stored bitwise-inverted (see teredoClientIPv4). Both embedded IPv4s must
	// be public for the Teredo address to be treated as public.
	if teredoPrefix.Contains(addr) && (!isPublicAddr(teredoClientIPv4(b)) || !isPublicAddr(teredoServerIPv4(b))) {
		return false
	}
	// RFC 4291 sec 2.5.5.1: deprecated IPv4-compatible ::a.b.c.d -- IPv4 is bytes 12-15.
	// IsUnspecified guard excludes :: (all-zeros).
	return embeddedAddrIsPublic(ipv4Compat.Contains(addr) && !addr.IsUnspecified(), netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
}

// embeddedAddrIsPublic reports whether an embedded-IPv4 constraint is
// satisfied: when the wrapper prefix is not active the constraint holds
// vacuously; otherwise the embedded addr must itself be public.
func embeddedAddrIsPublic(active bool, addr netip.Addr) bool {
	return !active || isPublicAddr(addr)
}

// teredoClientIPv4 extracts the Teredo client IPv4 (RFC 4380 sec 4, bytes
// 12-15). It is stored bitwise-inverted (XOR 0xffffffff / ^0xFF per byte) so it
// is obscured in the packet header. The inversion is load-bearing: without it
// an attacker could encode an internal client IP as its bitwise inverse and
// pass the check.
func teredoClientIPv4(b [16]byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[12] ^ 0xFF, b[13] ^ 0xFF, b[14] ^ 0xFF, b[15] ^ 0xFF})
}

// teredoServerIPv4 extracts the Teredo server IPv4 (RFC 4380 sec 4, bytes 4-7).
func teredoServerIPv4(b [16]byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
}

// SafeRedirectPolicy returns an http.Client CheckRedirect function that
// validates each redirect target URL against SSRF rules (HTTPS-only).
// For custom schemes, use [URLPolicy.RedirectPolicy].
func SafeRedirectPolicy(
	next func(req *http.Request, via []*http.Request) error,
) func(req *http.Request, via []*http.Request) error {
	return URLPolicy{}.RedirectPolicy(next)
}

// RedirectPolicy returns an http.Client CheckRedirect function that validates
// each redirect target URL against this policy's allowed schemes and the SSRF
// host rules. next, if non-nil, is called after validation passes, so callers
// can chain their own redirect logic.
func (p URLPolicy) RedirectPolicy(
	next func(req *http.Request, via []*http.Request) error,
) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			slog.Default().Warn("ssrf redirect blocked",
				"reason", "too_many_redirects", "hops", len(via))
			return ssrfErr(KindTooManyRedirects, "", fmt.Sprintf("stopped after %d redirects", maxRedirects), nil)
		}
		if verr := classifyURL(req.URL, p.allowedSchemes); verr != nil {
			// The inner Kind is propagated so a caller inspecting
			// errors.As(&ssrf.Error).Kind sees the real reason (bad scheme,
			// empty host, non-public IP, ...) rather than a blanket value.
			kind := verr.Kind
			slog.Default().Warn("ssrf redirect blocked",
				"url", urlForLog(req.URL.Redacted()), "reason", reasonLabel(kind), "error", errTextForLog(verr))
			return ssrfErr(kind, req.URL.Hostname(), "redirect blocked (SSRF): "+verr.Error(), verr)
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
}

// checkAllowedPort verifies portStr is one of the permitted ports. stage
// ("control" or "dial") selects the log/message context so both validation
// layers share one definition while keeping their distinct diagnostics.
// Returns a KindBadPort error on an unparseable or disallowed port.
//
// There is no permissive path: an empty or nil set refuses everything rather
// than allowing everything, so a construction bug fails closed. That is why
// an unparseable port needs no special case — it never reaches a lookup that
// might have been switched off.
func checkAllowedPort(allowedPorts map[uint16]struct{}, host, portStr, stage string) error {
	p, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil {
		slog.Default().Warn("ssrf "+stage+" blocked", "host", hostForLog(host), "port", portForLog(portStr), "reason", "bad_port")
		return ssrfErr(KindBadPort, host, fmt.Sprintf("SSRF %s: invalid port %q", stage, portStr), parseErr)
	}
	if _, ok := allowedPorts[uint16(p)]; !ok {
		slog.Default().Warn("ssrf "+stage+" blocked", "host", hostForLog(host), "port", uint16(p), "reason", "port_not_allowed")
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
// passes KindPolicyDenied when a custom WithAddressPolicy is in effect, so a
// custom-policy denial surfaces the documented KindPolicyDenied. Structural
// rejections (disallowed network, unparseable IP) always use KindNonPublicIP.
func safeControl(policy AddressPolicy, allowedPorts map[uint16]struct{}, denyKind ...ErrorKind) func(network, address string, c syscall.RawConn) error {
	policyDenyKind := KindNonPublicIP
	if len(denyKind) > 0 {
		policyDenyKind = denyKind[0]
	}
	return func(network, address string, _ syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" {
			// network is the ONE string this package logs without a ForLog
			// helper: net/http supplies it from its own constants ("tcp",
			// "tcp4", "tcp6"), it is not host-shaped, and it has no path from
			// caller input. Every other string in a slog call here goes through
			// a helper, which is what makes the sweep in
			// TestLogAttributesAreSanitizedAndBounded mechanical.
			slog.Default().Warn("ssrf control blocked", "network", network, "reason", "disallowed_network")
			return ssrfErr(KindNonPublicIP, "", fmt.Sprintf("SSRF control: disallowed network %q", network), nil)
		}

		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			slog.Default().Warn("ssrf control blocked", "address", addrForLog(address), "reason", "invalid_address")
			return ssrfErr(KindInvalidURL, "", fmt.Sprintf("SSRF control: invalid address %q", address), err)
		}

		// Validate port at dial time.
		if err := checkAllowedPort(allowedPorts, host, portStr, "control"); err != nil {
			return err
		}

		// Validate IP at dial time (defense-in-depth).
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			slog.Default().Warn("ssrf control blocked", "ip", hostForLog(host), "reason", "unparseable_ip")
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
// passes KindPolicyDenied when a custom WithAddressPolicy is in effect.
func safeDialContext(dialer *net.Dialer, policy AddressPolicy, resolver Resolver, allowedPorts map[uint16]struct{}, denyKind ...ErrorKind) func(ctx context.Context, network, addr string) (net.Conn, error) {
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
			slog.Default().Warn("ssrf dial blocked", "address", addrForLog(addr), "reason", "invalid_address")
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
func resolveAndValidate(ctx context.Context, resolver Resolver, policy AddressPolicy, host string, policyDenyKind ErrorKind) ([]netip.Addr, error) {
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := resolver.LookupNetIP(dnsCtx, "ip", host)
	cancel()
	if err != nil {
		slog.Default().Warn("ssrf dial blocked", "host", hostForLog(host), "reason", "dns_failed", "error", errTextForLog(err))
		return nil, ssrfErr(KindDNSFailed, host, fmt.Sprintf("SSRF dial: DNS lookup failed for %q", host), err)
	}
	if len(ips) == 0 {
		slog.Default().Warn("ssrf dial blocked", "host", hostForLog(host), "reason", "no_ips_resolved")
		return nil, ssrfErr(KindDNSFailed, host, fmt.Sprintf("SSRF dial: no IPs resolved for %q", host), nil)
	}

	// Copy the slice so we never mutate the resolver's cached return value.
	safe := make([]netip.Addr, len(ips))
	for i := range ips {
		safe[i] = ips[i].Unmap()
		if !policy(safe[i]) {
			slog.Default().Warn("ssrf dial blocked",
				"host", hostForLog(host), "resolved_ip", safe[i].String(), "reason", reasonLabel(policyDenyKind))
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
			"host", hostForLog(host), "resolved", len(safe), "dialing", maxDialIPs)
		dialList = dialList[:maxDialIPs]
	}
	var lastErr error
	for _, ip := range dialList {
		if ctx.Err() != nil {
			slog.Default().Debug("ssrf dial aborted",
				"host", hostForLog(host), "reason", "context_cancelled", "error", errTextForLog(ctx.Err()))
			return nil, fmt.Errorf("SSRF dial: context cancelled: %w", ctx.Err())
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	slog.Default().Debug("ssrf dial failed",
		"host", hostForLog(host), "ips_tried", len(dialList), "error", errTextForLog(lastErr))
	return nil, fmt.Errorf("SSRF dial: all %d IPs for %q failed: %w", len(dialList), host, lastErr)
}

// SafeTransport returns an *http.Transport hardened against SSRF and
// DNS rebinding. Use [WithAddressPolicy], [WithDialer], [WithResolver],
// and [WithAllowedPorts] to customize.
func SafeTransport(opts ...TransportOption) *http.Transport {
	cfg := transportConfig{
		policy: isPublicAddr,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		resolver:     net.DefaultResolver,
		allowedPorts: map[uint16]struct{}{443: {}},
	}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	// A custom WithAddressPolicy denial reports KindPolicyDenied (the
	// documented "custom policy rejected the IP" kind); the default
	// isPublicAddr policy keeps reporting KindNonPublicIP.
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
