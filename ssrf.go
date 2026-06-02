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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const schemeHTTPS = "https"

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
	policy       Policy
	dialer       *net.Dialer
	resolver     Resolver
	logger       *slog.Logger
	allowedPorts map[uint16]struct{}
	schemes      map[string]struct{}
}

// WithPolicy sets a custom allow/deny policy for resolved IP addresses.
// The policy is called after unmapping IPv4-mapped IPv6 addresses.
// A nil policy is ignored (the default [IsPublicAddr] policy is retained).
func WithPolicy(p Policy) Option {
	return func(c *transportConfig) {
		if p != nil {
			c.policy = p
		}
	}
}

// WithLogger sets a structured logger for SSRF validation warnings.
// A nil logger is ignored (slog.Default() is retained).
func WithLogger(l *slog.Logger) Option {
	return func(c *transportConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithDialer sets a custom [net.Dialer] used for outbound connections.
// The dialer's DialContext is wrapped with SSRF-safe DNS resolution;
// callers can customize Timeout, KeepAlive, and other dialer fields.
// A nil dialer is ignored (the default dialer is retained).
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

// WithAllowedSchemes sets the URL schemes that [ValidateURLWithOptions] accepts.
// By default only "https" is allowed. Mirrors doyensec/safeurl AllowedSchemes.
// Schemes are compared case-insensitively.
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
	return validateURLWithSchemes(raw, nil, slog.Default())
}

// validateURLWithSchemes validates a URL against a set of allowed schemes.
// If schemes is nil, only HTTPS is allowed.
func validateURLWithSchemes(raw string, schemes map[string]struct{}, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ssrfErr(KindInvalidURL, "", "invalid URL", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if schemes == nil {
		if scheme != schemeHTTPS {
			log.Warn("ssrf blocked", "reason", "scheme", "scheme", u.Scheme)
			return ssrfErr(KindBadScheme, "", fmt.Sprintf("URL scheme must be https, got %q", u.Scheme), nil)
		}
	} else {
		if _, ok := schemes[scheme]; !ok {
			log.Warn("ssrf blocked", "reason", "scheme", "scheme", u.Scheme)
			return ssrfErr(KindBadScheme, "", fmt.Sprintf("URL scheme %q is not allowed", u.Scheme), nil)
		}
	}
	host := u.Hostname()
	if host == "" {
		log.Warn("ssrf blocked", "reason", "empty_host")
		return ssrfErr(KindEmptyHost, "", "URL has empty host", nil)
	}
	return validateHostWithLogger(host, log)
}

// IsPublicHost checks that a hostname is not a private/loopback/CGNAT address.
// Returns false for localhost, bare hostnames, RFC 1918/link-local IPs,
// and RFC 6598 shared address space.
func IsPublicHost(host string) bool {
	return validateHost(host) == nil
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

// validateHost rejects hostnames that resolve to non-public addresses.
func validateHost(host string) error {
	return validateHostWithLogger(host, slog.Default())
}

// validateHostWithLogger rejects hostnames that resolve to non-public addresses,
// logging warnings via the provided logger.
func validateHostWithLogger(host string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if host == "" {
		return ssrfErr(KindEmptyHost, "", "empty host", nil)
	}

	// Strip all trailing dots (FQDN notation).
	for strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	if host == "" {
		log.Warn("ssrf blocked", "reason", "empty_host")
		return ssrfErr(KindEmptyHost, host, "empty host after trimming trailing dots", nil)
	}

	if strings.EqualFold(host, "localhost") {
		log.Warn("ssrf blocked", "host", host, "reason", "localhost")
		return ssrfErr(KindLocalhost, host, "URL points to localhost", nil)
	}

	// Parse as IP first.
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !isPublicAddr(addr) {
			log.Warn("ssrf blocked", "host", host, "reason", "non_public_ip")
			return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("URL points to non-public IP: %s", host), nil)
		}
		return nil
	}

	// Not an IP; must be a hostname with at least one dot.
	if !strings.Contains(host, ".") {
		log.Warn("ssrf blocked", "host", host, "reason", "bare_hostname")
		return ssrfErr(KindBareHostname, host, fmt.Sprintf("URL points to bare hostname: %s", host), nil)
	}
	return nil
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

	return hasPublicEmbeddedIPv4(addr)
}

// isNonRoutableRange checks documentation/benchmarking/discard ranges.
// addr must already be unmapped (callers guarantee this via isPublicAddr).
func isNonRoutableRange(addr netip.Addr) bool {
	if addr.Is4() {
		if ietfProtoAssign.Contains(addr) ||
			testNet1.Contains(addr) ||
			testNet2.Contains(addr) ||
			testNet3.Contains(addr) ||
			benchmarking4.Contains(addr) ||
			sixToFourRelay.Contains(addr) {
			return true
		}
	}
	if addr.Is6() && !addr.Is4In6() {
		// nat64Local (RFC 8215 64:ff9b:1::/48) is blocked outright: its
		// RFC 6052 /48 IPv4-embedding offset differs from the well-known
		// /96, so extracting bytes 12-15 would risk an SSRF bypass.
		if discardOnly.Contains(addr) ||
			benchmarking6.Contains(addr) ||
			documentation.Contains(addr) ||
			doc6New.Contains(addr) ||
			srv6SIDs.Contains(addr) ||
			nat64Local.Contains(addr) {
			return true
		}
	}
	return false
}

// hasPublicEmbeddedIPv4 validates IPv4 addresses embedded in IPv6 transition
// mechanism wrappers (6to4, NAT64, Teredo, IPv4-compatible).
func hasPublicEmbeddedIPv4(addr netip.Addr) bool {
	if sixToFour.Contains(addr) {
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		if !isPublicAddr(embedded) {
			return false
		}
	}
	if nat64Wellknown.Contains(addr) {
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if !isPublicAddr(embedded) {
			return false
		}
	}
	if teredoPrefix.Contains(addr) {
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
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return ssrfErr(KindNonPublicIP, "", "stopped after 10 redirects", nil)
		}
		if err := ValidateURL(req.URL.String()); err != nil {
			slog.Default().Warn("ssrf redirect blocked", "url", req.URL.Redacted(), "reason", err.Error())
			return ssrfErr(KindNonPublicIP, req.URL.Hostname(), "redirect blocked (SSRF): "+err.Error(), err)
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
}

// SafeRedirectPolicyWithSchemes returns a redirect policy that validates
// against the given allowed schemes (for use with [WithAllowedSchemes]).
func SafeRedirectPolicyWithSchemes(
	schemes map[string]struct{},
	next func(req *http.Request, via []*http.Request) error,
) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return ssrfErr(KindNonPublicIP, "", "stopped after 10 redirects", nil)
		}
		if err := validateURLWithSchemes(req.URL.String(), schemes, slog.Default()); err != nil {
			slog.Default().Warn("ssrf redirect blocked", "url", req.URL.Redacted(), "reason", err.Error())
			return ssrfErr(KindNonPublicIP, req.URL.Hostname(), "redirect blocked (SSRF): "+err.Error(), err)
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
}

// safeControl returns a net.Dialer Control function that validates the
// actually-connected IP address at socket creation time. This is the
// canonical defense-in-depth against DNS rebinding/TOCTOU, mirroring
// doyensec/safeurl and Stripe smokescreen's approach. The Control hook
// fires after DNS resolution but before the TCP handshake completes.
func safeControl(policy Policy, allowedPorts map[uint16]struct{}, log *slog.Logger) func(network, address string, c syscall.RawConn) error {
	if log == nil {
		log = slog.Default()
	}
	return func(network, address string, _ syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" {
			return ssrfErr(KindNonPublicIP, "", fmt.Sprintf("SSRF control: disallowed network %q", network), nil)
		}

		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return ssrfErr(KindInvalidURL, "", fmt.Sprintf("SSRF control: invalid address %q", address), err)
		}

		// Validate port at dial time.
		if allowedPorts != nil {
			port, parseErr := netip.ParseAddrPort(net.JoinHostPort(host, portStr))
			if parseErr != nil {
				return ssrfErr(KindBadPort, "", fmt.Sprintf("SSRF control: cannot parse port in %q", address), parseErr)
			}
			if _, ok := allowedPorts[port.Port()]; !ok {
				return ssrfErr(KindBadPort, host, fmt.Sprintf("SSRF control: port %d is not allowed", port.Port()), nil)
			}
		}

		// Validate IP at dial time (defense-in-depth).
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("SSRF control: cannot parse IP %q", host), parseErr)
		}
		addr = addr.Unmap()
		if !policy(addr) {
			log.Warn("ssrf control blocked",
				"ip", addr.String(), "reason", "non_public_ip")
			return ssrfErr(KindNonPublicIP, host, fmt.Sprintf("SSRF control: IP %s is not public", addr), nil)
		}
		return nil
	}
}

// safeDialContext returns a DialContext function that resolves DNS and
// validates all resolved IPs against the given policy before connecting.
// The dialer also has a Control hook for defense-in-depth validation.
func safeDialContext(dialer *net.Dialer, policy Policy, resolver Resolver, allowedPorts map[uint16]struct{}, log *slog.Logger) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if log == nil {
		log = slog.Default()
	}
	// Install the Control hook for defense-in-depth.
	dialer.Control = safeControl(policy, allowedPorts, log)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, ssrfErr(KindInvalidURL, "", fmt.Sprintf("SSRF dial: invalid address %q", addr), err)
		}

		// Validate port at resolve time (fail fast).
		if allowedPorts != nil {
			addrPort, parseErr := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", port))
			if parseErr != nil {
				return nil, ssrfErr(KindBadPort, host, fmt.Sprintf("SSRF dial: invalid port %q", port), parseErr)
			}
			if _, ok := allowedPorts[addrPort.Port()]; !ok {
				return nil, ssrfErr(KindBadPort, host, fmt.Sprintf("SSRF dial: port %s is not allowed", port), nil)
			}
		}

		dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := resolver.LookupNetIP(dnsCtx, "ip", host)
		cancel()
		if err != nil {
			return nil, ssrfErr(KindDNSFailed, host, fmt.Sprintf("SSRF dial: DNS lookup failed for %q", host), err)
		}
		if len(ips) == 0 {
			return nil, ssrfErr(KindDNSFailed, host, fmt.Sprintf("SSRF dial: no IPs resolved for %q", host), nil)
		}

		// Copy the slice so we never mutate the resolver's cached return value.
		safe := make([]netip.Addr, len(ips))
		for i := range ips {
			safe[i] = ips[i].Unmap()
			if !policy(safe[i]) {
				log.Warn("ssrf dial blocked",
					"host", host, "resolved_ip", safe[i].String(), "reason", "non_public_ip")
				return nil, ssrfErr(KindNonPublicIP, host, fmt.Sprintf("SSRF dial: resolved IP %s for %q is not public", safe[i], host), nil)
			}
		}

		var lastErr error
		for _, ip := range safe {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("SSRF dial: context cancelled: %w", ctx.Err())
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, fmt.Errorf("SSRF dial: all %d IPs for %q failed: %w", len(ips), host, lastErr)
	}
}

// SafeTransport returns an *http.Transport hardened against SSRF and
// DNS rebinding. Use [WithPolicy], [WithDialer], [WithResolver],
// [WithAllowedPorts], [WithAllowedSchemes], and [WithLogger] to customize.
func SafeTransport(opts ...Option) *http.Transport {
	cfg := transportConfig{
		policy: isPublicAddr,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		resolver:     net.DefaultResolver,
		logger:       slog.Default(),
		allowedPorts: map[uint16]struct{}{443: {}},
		schemes:      map[string]struct{}{schemeHTTPS: {}},
	}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return &http.Transport{
		DialContext:           safeDialContext(cfg.dialer, cfg.policy, cfg.resolver, cfg.allowedPorts, cfg.logger),
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
// with [SafeRedirectPolicyWithSchemes]. Returns nil if only HTTPS is allowed.
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
