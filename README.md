# ssrf

[![CI](https://github.com/cplieger/ssrf/actions/workflows/ci.yaml/badge.svg)](https://github.com/cplieger/ssrf/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/ssrf.svg)](https://pkg.go.dev/github.com/cplieger/ssrf)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

> URL validation to prevent server-side request forgery (SSRF)

Go library that validates URLs and IP addresses against SSRF attacks. Rejects private/loopback/link-local/CGNAT addresses, enforces HTTPS (configurable), detects IPv6 transition mechanism bypasses (6to4, NAT64, Teredo, IPv4-compatible), and provides a hardened HTTP transport with DNS rebinding protection via both resolve-once semantics and a `net.Dialer.Control` hook for defense-in-depth. Standard library only (test-only dependency on pgregory.net/rapid for property-based testing).

## Install

`go get github.com/cplieger/ssrf@latest`

## Usage

```go
import "github.com/cplieger/ssrf"

// Validate a URL before fetching
if err := ssrf.ValidateURL("https://example.com/data.json"); err != nil {
    log.Fatal(err)
}

// Use the hardened transport for all outbound requests
client := &http.Client{
    Transport:     ssrf.SafeTransport(),
    CheckRedirect: ssrf.SafeRedirectPolicy(nil),
}

// Allow HTTP + HTTPS with custom ports
client = &http.Client{
    Transport: ssrf.SafeTransport(
        ssrf.WithAllowedSchemes("https", "http"),
        ssrf.WithAllowedPorts(443, 80),
    ),
}

// Programmatic error handling
var ssrfErr *ssrf.Error
if errors.As(err, &ssrfErr) {
    switch ssrfErr.Kind {
    case ssrf.KindBadScheme:
        // handle scheme error
    case ssrf.KindNonPublicIP:
        // handle blocked IP
    case ssrf.KindBadPort:
        // handle port restriction
    }
}

// Check a pre-resolved IP directly
addr := netip.MustParseAddr("8.8.8.8")
if ssrf.IsPublicAddr(addr) {
    // safe to connect
}
```

## API

### Types

- `Option` — functional option for configuring `SafeTransport`
- `Policy func(netip.Addr) bool` — allow/deny predicate for resolved IPs
- `Resolver` — interface for DNS resolution (`LookupNetIP`)
- `Error` — structured SSRF error with `Kind`, `Host`, `Msg`, and `Err` fields
- `ErrorKind` — enum classifying SSRF validation failures

### Functions

- `ValidateURL(raw string) error` — checks scheme is HTTPS and host is public
- `IsPublicHost(host string) bool` — returns whether a host/IP is globally routable
- `IsPublicAddr(addr netip.Addr) bool` — returns whether an IP is globally routable
- `SafeRedirectPolicy(next) func` — redirect policy that validates each hop
- `SafeRedirectPolicyWithSchemes(schemes, next) func` — redirect policy with custom scheme set
- `SafeTransport(opts ...Option) *http.Transport` — transport with DNS-rebinding-safe dial + Control hook
- `AllowedSchemes(opts ...Option) map[string]struct{}` — extract scheme set for redirect policies

### Options

- `WithPolicy(Policy) Option` — inject a custom allow/deny IP predicate
- `WithDialer(*net.Dialer) Option` — inject a custom net.Dialer
- `WithResolver(Resolver) Option` — inject a custom DNS resolver
- `WithAllowedPorts(...uint16) Option` — restrict outbound ports (default: 443 only)
- `WithAllowedSchemes(...string) Option` — configure allowed URL schemes (default: https only)
- `WithLogger(*slog.Logger) Option` — inject a structured logger for SSRF warnings (default: slog.Default())

### Structured Errors

All errors returned by `ValidateURL` and `SafeTransport`'s dial function are `*ssrf.Error` with a `Kind` field:

| Kind | Meaning |
|------|---------|
| `KindInvalidURL` | URL could not be parsed |
| `KindBadScheme` | Scheme is not in the allowed set |
| `KindEmptyHost` | No host component |
| `KindLocalhost` | Points to localhost |
| `KindBareHostname` | Hostname without dots |
| `KindNonPublicIP` | IP is not globally routable |
| `KindDNSFailed` | DNS resolution failed |
| `KindPolicyDenied` | Custom policy rejected the IP |
| `KindBadPort` | Port is not in the allowed set |

### Defense-in-Depth: Dialer.Control Hook

The transport uses **two layers** of IP validation:

1. **Resolve-once** — DNS is resolved once, all IPs validated, then the dialer connects to the literal IP (prevents DNS rebinding via TOCTOU).
2. **`net.Dialer.Control` hook** — validates the actually-connected IP at socket creation time, after the OS has resolved the address but before the TCP handshake. This mirrors the canonical pattern from [doyensec/safeurl](https://github.com/doyensec/safeurl), [Stripe smokescreen](https://github.com/stripe/smokescreen), and [mccutchen/safedialer](https://github.com/mccutchen/safedialer).

### Blocked IP Ranges

IPv4 (RFC 6890 + RFC 5737 + RFC 2544):

- RFC 1918 private, loopback, link-local, multicast, unspecified
- `0.0.0.0/8` (this host), `240.0.0.0/4` (reserved/broadcast)
- `100.64.0.0/10` (CGNAT, RFC 6598)
- `192.0.0.0/24` (IETF Protocol Assignments)
- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (TEST-NET 1/2/3)
- `198.18.0.0/15` (Benchmarking)
- `192.88.99.0/24` (deprecated 6to4 relay)

IPv6:

- Loopback, ULA, link-local, multicast, unspecified
- `100::/64` (Discard-Only, RFC 6666)
- `2001:2::/48` (Benchmarking, RFC 5180)
- `2001:db8::/32` (Documentation, RFC 3849)
- `3fff::/20` (Documentation, RFC 9637)
- `5f00::/16` (SRv6 SIDs, RFC 9602)

IPv6 transition mechanisms (embedded IPv4 extracted and re-validated):

- `2002::/16` (6to4, RFC 3056)
- `64:ff9b::/96` (NAT64 well-known, RFC 6052)
- `64:ff9b:1::/48` (NAT64 local, RFC 8215 — blocked outright)
- `2001::/32` (Teredo, RFC 4380 — client IPv4 XOR-inverted in bits 96–127)
- `::/96` (deprecated IPv4-compatible)

## Unsupported by Design

The following features are intentionally NOT implemented:

| Feature | Rationale |
|---------|-----------|
| Custom allow/deny IP lists | `WithPolicy(func(netip.Addr) bool)` already provides this |
| Hostname allowlist/denylist | Application-layer policy, not core SSRF defense |
| Happy Eyeballs (RFC 8305) | Security library prioritizes correctness over speed |
| Response body size limit | Use `io.LimitReader` at the application layer |
| Blanket `2001::/23` block | Overly broad; some sub-allocations are globally reachable. We block specific non-routable sub-ranges instead |
| ISATAP embedded IPv4 | Uses `fe80::/64` (already blocked) or routable prefixes where embedded IPv4 is informational only |
| DNS-over-HTTPS/TLS resolver | `WithResolver` enables plugging in any resolver implementation |

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

GPL-3.0 — see [LICENSE](LICENSE).
