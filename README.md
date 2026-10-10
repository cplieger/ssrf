# ssrf

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/ssrf/v4.svg)](https://pkg.go.dev/github.com/cplieger/ssrf/v4) [![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/ssrf)](https://github.com/cplieger/ssrf/blob/main/go.mod) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/ssrf/badges/mutation.json)](https://github.com/cplieger/ssrf/issues?q=label%3Agremlins-tracker)

ssrf keeps your Go service's outbound requests off private networks and cloud metadata endpoints, by checking URLs before you fetch and every address at connect time.

It replaces the URL checks and custom dialer you would otherwise write around `net/http`, and it hands back a plain `*http.Transport` and `CheckRedirect` function. At run time it uses the standard library and one dependency, [runesafe](https://github.com/cplieger/runesafe) by the same author, to clean untrusted text in its log lines. It needs Go 1.27.2 or later and is licensed under Apache-2.0.

## Why use it

ssrf is built for Go code that fetches URLs a user or an upstream response supplies, such as webhooks and link previews.

- `ValidateURL` refuses a non-HTTPS URL, `localhost`, a name with no dot, and private, loopback, link-local, carrier-grade NAT and reserved addresses.
- `SafeTransport` stops DNS rebinding, where a checked name later resolves to an internal address. It looks up each name once, refuses it when any address is not public, and connects only to a checked address. It checks the connected address again before the TCP handshake.
- It also checks the IPv4 address inside a 6to4, NAT64 or Teredo IPv6 address.
- The transport connects to port 443 only unless you list other ports.
- Every refusal is an `*ssrf.Error` whose `Kind` you can switch on.

Consider [Smokescreen](https://github.com/stripe/smokescreen) if you want a separate egress proxy instead of a library. It authenticates clients over mTLS and applies a hostname allowlist per client.

## Install

```sh
go get github.com/cplieger/ssrf/v4@latest
```

## Usage

Check a URL, then fetch it through a client that checks every address and every redirect:

```go
import "github.com/cplieger/ssrf/v4"

if err := ssrf.ValidateURL("https://example.com/data.json"); err != nil {
    return err
}

client := &http.Client{
    Timeout:       30 * time.Second,
    Transport:     ssrf.SafeTransport(),
    CheckRedirect: ssrf.SafeRedirectPolicy(nil),
}
```

To allow plain HTTP as well, set the schemes on a `URLPolicy` and the ports on the transport. The policy checks schemes on the first request and on every redirect, and the transport checks addresses and ports at dial time:

```go
policy := ssrf.NewURLPolicy("https", "http")
client := &http.Client{
    Transport:     ssrf.SafeTransport(ssrf.WithAllowedPorts(443, 80)),
    CheckRedirect: policy.RedirectPolicy(nil),
}
if err := policy.Validate("http://example.com/data.json"); err != nil {
    return err
}
```

Check an address you already resolved:

```go
if ssrf.IsPublicAddr(netip.MustParseAddr("8.8.8.8")) {
    // safe to connect
}
```

[Error kinds](docs/errors.md) shows how to switch on a refusal's `Kind`. The `Example` functions on pkg.go.dev are runnable, and `go test` keeps them true.

## API

- Validation: `ValidateURL`, `IsPublicHost`, `IsPublicAddr`, and `URLPolicy` with `NewURLPolicy` and its `Validate` method.
- Transport: `SafeTransport` with the options `WithAllowedPorts`, `WithAddressPolicy`, `WithResolver`, `WithDialer` and `WithLogger`, and the `TransportOption`, `AddressPolicy` and `Resolver` types.
- Redirects: `SafeRedirectPolicy` and `URLPolicy.RedirectPolicy`, which check every hop and stop after 10.
- Errors: `Error`, with its `Kind`, `Host`, `Msg` and `Err` fields, and the `ErrorKind` constants.

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/ssrf/v4).

## Validation reads the name, the transport checks the address

`ValidateURL`, `IsPublicHost` and `URLPolicy.Validate` do no DNS lookup. They judge the host as written, so a public-looking name that resolves to an internal address passes them. The host check accepts `localhost.localdomain`, `a.localhost` and `metadata.google.internal`, and all three resolve privately. Use the validation functions with `SafeTransport`, which checks the resolved address and the connected address.

The host check accepts two kinds of host and refuses every other string, most with `KindInvalidHost`. One is an IP address without a zone suffix such as `%eth0`, which names a network interface. The other is an ASCII DNS name with at least two labels, such as `api.example.com`.

ssrf refuses a non-ASCII host instead of converting it, so convert an internationalized name to its `xn--` form first. The C library's resolver reads `0177.0.0.1`, `0x7f.0.0.1` and `127.1` as 127.0.0.1, so the check refuses any name whose last label is a number, with `KindNonPublicIP`. Pass a bare host without brackets. `ValidateURL` already does this with `url.Hostname()`.

[Host validation](docs/host-validation.md) has the full grammar and the reasons for it, and [Blocked address ranges](docs/blocked-ranges.md) lists every refused range.

## Ports, redirects and logging

`SafeTransport` connects to port 443 only, unless you list other ports with `WithAllowedPorts`. The list replaces the default, and a call with no ports keeps 443. No option allows every port. If you learn the port only at run time, validate the destination first, then build a transport that allows that one port.

The redirect policies refuse a hop with the hop's own `Kind`, such as `KindBadScheme`. The transport sets no proxy, so it ignores `HTTP_PROXY` and `HTTPS_PROXY` and connects to the destination itself.

The validation functions log nothing. Each transport or redirect refusal logs one `Warn` line, with a bounded `reason` attribute and its untrusted values sanitized. Transport lines go to the logger you pass with `WithLogger`, or to `slog`'s default logger. Redirect lines always go to the default logger. [The transport](docs/transport.md) covers the options, defaults and log lines.

## Unsupported by design

ssrf has no IP allow or deny lists beyond `WithAddressPolicy`, no hostname allowlist, no Happy Eyeballs fast connect and no response size limit. It also has no blanket `2001::/23` block, no ISATAP unwrapping, no built-in DNS-over-HTTPS resolver and no allow-every-port option. [Unsupported by design](docs/non-goals.md) gives the reason for each and what to use instead.

## Credits

The socket-time check uses a `net.Dialer` `Control` hook the way [safedialer](https://github.com/mccutchen/safedialer) and [safeurl](https://github.com/doyensec/safeurl) do. safedialer adapts Andrew Ayer's 2019 post on preventing SSRF in Go. The typed error kinds and the port allowlist with no allow-all setting also follow safeurl.

## Documentation

- [Host validation](docs/host-validation.md) defines which hosts pass and why.
- [The transport and redirect policies](docs/transport.md) covers both checks, the options, the defaults and the log lines.
- [Error kinds](docs/errors.md) lists every `Kind` and the remedy each one asks for.
- [Blocked address ranges](docs/blocked-ranges.md) lists every refused IPv4 and IPv6 range.
- [Unsupported by design](docs/non-goals.md) lists the features left out on purpose, with the reasons.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).
