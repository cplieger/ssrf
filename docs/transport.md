# The transport and redirect policies

This page describes how `SafeTransport` and the redirect policies check outbound connections, what their options change and what they log, for a developer wiring them into an `http.Client`.

## Two checks on every connection

`SafeTransport` checks each connection's address twice.

1. When it dials a name, it resolves the name once, checks every returned address and fails if any one is refused. It then connects to a checked address as a literal IP. The name cannot switch to an internal address between the check and the connection, which is the attack called DNS rebinding.
2. A `net.Dialer.Control` hook checks the address the socket actually connects to, after the operating system has the address and before the TCP handshake. The hook accepts only `tcp4` and `tcp6` connections.

Both checks also enforce the allowed ports. The DNS lookup has a 5-second timeout. When a name resolves to more than eight addresses, all of them are checked and only the first eight are dialed, which bounds the time a hostile resolver can cost you.

Every connection, TLS and HTTP/2 included, goes through this dial path. The transport sets no proxy, so it ignores `HTTP_PROXY` and `HTTPS_PROXY` and connects to the destination itself.

## Options

| Option | Effect |
| --- | --- |
| `WithAllowedPorts(...uint16)` | Replaces the allowed ports, 443 by default. Calling it with no ports keeps the default, and a later call replaces an earlier one |
| `WithAddressPolicy(AddressPolicy)` | Replaces `IsPublicAddr` with your own allow or deny function, called on each address after IPv4-mapped IPv6 addresses are unwrapped |
| `WithResolver(Resolver)` | Replaces `net.DefaultResolver`, for example with a test resolver or a DNS-over-HTTPS client |
| `WithDialer(*net.Dialer)` | Replaces the dialer, so you can set its timeout and keep-alive |
| `WithLogger(*slog.Logger)` | Sends the transport's refusal lines to this logger instead of `log/slog`'s default |

A nil policy, resolver, dialer or logger is ignored, and the default stays. A refusal by your own address policy reports `KindPolicyDenied`, and a refusal by the default policy reports `KindNonPublicIP`.

`WithDialer` copies your dialer, so ssrf never changes the one you passed. On the copy it always installs its own `Control` hook and clears `ControlContext`, because a `ControlContext` set by the caller would otherwise take precedence and skip the socket-time check.

## Ports

No option allows every port. An empty set refuses every port. When your peer sits on a port you cannot know in advance, build the transport once the destination is known and pass that single port. Pinning a destination you have already validated is a stronger check than a standing policy that allows any port.

## Defaults

| Setting | Default |
| --- | --- |
| Dial timeout | 10 seconds |
| TCP keep-alive | 30 seconds |
| TLS handshake timeout | 10 seconds |
| Response header timeout | 15 seconds |
| Expect-continue timeout | 1 second |
| Idle connection timeout | 90 seconds |
| Idle connections | 100 in total, 4 per host |
| HTTP/2 | attempted |

`SafeTransport` returns a plain `*http.Transport`, so you can change any of these fields on the value it returns. Leave `DialContext` as it is, because it carries both checks.

## Redirect policies

`SafeRedirectPolicy(next)` and `URLPolicy.RedirectPolicy(next)` are `CheckRedirect` functions. They check each hop's URL against the policy's schemes and the host rules on [Host validation](host-validation.md), and stop after 10 redirects with `KindTooManyRedirects`. `SafeRedirectPolicy` allows HTTPS only. When a hop passes, they call `next` if you passed one, so you can add your own redirect logic.

A refused hop returns an `*ssrf.Error` that carries the hop's own `Kind`, such as `KindBadScheme`. So `errors.As` on the client's error reports the real reason.

Schemes are a `URLPolicy` setting and never a transport option. Use one `URLPolicy` for the first request and for its redirects, and the transport for the addresses and ports.

## Logging

The validation functions do not log. `ValidateURL`, `URLPolicy.Validate` and `IsPublicHost` return their verdict and nothing else. The returned `*Error` carries `Kind`, `Host`, `Msg` and `Err`, so you already hold everything a log line could say, and you decide whether to record it, at your level, through your logger.

The transport logs, because you cannot see its refusals otherwise. The dial path, the `Control` hook and the redirect policies run inside `net/http`, where a refusal can be retried or wrapped before it reaches you. Each refusal emits one `Warn` line, `ssrf dial blocked`, `ssrf control blocked` or `ssrf redirect blocked`. Each line has a bounded snake_case `reason` attribute such as `non_public_ip`, `bad_port` or `too_many_redirects`, which you can count on a dashboard.

The dial and `Control` lines go to the logger you pass with `WithLogger`, so a program running one transport per peer can add the peer's name to every line. Without it they go to `log/slog`'s default logger at the time each line is written. The redirect policies are not transport options, so their lines always go to the default logger.

Every untrusted value in those lines is sanitized and length-bounded first. A host, address, URL or port is attacker-influenced by definition, and `slog`'s `JSONHandler` escapes only what JSON requires. C1 control characters, Unicode bidirectional controls and U+2028 and U+2029 would otherwise reach your log pipeline intact. Each value is capped at the longest legal length for its kind, 253 bytes for a host, so a real host is never cut. The cap also stops one refusal from writing an attacker-sized record.

To log a refused host yourself, take it from the error rather than from the transport's line:

```go
if err := ssrf.ValidateURL(raw); err != nil {
    var serr *ssrf.Error
    if errors.As(err, &serr) {
        // serr.Host can contain untrusted input. Sanitize it before it
        // reaches a log sink or a rendered page, here with runesafe.
        slog.Warn("refused an outbound URL",
            "host", runesafe.SanitizeSingleLineBounded(serr.Host, 253),
            "kind", serr.Kind)
    }
}
```
