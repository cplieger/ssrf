# Error kinds

This page lists the errors ssrf returns and what each one asks you to do, for a developer handling a refused URL in code.

## The error type

Every refusal is an `*ssrf.Error` with `Kind`, `Host`, `Msg` and `Err` fields. `ValidateURL`, `URLPolicy.Validate`, the redirect policies and the transport's checks all return it, and `errors.As` finds it inside the error an `http.Client` returns. An ordinary connection failure after the checks pass, or a cancelled context, is returned as a plain wrapped error instead.

`Host`, when set, holds the host the refusal is about, such as the host part of a URL or a redirect target. It can contain untrusted input, so sanitize it before you log or display it.

## Kinds

| Kind | Meaning |
| --- | --- |
| `KindInvalidURL` | The URL could not be parsed |
| `KindBadScheme` | The scheme is not in the allowed set |
| `KindEmptyHost` | The URL has no host |
| `KindLocalhost` | The host is `localhost` |
| `KindBareHostname` | The host name has no dot |
| `KindNonPublicIP` | The address is not globally routable |
| `KindDNSFailed` | The DNS lookup failed or returned no address |
| `KindPolicyDenied` | Your own `WithAddressPolicy` refused the address |
| `KindBadPort` | The port is not in the allowed set |
| `KindTooManyRedirects` | The redirect chain passed the 10-hop limit |
| `KindInvalidHost` | The string is not a canonical host at all |

When a redirect is refused because its target failed a check, the policy returns the target's own `Kind`, such as `KindBadScheme`, rather than one value for every refused redirect.

## Invalid host or non-public address

`KindInvalidHost` and `KindNonPublicIP` answer different questions, and the difference decides your remedy.

- `KindNonPublicIP` means a well-formed host that points somewhere private, so the URL itself is the problem. Look for a different destination.
- `KindInvalidHost` means the string is not a host. It holds a non-ASCII or other illegal byte, bracketed authority syntax, an oversized name or label, or an IP literal with a zone identifier. Normalize your input instead, with an `xn--` A-label or `url.Hostname()`.

## Handling an error

```go
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
```
