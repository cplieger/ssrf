# Host validation

This page describes which hosts `ValidateURL`, `URLPolicy.Validate` and `IsPublicHost` accept and why, for a developer deciding what input to pass them.

## What counts as a host

The host check is an allowlist. It accepts a host only in one of two shapes and refuses everything else with `KindInvalidHost`.

- An IP literal that `netip.ParseAddr` accepts, with no zone identifier. A zone identifier is the `%eth0` suffix that ties an address to one network interface. It means nothing on a global address, and the WHATWG URL Standard leaves zone support out of host parsing for the same reason.
- A DNS name of at most 253 bytes with two or more labels. Each label is 1 to 63 bytes of ASCII letters, digits, `-` or `_`, and does not begin or end with a hyphen. One trailing root dot is allowed.

A name whose rightmost label is numeric is treated as an IPv4 address rather than a domain, following WHATWG's [ends in a number](https://url.spec.whatwg.org/#ends-in-a-number-checker) rule. That rule is what refuses `0177.0.0.1`, `0x7f.0.0.1`, `127.1` and `192.168.257`.

`localhost` in any ASCII case is refused with `KindLocalhost`, and a name with no dot with `KindBareHostname`.

## Why an allowlist

Standard IDNA processing rewrites some hosts into others. UTS-46, the Unicode mapping that IDNA uses, deletes format characters such as U+200B ZERO WIDTH SPACE and U+00AD SOFT HYPHEN. So `169.254.169.254\u200b` becomes the cloud metadata address. UTS-46 also maps fullwidth and circled digits to ASCII, so `１６９.254.169.254` becomes the same address. A blocklist would have to name each of those characters and would miss the next one. Refusing every byte outside the label set closes the whole class.

## Two consequences for your input

Non-ASCII hosts are refused rather than converted. Convert an internationalized name to its `xn--` A-label, its ASCII form, before you validate it. ssrf does not guess, because a validator that converts names differently from your HTTP client is how bypasses happen.

Bracketed authority syntax such as `[::1]` is refused, because these functions take a host. Use `url.Hostname()` or `net.SplitHostPort` first. `ValidateURL` already does.

## Case matching

Scheme and host matching ignores case for ASCII letters and compares every other byte exactly. That is the whole of the RFC 3986 scheme grammar and the RFC 1035 hostname grammar, since an internationalized name arrives as an `xn--` A-label. Wider Unicode case folding would let a character outside the grammar match a literal. For example, `strings.EqualFold` treats `localhoſt` as `localhost`. Matching only ASCII case also keeps the verdicts independent of the Go toolchain's Unicode tables.

## What the host check does not catch

The check reads the name and does no DNS lookup. A well-formed public-looking name that resolves to an internal address passes it. The host check accepts `localhost.localdomain`, `a.localhost` and `metadata.google.internal`, and all three resolve privately. Only `SafeTransport` stops them, because it checks the resolved address and the connected address. [The transport](transport.md) describes those checks.
