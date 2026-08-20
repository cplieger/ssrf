# Security assurance case: ssrf

This extends the shared
[default assurance case](https://github.com/cplieger/.github/blob/main/assurance-case.md)
with the threat model specific to `ssrf`. Read that first for the shared posture.

## What this library is

`ssrf` validates outbound URLs/IPs and provides a hardened HTTP transport to
defend against Server-Side Request Forgery: stopping a service from being
tricked into making requests to internal/sensitive addresses. It is a security
control, so its correctness is its entire reason to exist.

## Top-level claim

`ssrf` correctly blocks requests to private, loopback, link-local, and other
non-public address ranges, including the bypass techniques attackers use,
when a consumer routes user-influenced URLs through it.

## Threats and mitigations

| Threat                                                                       | Mitigation                                                                                         | Evidence               |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------- |
| Direct request to private / loopback / link-local / CGNAT ranges             | explicit blocklist of all such ranges (IPv4 + IPv6)                                                | range tests            |
| IPv6 transition bypasses (6to4, NAT64, Teredo, IPv4-mapped, IPv4-compatible) | those embeddings are decoded and blocked                                                           | dedicated bypass tests |
| DNS rebinding (validate one IP, connect to another)                          | resolve-once + `Dialer.Control` re-validates the _actually-connected_ IP at dial time              | transport tests        |
| Redirect-based bypass (validated URL 302s to an internal one)                | every redirect hop is re-validated; redirect chains are capped at 10 hops                          | redirect tests         |
| Malformed/edge-case URLs slipping past the parser                            | hardened parsing under fuzz                                                                        | `*_fuzz_test.go`       |
| Case-folding laundering of a host or scheme (`localhoſt`, `\u212Aafka`)      | every case comparison folds over ASCII only, so a rune the grammar excludes cannot match a literal | fold tests             |

## Design note

The core defense is "resolve once, dial the validated IP literally, and
re-validate the connected IP via the transport's `Control` hook," which closes
the classic validate-then-connect TOCTOU gap that naive SSRF filters miss.
Stdlib-only.

The same check-then-use reasoning governs the redirect policy: it classifies the
`*url.URL` net/http is about to dial rather than a re-parse of that URL's text,
so there is no second object for the two halves to disagree about. No exported
function returns or accepts a `*url.URL`, so a caller is never handed a parsed
URL it could mutate after validation.

## Residual risks

- The library protects requests routed _through_ it; a consumer that makes a
  raw `http.Get` bypasses the control. Correct wiring (use the provided client/
  transport for all user-influenced fetches) is the consumer's responsibility.
- New address ranges or transition mechanisms could require blocklist updates.
- Host classification is textual and performs no DNS lookup, so a public-looking
  name that resolves to an internal address (`localhost.localdomain`) passes
  `IsPublicHost` by design. `SafeTransport` is the layer that catches it, at
  resolve time and again at socket time; a consumer using `ValidateURL` or
  `IsPublicHost` without the transport gets scheme and syntax checking only.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
