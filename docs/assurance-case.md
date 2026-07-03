# Security assurance case — ssrf

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
non-public address ranges — including the bypass techniques attackers use —
when a consumer routes user-influenced URLs through it.

## Threats and mitigations

| Threat                                                           | Mitigation                                                                            | Evidence               |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ---------------------- |
| Direct request to private / loopback / link-local / CGNAT ranges | explicit bl- list of all such ranges (IPv4 + IPv6)                                    | range tests            |
| IPv6 transition bypasses (6to4, NAT64, Teredo, IPv4-mapped)      | those embeddings are decoded and blocked                                              | dedicated bypass tests |
| DNS rebinding (validate one IP, connect to another)              | resolve-once + `Dialer.Control` re-validates the _actually-connected_ IP at dial time | transport tests        |
| Redirect-based bypass (validated URL 302s to an internal one)    | redirect allowlist / re-validation on redirect                                        | redirect tests         |
| Malformed/edge-case URLs slipping past the parser                | hardened parsing under fuzz                                                           | `*_fuzz_test.go`       |

## Design note

The core defense is "resolve once, then pin the connection to the validated IP
via the transport's `Control` hook," which closes the classic
validate-then-connect TOCTOU gap that naive SSRF filters miss. Stdlib-only.

## Residual risks

- The library protects requests routed _through_ it; a consumer that makes a
  raw `http.Get` bypasses the control. Correct wiring (use the provided client/
  transport for all user-influenced fetches) is the consumer's responsibility.
- New address ranges or transition mechanisms could require blocklist updates.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
