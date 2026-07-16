# Contributing to ssrf

This repo-specific guide supplements the
[org-wide defaults](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md).
`ssrf` is a security library: most of the surface area is small, but a handful
of invariants are load-bearing and easy to break without noticing.

## What this library guarantees

`ssrf` validates URLs and resolved IPs against SSRF attacks and ships a
hardened `*http.Transport`. The public surface lives in a single file,
`ssrf.go`:

- `ValidateURL(raw)` — scheme must be `https` and the host must be public.
- `IsPublicHost(host)` / `IsPublicAddr(netip.Addr)` — globally-routable
  predicates.
- `SafeTransport(opts ...TransportOption)` — the hardened transport (see
  invariants below); configured via `WithAddressPolicy`, `WithDialer`,
  `WithResolver`, `WithAllowedPorts`, and `WithAnyPort`.
- `SafeRedirectPolicy` — HTTPS-only redirect policy; wire as
  `http.Client.CheckRedirect`; each redirect hop is re-validated.
- `URLPolicy` (`NewURLPolicy(schemes...)`, `.Validate(raw)`,
  `.RedirectPolicy(next)`) — custom-scheme URL validation and redirect
  policies; the zero value is HTTPS-only.

Errors are `*ssrf.Error` with a machine-readable `Kind` (`KindBadScheme`,
`KindNonPublicIP`, `KindBadPort`, …); consumers branch on it via `errors.As`.
Redirect-policy rejections propagate the inner `Kind` (a bad-scheme redirect
surfaces as `KindBadScheme`, not a blanket `KindNonPublicIP`); the hop-cap
returns `KindTooManyRedirects`.

## Security invariants (do not weaken)

These are the parts a change can silently break. Treat them as contracts.

- **Two-layer DNS-rebinding defense.** `safeDialContext` resolves a hostname
  **once**, validates every returned IP, then dials the literal IP — and it
  also installs a `net.Dialer.Control` hook (`safeControl`) that re-validates
  the actually-connected IP at socket creation, after the OS resolves but
  before the TCP handshake. Never collapse these two layers into one; the
  pairing is what defeats TOCTOU rebinding. Two implementation details keep it
  intact and are easy to break: (1) `safeDialContext` sets
  `dialer.ControlContext = nil` before assigning `dialer.Control`, because a
  non-nil `ControlContext` takes precedence in `net.Dialer` and a
  caller-supplied one (via `WithDialer`) would otherwise silently shadow
  `safeControl`; (2) the `maxDialIPs` (8) dial-attempt cap is applied only after
  every resolved IP has been validated, so it bounds dial time against a
  resolver returning many valid-but-blackholed IPs without ever skipping a
  check (fail-closed).
- **`IsPublicHost` is a silent predicate; only enforcement logs.**
  `IsPublicHost` and the enforcement path share one classification core
  (`hostValidationError`), but only the enforcement wrapper
  (`validateURLWithSchemes`, reached via `ValidateURL`) emits a `slog.Warn`; the
  redirect policy re-validates each hop through the silent core
  (`classifyURLWithSchemes`) and emits its own single `ssrf redirect blocked`
  line. Keep `IsPublicHost` log-free so callers can probe host publicness
  without polluting block dashboards. All logging goes through `slog.Default()` (there
  is no per-instance logger option), and every block log carries a bounded
  snake_case `reason` from `reasonLabel(ErrorKind)`; never put a host or IP in
  the `reason` attribute (use the `error` key for detail) or block-dashboard
  cardinality blows up.
- **`isPublicAddr` unmaps first.** IPv4-mapped IPv6 (`::ffff:x.x.x.x`) is
  unmapped before any prefix check, so IPv4 block ranges still apply.
- **IPv6 transition wrappers are unwrapped and re-validated.** 6to4
  (`2002::/16`), NAT64 well-known (`64:ff9b::/96`), Teredo (`2001::/32`, client
  IPv4 XOR-inverted in bytes 12–15), and IPv4-compatible (`::/96`) all extract
  the embedded IPv4 and recurse through `isPublicAddr`. NAT64-local
  (`64:ff9b:1::/48`) is blocked outright rather than unwrapped, because its
  embedding offset differs from the well-known prefix.
- **The blocked-range list and the "Unsupported by Design" table in the
  `README.md` are the contract**, not tunable knobs. Adding a range, or
  implementing a documented non-goal (hostname allowlists, Happy Eyeballs,
  response size limits, a blanket `2001::/23` block), needs explicit
  discussion first.
- **Stdlib-only for non-test code.** The only dependency in `go.mod` is the
  test-only `pgregory.net/rapid`. Keep it that way.

## Local development

Requires the Go toolchain pinned in `go.mod`.

```sh
go build ./...
go vet ./...
go test ./...                # unit + property + regression suites
go test -race ./...          # the race detector is part of CI
```

Linting uses golangci-lint **v2** with the config in `.golangci.yaml`
(gofumpt with `-extra` rules, gci import ordering, plus `gosec`, `gocritic`,
`revive`, and more). `golangci-lint run` reports unformatted files as issues,
so run it before pushing and apply fixes with `golangci-lint fmt`:

```sh
golangci-lint run
golangci-lint fmt
```

## Property and fuzz tests

Correctness here is enforced by property-based and fuzz tests, not just
examples — extend them when you touch validation logic.

- Property test (`pgregory.net/rapid`): `TestValidateURL_properties` in
  `ssrf_prop_test.go`. Runs as part of `go test ./...`.
- Fuzz targets in `ssrf_fuzz_test.go`, each with an independent oracle
  (the fuzz tests re-derive blocked ranges separately from the implementation
  so a regression in `ssrf.go` is caught against a second source of truth):

  - `FuzzValidateURL`
  - `FuzzIsPublicAddr`
  - `FuzzIsPublicHost`
  - `FuzzSafeControl`
  - `FuzzValidateURLWithSchemes`

Run a single target locally (Go only fuzzes one at a time):

```sh
go test -run '^$' -fuzz '^FuzzIsPublicAddr$' -fuzztime 30s
```

If you add or change a blocked range, update the independent oracle
(`independentBlockedRanges` and the transition-wrapper builders) in
`ssrf_fuzz_test.go` so the two sources of truth stay in agreement.

## Commits and PRs

Commits follow [Conventional Commits](https://www.conventionalcommits.org/);
`cliff.toml` parses them for release notes and version bumps. Use `feat:` for
new API, `fix:` for bug fixes, and **`sec:` for security fixes** (it maps to
the Security changelog section). `test:`, `fuzz:`, `docs:`, `chore:`, and
`ci:` do not trigger a release. Branch from `main`, keep the change focused,
ensure `go test ./...` and `golangci-lint run` pass, and open a PR.

## Conduct & security

By participating you agree to the
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report vulnerabilities through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md) —
never in a public issue.
