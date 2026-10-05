# Contributing to ssrf

The [shared rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) for commits, releases, synced files and checks apply here.

## Scope

Open an issue before you add a blocked range. A new range makes addresses that pass validation today fail, so it changes what [Blocked address ranges](docs/blocked-ranges.md) promises callers.

## Rules

- A new or changed blocked range needs its prefix and its family's predicate check in `ssrf.go`, an entry in `independentBlockedRanges` in `ssrf_fuzz_test.go`, and a line in `docs/blocked-ranges.md`. The fuzz oracle cannot catch an unlisted range that `IsPublicAddr` accepts.
- A new IPv6 form that carries an IPv4 address needs its prefix and unwrapping in `ssrf.go`, a seed builder and an oracle branch in `FuzzIsPublicAddr`, and its line in `docs/blocked-ranges.md`. Without the branch, the fuzzer never checks the embedded address.
- A new `ErrorKind` goes last in its const block, becomes the `TestReasonLabel_exhaustive` loop bound, and needs a `reasonLabels` entry, a `docs/errors.md` row and a place in `TestErrorKind_constants_distinct_and_nonzero`. Both tests check only the kinds they name.
