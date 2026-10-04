# Blocked address ranges

This page lists every address range `IsPublicAddr` refuses, for a developer checking whether a destination will pass. `SafeTransport` uses `IsPublicAddr` unless you pass your own policy with `WithAddressPolicy`.

## IPv4

The IPv4 list follows RFC 6890, RFC 5737 and RFC 2544.

- RFC 1918 private, loopback, link-local, multicast and unspecified addresses
- `0.0.0.0/8`, this host, and `240.0.0.0/4`, reserved and broadcast
- `100.64.0.0/10`, shared address space for carrier-grade NAT, RFC 6598
- `192.0.0.0/24`, IETF protocol assignments
- `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, the TEST-NET-1, TEST-NET-2 and TEST-NET-3 documentation ranges
- `198.18.0.0/15`, benchmarking
- `192.88.99.0/24`, the deprecated 6to4 relay

## IPv6

- Loopback, unique local, link-local, multicast and unspecified addresses
- `fec0::/10`, deprecated site-local, RFC 3879
- `100::/64`, discard-only, RFC 6666
- `2001:2::/48`, benchmarking, RFC 5180
- `2001:db8::/32`, documentation, RFC 3849
- `3fff::/20`, documentation, RFC 9637
- `5f00::/16`, SRv6 segment identifiers, RFC 9602

## IPv4 inside IPv6

Some IPv6 transition addresses carry an IPv4 address inside them. ssrf extracts and checks the embedded address in the 6to4, well-known NAT64, Teredo and IPv4-compatible forms. A private IPv4 address cannot pass inside one of them. ssrf blocks the local-use NAT64 prefix as a whole instead.

- `2002::/16`, 6to4, RFC 3056
- `64:ff9b::/96`, NAT64 well-known prefix, RFC 6052
- `64:ff9b:1::/48`, NAT64 local-use prefix, RFC 8215, blocked as a whole
- `2001::/32`, Teredo, RFC 4380, where both the client and the server IPv4 addresses are checked
- `::/96`, the deprecated IPv4-compatible form

An IPv4-mapped IPv6 address such as `::ffff:127.0.0.1` is unwrapped to its IPv4 address before any check.
