# Unsupported by design

This page lists what ssrf leaves out on purpose, for a developer wondering whether a missing feature is coming. These are decisions, not a backlog. To argue one back into scope, open an issue first.

| Feature | Reason |
| --- | --- |
| Custom allow or deny IP lists | `WithAddressPolicy(func(netip.Addr) bool)` already provides this |
| Hostname allowlist or denylist | It is application-layer policy, not core SSRF defense |
| Happy Eyeballs (RFC 8305) | A security library puts correctness before connection speed |
| Response body size limit | Use `io.LimitReader` in your application |
| A blanket `2001::/23` block | It is too broad, because some of its sub-allocations are globally reachable. ssrf blocks the specific non-routable sub-ranges instead |
| ISATAP embedded IPv4 | ISATAP uses `fe80::/64`, which is already blocked, or routable prefixes where the embedded IPv4 address is informational only |
| A DNS-over-HTTPS or DNS-over-TLS resolver | `WithResolver` accepts any resolver implementation |
| An option that allows every port | List the ports you need with `WithAllowedPorts`, or pass the single port of a destination you have already validated |
