# ssrf
> URL validation to prevent server-side request forgery (SSRF)

Go library that validates URLs and IP addresses against SSRF attacks. Rejects private/loopback/link-local/CGNAT addresses, enforces HTTPS, detects IPv6 transition mechanism bypasses (6to4, NAT64, IPv4-compatible), and provides a hardened HTTP transport with DNS rebinding protection. Standard library only (test-only dependency on pgregory.net/rapid for property-based testing).

## Install
<!-- TODO: registry/pull link -->
`go get github.com/cplieger/ssrf@latest`

## Usage
```go
import "github.com/cplieger/ssrf"

// Validate a URL before fetching
if err := ssrf.ValidateURL("https://example.com/file.srt"); err != nil {
    log.Fatal(err)
}

// Use the hardened transport for all outbound requests
client := &http.Client{
    Transport:     ssrf.SafeTransport(),
    CheckRedirect: ssrf.SafeRedirectPolicy(nil),
}
```

## API
- `ValidateURL(raw string) error` — checks scheme is HTTPS and host is public
- `IsPublicHost(host string) bool` — returns whether a host/IP is globally routable
- `SafeRedirectPolicy(next) func` — redirect policy that validates each hop
- `SafeTransport() *http.Transport` — transport with DNS-rebinding-safe dial

## License
GPL-3.0 — see [LICENSE](LICENSE).
