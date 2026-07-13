package ssrf

import (
	"fmt"
	"net/netip"
	"testing"

	"pgregory.net/rapid"
)

// ValidateURL must reject every non-https scheme.
func TestValidateURL_rejects_non_https_schemes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		scheme := rapid.SampledFrom([]string{"http", "ftp", "gopher", "file", "ssh", "ws", "wss"}).Draw(t, "scheme")
		url := fmt.Sprintf("%s://example.com/file", scheme)

		err := ValidateURL(url)

		if err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error for non-https scheme", url)
		}
	})
}

// ValidateURL and IsPublicHost stay consistent: if ValidateURL accepts an https
// URL with a given host, IsPublicHost must also accept that host.
func TestValidateURL_IsPublicHost_consistency(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Domain-like hostnames with at least one dot (to pass the bare-name gate).
		label := rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "label")
		tld := rapid.SampledFrom([]string{"com", "org", "net", "io"}).Draw(t, "tld")
		host := label + "." + tld
		url := fmt.Sprintf("https://%s/path", host)

		urlErr := ValidateURL(url)
		hostOK := IsPublicHost(host)

		if urlErr == nil && !hostOK {
			t.Errorf("ValidateURL(%q) = nil but IsPublicHost(%q) = false", url, host)
		}
	})
}

// isPublicAddr rejects all non-public IPv4 addresses (stdlib + re-derived
// blocked-range oracle).
func TestIsPublicAddr_rejects_all_non_public(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "ipv4")
		addr := netip.AddrFrom4([4]byte(b))
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsMulticast() || addr.IsUnspecified() || sharedAddrSpace.Contains(addr) ||
			thisHostNet.Contains(addr) || reserved240.Contains(addr) {
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false for non-public address", addr)
			}
		}
	})
}

// isPublicAddr rejects all non-public IPv6 addresses. Symmetric to the IPv4
// property; closes the mutation gap where a flip on the IPv6 code path could
// survive because only IPv4 addresses were randomly drawn.
func TestIsPublicAddr_rejects_all_non_public_ipv6(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "ipv6")
		addr := netip.AddrFrom16([16]byte(b))
		// Skip IPv4-mapped forms — covered by the mapped-consistency property
		// and by Unmap() inside hostValidationError/safeDialContext.
		if addr.Is4In6() || addr.Is4() {
			return
		}
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsMulticast() || addr.IsUnspecified() {
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false for non-public IPv6 address", addr)
			}
		}
	})
}

// ValidateURL never panics on arbitrary input.
func TestValidateURL_never_panics(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "url")
		_ = ValidateURL(input) // must not panic
	})
}

// IPv4-mapped IPv6 addresses are rejected consistently with their IPv4
// equivalents (defense-in-depth for CVE-2024-24790).
func TestValidateURL_ipv4_mapped_ipv6_consistency(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "ipv4")
		addr := netip.AddrFrom4([4]byte(b))
		if !isPublicAddr(addr) {
			mapped := netip.AddrFrom16(addr.As16())
			host := mapped.String()
			url := fmt.Sprintf("https://[%s]/file.txt", host)
			err := ValidateURL(url)
			if err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error for IPv4-mapped IPv6 of non-public %v", url, addr)
			}
		}
	})
}

// ValidateURL must reject any host made of two-or-more all-numeric labels that
// netip.ParseAddr does not parse as a canonical IP — the non-canonical IPv4
// encoding class (dotted-octal/hex, short-form, oversized inet_aton) that a
// libc resolver would still resolve to an internal address. The library's own
// contract (isNumericLabel: "a real DNS name never has an all-numeric label
// set") makes this a total invariant, not an example. Uses only fmt/netip/rapid
// (already imported). A mutant removing the looksLikeNumericIPv4 gate lets these
// fall through the has-a-dot hostname arm and be accepted, failing this property.
func TestValidateURL_numeric_ipv4_encodings_rejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		host := fmt.Sprintf("%d.%d",
			rapid.IntRange(0, 100000).Draw(t, "a"),
			rapid.IntRange(0, 100000).Draw(t, "b"))
		if rapid.Bool().Draw(t, "third") {
			host = fmt.Sprintf("%s.%d", host, rapid.IntRange(0, 100000).Draw(t, "c"))
		}
		// A canonically parseable IP is isPublicAddr's job, covered elsewhere.
		if _, err := netip.ParseAddr(host); err == nil {
			return
		}
		url := fmt.Sprintf("https://%s/x", host)
		if err := ValidateURL(url); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want rejection of non-canonical numeric IPv4 encoding", url)
		}
	})
}
