package ssrf

import (
	"net/netip"
	"testing"
)

func TestIsPublicAddr_exported(t *testing.T) {
	t.Parallel()
	if !IsPublicAddr(netip.MustParseAddr("8.8.8.8")) {
		t.Error("IsPublicAddr(8.8.8.8) = false, want true")
	}
	if IsPublicAddr(netip.MustParseAddr("127.0.0.1")) {
		t.Error("IsPublicAddr(127.0.0.1) = true, want false")
	}
	if IsPublicAddr(netip.MustParseAddr("192.0.2.1")) {
		t.Error("IsPublicAddr(192.0.2.1) = true, want false (TEST-NET-1)")
	}
	if IsPublicAddr(netip.MustParseAddr("2001:db8::1")) {
		t.Error("IsPublicAddr(2001:db8::1) = true, want false (documentation)")
	}
}

func TestIsPublicAddr_invalid_zero_value(t *testing.T) {
	t.Parallel()
	if IsPublicAddr(netip.Addr{}) {
		t.Error("IsPublicAddr(netip.Addr{}) = true, want false for invalid zero address")
	}
}

// TestIsPublicAddr_blocked_ranges_comprehensive sweeps a representative IP from
// every non-routable IPv4/IPv6 range the library blocks. Folds the red-team
// "all blocked ranges" round into the canonical isPublicAddr table.
func TestIsPublicAddr_blocked_ranges_comprehensive(t *testing.T) {
	t.Parallel()
	blocked := []string{
		// RFC 1918 private
		"10.0.0.1", "172.16.0.1", "192.168.0.1",
		// CGNAT (RFC 6598)
		"100.64.0.1", "100.127.255.254",
		// Loopback
		"127.0.0.1", "127.255.255.255",
		// Link-local
		"169.254.1.1", "fe80::1",
		// This host (RFC 6890 0.0.0.0/8)
		"0.0.0.1", "0.255.255.255",
		// Reserved Class E (240.0.0.0/4)
		"240.0.0.1", "255.255.255.254",
		// Broadcast
		"255.255.255.255",
		// IETF protocol assignments
		"192.0.0.1",
		// TEST-NETs (RFC 5737)
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		// Benchmarking (RFC 2544)
		"198.18.0.1", "198.19.255.254",
		// 6to4 relay anycast (RFC 7526)
		"192.88.99.1",
		// IPv6 discard-only (RFC 6666)
		"100::1",
		// IPv6 benchmarking (RFC 5180)
		"2001:2::1",
		// Documentation (RFC 3849 + RFC 9637)
		"2001:db8::1", "3fff::1",
		// SRv6 SIDs (RFC 9602)
		"5f00::1",
		// Multicast
		"224.0.0.1", "ff02::1",
		// Unspecified
		"0.0.0.0", "::",
		// IPv6 loopback
		"::1",
		// IPv6 private (ULA)
		"fd00::1", "fc00::1",
	}
	for _, ip := range blocked {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("isPublicAddr(%s) = true, want false (blocked range)", ip)
		}
	}
}

// --- IPv4 non-routable ranges (RFC 5737, RFC 2544, RFC 5736), boundaries ---

func TestIsPublicAddr_IPv4_NonRoutable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"IETF Protocol Assignments 192.0.0.1", "192.0.0.1"},
		{"IETF Protocol Assignments 192.0.0.254", "192.0.0.254"},
		{"TEST-NET-1 192.0.2.1", "192.0.2.1"},
		{"TEST-NET-1 192.0.2.255", "192.0.2.255"},
		{"TEST-NET-2 198.51.100.1", "198.51.100.1"},
		{"TEST-NET-2 198.51.100.255", "198.51.100.255"},
		{"TEST-NET-3 203.0.113.1", "203.0.113.1"},
		{"TEST-NET-3 203.0.113.255", "203.0.113.255"},
		{"Benchmarking 198.18.0.1", "198.18.0.1"},
		{"Benchmarking 198.19.255.255", "198.19.255.255"},
		{"6to4 relay 192.88.99.1", "192.88.99.1"},
		{"6to4 relay 192.88.99.255", "192.88.99.255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false", addr)
			}
		})
	}
}

func TestIsPublicAddr_IPv6_NonRoutable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"Discard 100::1", "100::1"},
		{"Discard 100::ffff:ffff:ffff:ffff", "100::ffff:ffff:ffff:ffff"},
		{"Benchmarking 2001:2::1", "2001:2::1"},
		{"Benchmarking 2001:2:0:ffff::", "2001:2:0:ffff::"},
		{"Documentation 2001:db8::1", "2001:db8::1"},
		{"Documentation 2001:db8:ffff:ffff::", "2001:db8:ffff:ffff::"},
		{"Documentation new 3fff::1", "3fff::1"},
		{"Documentation new 3fff:f:ffff::", "3fff:f:ffff::"},
		{"SRv6 SIDs 5f00::1", "5f00::1"},
		{"SRv6 SIDs 5f00:ffff::", "5f00:ffff::"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if isPublicAddr(addr) {
				t.Errorf("isPublicAddr(%v) = true, want false", addr)
			}
		})
	}
}

// --- IPv4-mapped IPv6 (::ffff:x) must classify by the embedded IPv4 ---

// TestIsPublicAddr_mapped_nonpublic checks IPv4-mapped IPv6 forms of non-public
// addresses are rejected even when called directly (without prior Unmap by the
// caller). Folds the mapped-CGNAT regression and the red-team double-mapped
// round; sharedAddrSpace.Contains once missed ::ffff:100.64.0.1 because the
// prefix is IPv4 and the address was IPv6.
func TestIsPublicAddr_mapped_nonpublic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
	}{
		{"mapped CGNAT", "::ffff:100.64.0.1"},
		{"mapped CGNAT high boundary", "::ffff:100.127.255.255"},
		{"mapped CGNAT low boundary", "::ffff:100.127.255.254"},
		{"mapped CGNAT mid", "::ffff:100.100.100.100"},
		{"mapped loopback", "::ffff:127.0.0.1"},
		{"mapped private 10", "::ffff:10.0.0.1"},
		{"mapped private 172.16", "::ffff:172.16.0.1"},
		{"mapped private 192.168", "::ffff:192.168.1.1"},
		{"mapped link-local", "::ffff:169.254.1.1"},
		{"mapped this-host", "::ffff:0.1.2.3"},
		{"mapped this-host low boundary", "::ffff:0.0.0.1"},
		{"mapped reserved 240", "::ffff:240.0.0.1"},
		{"mapped TEST-NET-1", "::ffff:192.0.2.1"},
		{"mapped benchmarking", "::ffff:198.18.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if IsPublicAddr(addr) {
				t.Errorf("IsPublicAddr(%v) = true, want false", addr)
			}
		})
	}
}

func TestIsPublicAddr_mapped_public_allowed(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("::ffff:8.8.8.8")
	if !IsPublicAddr(addr) {
		t.Errorf("IsPublicAddr(%v) = false, want true", addr)
	}
}

// --- IPv6 transition mechanisms: embedded IPv4 is extracted and re-validated ---

// TestIsPublicAddr_Teredo covers RFC 4380 Teredo (2001:0000::/32): the client
// IPv4 (bytes 12-15, bitwise-inverted) and server IPv4 (bytes 4-7) are both
// extracted and re-validated, so a private client OR server is rejected. Folds
// every red-team Teredo round into one table.
func TestIsPublicAddr_Teredo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"client 127.0.0.1", "2001:0000:4136:e378:8000:63bf:80ff:fffe", false},
		{"client 10.0.0.1", "2001:0000:4136:e378:8000:63bf:f5ff:fffe", false},
		{"client 169.254.169.254 metadata", "2001:0000:4136:e378:8000:63bf:5601:5601", false},
		{"client 192.168.1.1", "2001:0000:4136:e378:8000:63bf:3f57:fefe", false},
		{"client 100.64.0.1 CGNAT", "2001:0000:4136:e378:8000:63bf:9bbf:fffe", false},
		{"server 10.0.0.1", "2001:0000:0a00:0001:8000:63bf:f7f7:f7f7", false},
		{"server 192.168.1.1", "2001:0000:c0a8:0101:8000:63bf:f7f7:f7f7", false},
		{"server 127.0.0.1", "2001:0000:7f00:0001:8000:63bf:f7f7:f7f7", false},
		{"zero server and client", "2001:0000:0000:0000:0000:0000:ffff:ffff", false},
		{"public client 8.8.8.8 server 8.8.4.4", "2001:0000:0808:0404:8000:63bf:f7f7:f7f7", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if got := isPublicAddr(addr); got != tc.want {
				t.Errorf("isPublicAddr(%v) = %v, want %v (Teredo %s)", addr, got, tc.want, tc.name)
			}
		})
	}
}

// TestIsPublicAddr_NAT64 covers RFC 6052 NAT64 well-known (64:ff9b::/96): the
// embedded IPv4 is the last 32 bits (bytes 12-15) and is re-validated.
func TestIsPublicAddr_NAT64(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"127.0.0.1", "64:ff9b::7f00:1", false},
		{"10.0.0.1", "64:ff9b::a00:1", false},
		{"192.168.1.1", "64:ff9b::c0a8:101", false},
		{"172.16.0.1", "64:ff9b::ac10:1", false},
		{"169.254.169.254 metadata", "64:ff9b::a9fe:a9fe", false},
		{"169.254.1.1", "64:ff9b::a9fe:101", false},
		{"100.64.0.1 CGNAT", "64:ff9b::6440:1", false},
		{"100.127.255.254 CGNAT", "64:ff9b::647f:fffe", false},
		{"public 8.8.8.8", "64:ff9b::808:808", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if got := isPublicAddr(addr); got != tc.want {
				t.Errorf("isPublicAddr(%v) = %v, want %v (NAT64 %s)", addr, got, tc.want, tc.name)
			}
		})
	}
}

// TestIsPublicAddr_6to4 covers RFC 3056 6to4 (2002::/16): the embedded IPv4 is
// bytes 2-5 and is re-validated.
func TestIsPublicAddr_6to4(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"127.0.0.1", "2002:7f00:0001::", false},
		{"192.168.1.1", "2002:c0a8:0101::", false},
		{"10.0.0.1", "2002:0a00:0001::", false},
		{"172.16.0.1", "2002:ac10:0001::", false},
		{"169.254.169.254 metadata", "2002:a9fe:a9fe::", false},
		{"169.254.1.1", "2002:a9fe:0101::", false},
		{"100.64.0.1 CGNAT", "2002:6440:0001::", false},
		{"100.64.0.0 CGNAT", "2002:6440:0000::", false},
		{"100.127.255.254 CGNAT", "2002:647f:fffe::", false},
		{"192.0.2.1 TEST-NET-1", "2002:c000:0201::", false},
		{"198.18.0.1 benchmarking", "2002:c612:0001::", false},
		{"public 8.8.8.8", "2002:0808:0808::", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.ip)
			if got := isPublicAddr(addr); got != tc.want {
				t.Errorf("isPublicAddr(%v) = %v, want %v (6to4 %s)", addr, got, tc.want, tc.name)
			}
		})
	}
}

// TestIsPublicAddr_IPv4Compatible covers the deprecated RFC 4291 §2.5.5.1
// IPv4-compatible form (::/96): the embedded IPv4 is bytes 12-15.
func TestIsPublicAddr_IPv4Compatible(t *testing.T) {
	t.Parallel()
	blocked := []string{
		"::127.0.0.1",
		"::10.0.0.1",
		"::192.168.1.1",
		"::169.254.169.254",
		"::100.64.0.1",
	}
	for _, ip := range blocked {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("isPublicAddr(%s) = true, want false (IPv4-compatible embedding non-public)", ip)
		}
	}
}

// TestIsPublicAddr_NAT64Local_blocked_outright covers RFC 8215 local-use NAT64
// (64:ff9b:1::/48): its /48 RFC 6052 embedding offset differs from the
// well-known /96, so the whole range is blocked outright rather than
// IPv4-extracted — even a public embedded payload stays blocked.
func TestIsPublicAddr_NAT64Local_blocked_outright(t *testing.T) {
	t.Parallel()
	blocked := []string{
		"64:ff9b:1::7f00:1",       // 127.0.0.1
		"64:ff9b:1::c0a8:101",     // 192.168.1.1
		"64:ff9b:1::808:808",      // 8.8.8.8 (public payload, still blocked)
		"64:ff9b:1::1",            // low host
		"64:ff9b:1:ffff::1",       // within /48
		"64:ff9b:1:abcd::8.8.8.8", // dotted public payload, still blocked
	}
	for _, ip := range blocked {
		addr := netip.MustParseAddr(ip)
		if isPublicAddr(addr) {
			t.Errorf("isPublicAddr(%s) = true, want false (NAT64 local blocked outright)", ip)
		}
	}
}

// --- ValidateURL of non-routable IP literals (end-to-end through the URL path) ---

func TestValidateURL_IPv4_NonRoutable(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://192.0.2.1/file",
		"https://198.51.100.1/file",
		"https://203.0.113.1/file",
		"https://198.18.0.1/file",
		"https://192.88.99.1/file",
		"https://192.0.0.1/file",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURL(u); err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error", u)
			}
		})
	}
}

func TestValidateURL_IPv6_NonRoutable(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://[100::1]/file",
		"https://[2001:2::1]/file",
		"https://[2001:db8::1]/file",
		"https://[3fff::1]/file",
		"https://[5f00::1]/file",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURL(u); err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error", u)
			}
		})
	}
}

func TestValidateURL_Teredo_embedded_loopback(t *testing.T) {
	t.Parallel()
	err := ValidateURL("https://[2001:0000:4136:e378:8000:63bf:80ff:fffe]/file")
	if err == nil {
		t.Error("ValidateURL() = nil, want error for Teredo embedding 127.0.0.1")
	}
}

func TestValidateURL_NAT64Local_embedded_loopback(t *testing.T) {
	t.Parallel()
	err := ValidateURL("https://[64:ff9b:1::7f00:1]/file")
	if err == nil {
		t.Error("ValidateURL() = nil, want error for NAT64 local embedding 127.0.0.1")
	}
}
