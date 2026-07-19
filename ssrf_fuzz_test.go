package ssrf

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func FuzzValidateURL(f *testing.F) {
	f.Add("https://example.com/path")
	f.Add("http://localhost")
	f.Add("https://127.0.0.1")
	f.Add("https://[::1]/path")
	f.Add("")
	f.Add("not-a-url")
	f.Add("https://10.0.0.1/internal")
	f.Add("https://192.168.1.1")
	f.Add("https://172.16.0.1")
	f.Add("https://[fc00::1]")
	f.Add("ftp://example.com")
	f.Fuzz(func(t *testing.T, raw string) {
		err := ValidateURL(raw)

		if u, parseErr := url.Parse(raw); parseErr == nil && u.Scheme != "" {
			scheme := strings.ToLower(u.Scheme)
			if scheme != "https" && err == nil {
				t.Fatalf("non-https scheme %q was accepted: %s", scheme, raw)
			}
		}

		if err == nil {
			if u, parseErr := url.Parse(raw); parseErr == nil {
				host := strings.TrimRight(u.Hostname(), ".")
				if addr, addrErr := netip.ParseAddr(host); addrErr == nil {
					// Independent oracle: assert against re-derived blocked ranges and
					// stdlib classifiers, NOT against IsPublicAddr (same code path).
					canonical := addr.Unmap()
					if canonical.IsLoopback() || canonical.IsPrivate() ||
						canonical.IsLinkLocalUnicast() || canonical.IsMulticast() ||
						canonical.IsUnspecified() {
						t.Fatalf("ValidateURL accepted stdlib-classified non-public IP %s: %s", addr, raw)
					}
					for _, br := range independentBlockedRanges {
						if br.prefix.Contains(canonical) {
							t.Fatalf("ValidateURL accepted IP %s in blocked range %s (%s): %s", addr, br.prefix, br.name, raw)
						}
					}
				}
			}
		}

		knownBad := []string{
			"localhost", "127.0.0.1", "10.0.0.1", "10.255.255.255",
			"192.168.0.1", "192.168.255.255", "172.16.0.1", "172.31.255.255",
			"[::1]", "[fc00::1]",
		}
		for _, bad := range knownBad {
			if strings.Contains(raw, "://"+bad+"/") || strings.HasSuffix(raw, "://"+bad) || strings.Contains(raw, "://"+bad+":") {
				if u, parseErr := url.Parse(raw); parseErr == nil && strings.ToLower(u.Scheme) == "https" {
					host := u.Hostname()
					if strings.EqualFold(host, strings.Trim(bad, "[]")) && err == nil {
						t.Fatalf("known-bad host %q was accepted: %s", bad, raw)
					}
				}
			}
		}
	})
}

// blockedRange is an independent oracle for ranges IsPublicAddr must reject.
type blockedRange struct {
	prefix netip.Prefix
	name   string
}

var independentBlockedRanges = []blockedRange{
	// CGNAT
	{netip.MustParsePrefix("100.64.0.0/10"), "CGNAT"},
	// Class E
	{netip.MustParsePrefix("240.0.0.0/4"), "ClassE"},
	// Documentation
	{netip.MustParsePrefix("192.0.2.0/24"), "TEST-NET-1"},
	{netip.MustParsePrefix("198.51.100.0/24"), "TEST-NET-2"},
	{netip.MustParsePrefix("203.0.113.0/24"), "TEST-NET-3"},
	// Benchmarking
	{netip.MustParsePrefix("198.18.0.0/15"), "Benchmarking4"},
	// This host
	{netip.MustParsePrefix("0.0.0.0/8"), "ThisHost"},
	// IETF protocol assignments
	{netip.MustParsePrefix("192.0.0.0/24"), "IETFProto"},
	// Loopback
	{netip.MustParsePrefix("127.0.0.0/8"), "Loopback4"},
	// Private
	{netip.MustParsePrefix("10.0.0.0/8"), "Private10"},
	{netip.MustParsePrefix("172.16.0.0/12"), "Private172"},
	{netip.MustParsePrefix("192.168.0.0/16"), "Private192"},
	// Link-local
	{netip.MustParsePrefix("169.254.0.0/16"), "LinkLocal4"},
	// IPv6 non-routable
	{netip.MustParsePrefix("::1/128"), "Loopback6"},
	{netip.MustParsePrefix("fc00::/7"), "ULA"},
	{netip.MustParsePrefix("fe80::/10"), "LinkLocal6"},
	{netip.MustParsePrefix("100::/64"), "Discard"},
	{netip.MustParsePrefix("2001:2::/48"), "Benchmarking6"},
	{netip.MustParsePrefix("2001:db8::/32"), "Documentation6"},
	{netip.MustParsePrefix("3fff::/20"), "Documentation6New"},
	{netip.MustParsePrefix("5f00::/16"), "SRv6SIDs"},
	// NAT64 local (RFC 8215)
	{netip.MustParsePrefix("64:ff9b:1::/48"), "NAT64Local"},
	// 6to4 relay anycast (RFC 7526)
	{netip.MustParsePrefix("192.88.99.0/24"), "SixToFourRelay"},
}

// build6to4 creates a 6to4 address (2002::/16) embedding the given IPv4.
func build6to4(v4 netip.Addr) netip.Addr {
	b4 := v4.As4()
	var b [16]byte
	b[0] = 0x20
	b[1] = 0x02
	b[2] = b4[0]
	b[3] = b4[1]
	b[4] = b4[2]
	b[5] = b4[3]
	return netip.AddrFrom16(b)
}

// buildNAT64 creates a NAT64 well-known address (64:ff9b::/96) embedding the given IPv4.
func buildNAT64(v4 netip.Addr) netip.Addr {
	b4 := v4.As4()
	var b [16]byte
	b[0] = 0x00
	b[1] = 0x64
	b[2] = 0xff
	b[3] = 0x9b
	b[12] = b4[0]
	b[13] = b4[1]
	b[14] = b4[2]
	b[15] = b4[3]
	return netip.AddrFrom16(b)
}

// buildTeredo creates a Teredo address (2001:0000::/32) with the given client IPv4 (XOR inverted).
func buildTeredo(serverV4, clientV4 netip.Addr) netip.Addr {
	s4 := serverV4.As4()
	c4 := clientV4.As4()
	var b [16]byte
	b[0] = 0x20
	b[1] = 0x01
	// server in bytes 4-7
	b[4] = s4[0]
	b[5] = s4[1]
	b[6] = s4[2]
	b[7] = s4[3]
	// client XOR-inverted in bytes 12-15
	b[12] = c4[0] ^ 0xFF
	b[13] = c4[1] ^ 0xFF
	b[14] = c4[2] ^ 0xFF
	b[15] = c4[3] ^ 0xFF
	return netip.AddrFrom16(b)
}

// privateV4Seeds are representative private/non-routable IPv4 addresses.
var privateV4Seeds = []netip.Addr{
	netip.MustParseAddr("10.0.0.1"),
	netip.MustParseAddr("192.168.1.1"),
	netip.MustParseAddr("172.16.0.1"),
	netip.MustParseAddr("127.0.0.1"),
	netip.MustParseAddr("100.64.0.1"),
	netip.MustParseAddr("240.0.0.1"),
	netip.MustParseAddr("192.0.2.1"),
	netip.MustParseAddr("0.0.0.1"),
}

func addr16(a netip.Addr) []byte { b := a.As16(); return b[:] }

func FuzzIsPublicAddr(f *testing.F) {
	// Standard seeds
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{10, 0, 0, 1})
	f.Add([]byte{192, 168, 1, 1})
	f.Add([]byte{172, 16, 0, 1})
	f.Add([]byte{8, 8, 8, 8})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // ::1
	f.Add([]byte{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	// CGNAT seeds
	f.Add([]byte{100, 64, 0, 1})
	f.Add([]byte{100, 127, 255, 254})

	// Class E seeds
	f.Add([]byte{240, 0, 0, 1})
	f.Add([]byte{255, 255, 255, 254})

	// Documentation range seeds
	f.Add([]byte{192, 0, 2, 1})
	f.Add([]byte{198, 51, 100, 1})
	f.Add([]byte{203, 0, 113, 1})

	// Benchmarking seeds
	f.Add([]byte{198, 18, 0, 1})
	f.Add([]byte{198, 19, 255, 254})

	// This host
	f.Add([]byte{0, 0, 0, 1})
	f.Add([]byte{0, 255, 255, 254})

	// IETF protocol
	f.Add([]byte{192, 0, 0, 1})

	// 6to4 wrapping private IPv4 (2002:c0a8:0101::)
	for _, priv := range privateV4Seeds {
		f.Add(addr16(build6to4(priv)))
	}
	// NAT64 with private payload
	for _, priv := range privateV4Seeds {
		f.Add(addr16(buildNAT64(priv)))
	}
	// Teredo with private client
	pub := netip.MustParseAddr("8.8.8.8")
	for _, priv := range privateV4Seeds {
		f.Add(addr16(buildTeredo(pub, priv)))
	}
	// Teredo with private server
	for _, priv := range privateV4Seeds {
		f.Add(addr16(buildTeredo(priv, pub)))
	}

	// IPv6 non-routable seeds
	f.Add(addr16(netip.MustParseAddr("100::1")))                 // discard
	f.Add(addr16(netip.MustParseAddr("2001:2::1")))              // benchmarking6
	f.Add(addr16(netip.MustParseAddr("2001:db8::1")))            // documentation
	f.Add(addr16(netip.MustParseAddr("3fff::1")))                // doc new
	f.Add(addr16(netip.MustParseAddr("5f00::1")))                // SRv6
	f.Add(addr16(netip.MustParseAddr("64:ff9b:1::192.168.1.1"))) // nat64 local
	f.Add(addr16(netip.MustParseAddr("64:ff9b:1::a00:1")))       // nat64Local with 10.0.0.1
	f.Add(addr16(netip.MustParseAddr("::a00:1")))                // ipv4Compat with 10.0.0.1
	f.Add([]byte{192, 88, 99, 1})                                // sixToFourRelay anycast
	f.Add(addr16(netip.MustParseAddr("64:ff9b:1::c0a8:101")))    // nat64Local with 192.168.1.1

	f.Fuzz(func(t *testing.T, data []byte) {
		var addr netip.Addr
		switch len(data) {
		case 4:
			addr = netip.AddrFrom4([4]byte(data))
		case 16:
			addr = netip.AddrFrom16([16]byte(data))
		default:
			return
		}

		result := IsPublicAddr(addr)

		// Original stdlib oracle
		mustBeFalse := addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
		if mustBeFalse && result {
			t.Fatalf("IsPublicAddr returned true for stdlib-classified non-public addr %s", addr)
		}

		// INDEPENDENT oracle: check against manually-defined blocked ranges
		canonical := addr.Unmap()
		for _, br := range independentBlockedRanges {
			if br.prefix.Contains(canonical) && result {
				t.Fatalf("IsPublicAddr returned true for %s which is in blocked range %s (%s)", addr, br.prefix, br.name)
			}
		}

		// INDEPENDENT oracle: 6to4 wrapping private IPv4
		if sixToFour.Contains(canonical) {
			b := canonical.As16()
			embedded := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
			for _, br := range independentBlockedRanges {
				if br.prefix.Addr().Is4() && br.prefix.Contains(embedded) && result {
					t.Fatalf("IsPublicAddr returned true for 6to4 %s embedding private %s (%s)", addr, embedded, br.name)
				}
			}
		}

		// INDEPENDENT oracle: NAT64 well-known wrapping private IPv4
		if nat64Wellknown.Contains(canonical) {
			b := canonical.As16()
			embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
			for _, br := range independentBlockedRanges {
				if br.prefix.Addr().Is4() && br.prefix.Contains(embedded) && result {
					t.Fatalf("IsPublicAddr returned true for NAT64 %s embedding private %s (%s)", addr, embedded, br.name)
				}
			}
		}

		// INDEPENDENT oracle: Teredo client IP
		if teredoPrefix.Contains(canonical) {
			b := canonical.As16()
			clientIP := netip.AddrFrom4([4]byte{b[12] ^ 0xFF, b[13] ^ 0xFF, b[14] ^ 0xFF, b[15] ^ 0xFF})
			for _, br := range independentBlockedRanges {
				if br.prefix.Addr().Is4() && br.prefix.Contains(clientIP) && result {
					t.Fatalf("IsPublicAddr returned true for Teredo %s with private client %s (%s)", addr, clientIP, br.name)
				}
			}
			serverIP := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
			for _, br := range independentBlockedRanges {
				if br.prefix.Addr().Is4() && br.prefix.Contains(serverIP) && result {
					t.Fatalf("IsPublicAddr returned true for Teredo %s with private server %s (%s)", addr, serverIP, br.name)
				}
			}
		}

		// INDEPENDENT oracle: IPv4-compatible addresses (::/96 embedding)
		if ipv4Compat.Contains(canonical) && !canonical.IsUnspecified() {
			b := canonical.As16()
			// First 12 bytes must be zero for IPv4-compatible
			allZero := true
			for i := range 12 {
				if b[i] != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
				for _, br := range independentBlockedRanges {
					if br.prefix.Addr().Is4() && br.prefix.Contains(embedded) && result {
						t.Fatalf("IsPublicAddr returned true for IPv4-compatible %s embedding private %s (%s)", addr, embedded, br.name)
					}
				}
			}
		}
	})
}

func FuzzIsPublicHost(f *testing.F) {
	f.Add("localhost")
	f.Add("127.0.0.1")
	f.Add("example.com")
	f.Add("10.0.0.1")
	f.Add("::1")
	f.Add("internal")
	// Non-canonical IPv4 encodings (looksLikeNumericIPv4 gate) — the fuzz oracle in
	// FuzzValidateURL/FuzzValidateURLWithSchemes deliberately skips these because
	// netip.ParseAddr rejects them, so FuzzIsPublicHost's consistency oracle is the
	// only fuzz coverage of this bypass class. Seed it so the shallow 2-min weekly
	// run starts from these inputs instead of re-discovering them.
	f.Add("0177.0.0.1")       // dotted-octal loopback
	f.Add("0x7f.0.0.1")       // dotted-hex loopback
	f.Add("127.1")            // short-form loopback
	f.Add("192.168.257")      // oversized inet_aton private
	f.Add("0x7f.0x0.0x0.0x1") // fully dotted-hex loopback
	// IPv6 transition-mechanism wrappers embedding private IPv4.
	f.Add("2002:c0a8:0101::") // 6to4 embedding 192.168.1.1
	f.Add("64:ff9b::7f00:1")  // NAT64 well-known embedding 127.0.0.1
	f.Add("::127.0.0.1")      // deprecated IPv4-compatible embedding loopback
	// Bracketed URL-authority literals (hostValidationError strips one bracket pair).
	f.Add("[::ffff:192.168.1.1]")   // bracketed IPv4-mapped private
	f.Add("[2606:4700:4700::1111]") // bracketed public IPv6 (must stay public)
	// CGNAT boundary + public canonical anchors.
	f.Add("100.64.0.1")     // CGNAT
	f.Add("100.63.255.255") // just below CGNAT (public)
	f.Add("8.8.8.8")        // public canonical IPv4
	f.Add("2606:4700::1")   // public canonical IPv6
	f.Fuzz(func(t *testing.T, host string) {
		hostOk := IsPublicHost(host)
		if !hostOk {
			testURL := "https://" + host + "/"
			// The oracle only holds when the URL actually carries host as its
			// authority. Raw fuzz input containing URL delimiters ('#', '?',
			// '/', '@', ...) re-parses into a DIFFERENT (often empty) host —
			// e.g. "a.A# 0" puts "# 0" in the fragment — so IsPublicHost and
			// ValidateURL would be judging different hosts and a mismatch is
			// not a bypass (fuzz finding 453ea43caa7c18fc).
			if u, err := url.Parse(testURL); err != nil || u.Hostname() != host {
				return
			}
			if err := ValidateURL(testURL); err == nil {
				t.Fatalf("IsPublicHost rejected %q but ValidateURL accepted %q", host, testURL)
			}
		}
	})
}

func FuzzSafeControl(f *testing.F) {
	f.Add("tcp4", "8.8.8.8:443")
	f.Add("tcp6", "[2607:f8b0:4004:800::200e]:443")
	f.Add("tcp", "192.168.1.1:80")
	f.Add("udp", "8.8.8.8:53")
	f.Add("unix", "/var/run/sock")
	f.Add("tcp4", "10.0.0.1:443")
	f.Add("tcp4", "127.0.0.1:443")
	f.Add("tcp4", "100.64.0.1:443")
	f.Add("tcp4", "240.0.0.1:443")
	f.Add("tcp6", "[2002:c0a8:0101::]:443")
	f.Add("tcp6", "[64:ff9b::192.168.1.1]:443")

	f.Fuzz(func(t *testing.T, network, address string) {
		ctrl := safeControl(isPublicAddr, nil)
		err := ctrl(network, address, nil)

		// Must never panic (implicit by reaching here)

		// Non-tcp networks must error
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			if err == nil {
				t.Fatalf("safeControl accepted non-tcp network %q", network)
			}
			return
		}

		// For tcp with private IP, must error
		if err == nil {
			host := extractHost(address)
			if host == "" {
				return
			}
			if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
				canonical := addr.Unmap()
				for _, br := range independentBlockedRanges {
					if br.prefix.Contains(canonical) {
						t.Fatalf("safeControl accepted tcp connection to %s in blocked range %s (%s)", address, br.prefix, br.name)
					}
				}
			}
		}
	})
}

// extractHost extracts the host part from a host:port string.
func extractHost(address string) string {
	if len(address) == 0 {
		return ""
	}
	if address[0] == '[' {
		end := strings.IndexByte(address, ']')
		if end < 0 {
			return ""
		}
		return address[1:end]
	}
	colon := strings.LastIndexByte(address, ':')
	if colon < 0 {
		return address
	}
	return address[:colon]
}

func FuzzValidateURLWithSchemes(f *testing.F) {
	f.Add("https://example.com", "https")
	f.Add("http://example.com", "http,https")
	f.Add("ftp://evil.com", "https")
	f.Add("https://10.0.0.1", "https,http")
	f.Add("http://192.168.1.1/path", "http")
	f.Add("gopher://localhost", "gopher")
	f.Add("https://[2002:c0a8:0101::]/x", "https")

	f.Fuzz(func(t *testing.T, rawURL, schemesCSV string) {
		parts := strings.Split(schemesCSV, ",")
		schemes := make(map[string]struct{}, len(parts))
		for _, s := range parts {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				schemes[s] = struct{}{}
			}
		}
		if len(schemes) == 0 {
			return
		}

		err := validateURLWithSchemes(rawURL, schemes)

		// If accepted, scheme must be in allowed list AND host must be public
		if err == nil {
			u, parseErr := url.Parse(rawURL)
			if parseErr != nil {
				t.Fatalf("validateURLWithSchemes accepted unparseable URL: %s", rawURL)
			}
			scheme := strings.ToLower(u.Scheme)
			if _, ok := schemes[scheme]; !ok {
				t.Fatalf("validateURLWithSchemes accepted scheme %q not in allowed set %v", scheme, schemes)
			}
			host := strings.TrimRight(u.Hostname(), ".")
			if addr, addrErr := netip.ParseAddr(host); addrErr == nil {
				// Independent oracle (see FuzzValidateURL): assert against re-derived
				// blocked ranges + stdlib classifiers, not against IsPublicAddr.
				canonical := addr.Unmap()
				if canonical.IsLoopback() || canonical.IsPrivate() ||
					canonical.IsLinkLocalUnicast() || canonical.IsMulticast() ||
					canonical.IsUnspecified() {
					t.Fatalf("validateURLWithSchemes accepted stdlib-classified non-public IP %s in URL %s", addr, rawURL)
				}
				for _, br := range independentBlockedRanges {
					if br.prefix.Contains(canonical) {
						t.Fatalf("validateURLWithSchemes accepted IP %s in blocked range %s (%s) in URL %s", addr, br.prefix, br.name, rawURL)
					}
				}
			}
		}
	})
}
