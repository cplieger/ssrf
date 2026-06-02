package ssrf

import (
	"net/netip"
	"testing"
)

// --- IsPublicAddr benchmarks: the core IP classification hot path ---

func BenchmarkIsPublicAddr_PublicIPv4(b *testing.B) {
	addr := netip.MustParseAddr("8.8.8.8")
	for b.Loop() {
		isPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_PrivateIPv4(b *testing.B) {
	addr := netip.MustParseAddr("10.0.0.1")
	for b.Loop() {
		isPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_Loopback(b *testing.B) {
	addr := netip.MustParseAddr("127.0.0.1")
	for b.Loop() {
		isPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_IPv4Mapped(b *testing.B) {
	addr := netip.MustParseAddr("::ffff:192.168.1.1")
	for b.Loop() {
		isPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_CGNAT(b *testing.B) {
	addr := netip.MustParseAddr("100.64.0.1")
	for b.Loop() {
		isPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_PublicIPv6(b *testing.B) {
	addr := netip.MustParseAddr("2607:f8b0:4004:800::200e")
	for b.Loop() {
		isPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_6to4Embed(b *testing.B) {
	addr := netip.MustParseAddr("2002:c000:0204::1") // embeds 192.0.2.4 (TEST-NET-1)
	for b.Loop() {
		isPublicAddr(addr)
	}
}

// --- validateHost benchmarks: hostname/IP classification ---

func BenchmarkValidateHost_PublicIP(b *testing.B) {
	for b.Loop() {
		validateHost("93.184.216.34")
	}
}

func BenchmarkValidateHost_PrivateIP(b *testing.B) {
	for b.Loop() {
		validateHost("192.168.1.1")
	}
}

func BenchmarkValidateHost_Localhost(b *testing.B) {
	for b.Loop() {
		validateHost("localhost")
	}
}

func BenchmarkValidateHost_DottedHostname(b *testing.B) {
	for b.Loop() {
		validateHost("api.example.com")
	}
}

func BenchmarkValidateHost_BareHostname(b *testing.B) {
	for b.Loop() {
		validateHost("internal")
	}
}

// --- ValidateURL benchmarks: the full public Check path ---

func BenchmarkValidateURL_PublicHTTPS(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://93.184.216.34/path?q=1")
	}
}

func BenchmarkValidateURL_PrivateBlocked(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://10.0.0.1/internal")
	}
}

func BenchmarkValidateURL_LoopbackBlocked(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://127.0.0.1/")
	}
}

func BenchmarkValidateURL_IPv4MappedBlocked(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://[::ffff:169.254.169.254]/metadata")
	}
}

func BenchmarkValidateURL_BadScheme(b *testing.B) {
	for b.Loop() {
		ValidateURL("http://example.com/")
	}
}
