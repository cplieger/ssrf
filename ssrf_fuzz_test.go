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

		// (b) non-https schemes must always be rejected
		if u, parseErr := url.Parse(raw); parseErr == nil && u.Scheme != "" {
			scheme := strings.ToLower(u.Scheme)
			if scheme != "https" && err == nil {
				t.Fatalf("non-https scheme %q was accepted: %s", scheme, raw)
			}
		}

		// (a) if ValidateURL accepts an IP-literal URL, IsPublicAddr must agree
		if err == nil {
			if u, parseErr := url.Parse(raw); parseErr == nil {
				host := u.Hostname()
				if addr, addrErr := netip.ParseAddr(host); addrErr == nil {
					if !IsPublicAddr(addr) {
						t.Fatalf("ValidateURL accepted non-public IP literal: %s", raw)
					}
				}
			}
		}

		// (c) known-bad hosts must always be rejected
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

func FuzzIsPublicAddr(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{10, 0, 0, 1})
	f.Add([]byte{192, 168, 1, 1})
	f.Add([]byte{172, 16, 0, 1})
	f.Add([]byte{8, 8, 8, 8})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // ::1
	f.Add([]byte{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
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
		mustBeFalse := addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
		if mustBeFalse && result {
			t.Fatalf("IsPublicAddr returned true for non-public addr %s", addr)
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
	f.Fuzz(func(t *testing.T, host string) {
		hostOk := IsPublicHost(host)
		if !hostOk {
			// If IsPublicHost rejects, ValidateURL for https://<host> must also reject
			testURL := "https://" + host + "/"
			if err := ValidateURL(testURL); err == nil {
				t.Fatalf("IsPublicHost rejected %q but ValidateURL accepted %q", host, testURL)
			}
		}
	})
}
