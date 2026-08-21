package ssrf

import (
	"strings"
	"testing"
)

// The canonical-host gate closed a family of bypasses that all reached a private
// address through STANDARD IDNA processing. Each input below was accepted by
// IsPublicHost before the gate existed, and each maps to a bare private literal
// (or is rejected outright) under x/net/idna's Lookup profile.
//
// The mechanism is worth stating once, because it is the reason an allowlist is
// the only durable answer here. UTS-46 either DELETES a format character or MAPS
// it to an ASCII digit, so a host that is not a private literal on its face
// becomes one at the resolver. Enumerating those runes would never finish;
// admitting only ASCII letters, digits, hyphen and underscore refuses all of
// them and refuses the next such family without an edit.
//
// Measured on go1.27.0 with x/net v0.46.0. The comment after each case is what
// idna.Lookup.ToASCII returns for it.
func TestCanonicalHostGate_refusesIDNAReachablePrivateHosts(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		// Format characters UTS-46 deletes: these map to the bare literal.
		"zwsp":                   "127.0.0.1\u200b",       // "127.0.0.1"
		"soft hyphen":            "127.0.0.1\u00ad",       // "127.0.0.1"
		"word joiner":            "127.0.0.1\u2060",       // "127.0.0.1"
		"bom":                    "127.0.0.1\ufeff",       // "127.0.0.1"
		"mongolian fvs":          "127.0.0.1\u180b",       // "127.0.0.1"
		"zwsp on cloud metadata": "169.254.169.254\u200b", // "169.254.169.254"

		// Format characters UTS-46 rejects rather than deletes. Still refused
		// here: a validator must not accept what its consumer's resolver will
		// not accept either, and the two ZW joiners are only rejected because
		// the Lookup profile happens to set CheckJoiners.
		"zwnj": "127.0.0.1\u200c",
		"zwj":  "127.0.0.1\u200d",
		"rlo":  "127.0.0.1\u202e",
		"alm":  "10.0.0.1\u061c",

		// Characters UTS-46 MAPS to ASCII digits and dots. WHATWG names this
		// class IPv4-non-ASCII-input.
		"fullwidth digits":                "\uff11\uff12\uff17.0.0.1",       // "127.0.0.1"
		"fullwidth digits on metadata":    "\uff11\uff16\uff19.254.169.254", // "169.254.169.254"
		"circled digits":                  "\u2460.\u2461.\u2462.\u2463",    // "1.2.3.4"
		"ideographic full stop":           "127\u30020\u30020\u30021",       // "127.0.0.1"
		"fullwidth full stop":             "127\uff0e0\uff0e0\uff0e1",       // "127.0.0.1"
		"fullwidth digits plus a deleted": "\uff11\uff10.0.0.1\u200b",       // "10.0.0.1"
	}
	for name, host := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if IsPublicHost(host) {
				t.Errorf("IsPublicHost(%q) = true, want false: this host reaches a "+
					"private address through IDNA processing", host)
			}
			if err := ValidateURL("https://" + host + "/x"); err == nil {
				t.Errorf("ValidateURL(https://%q/x) = nil, want an error", host)
			}
		})
	}
}

// A zone identifier scopes an address to one interface, so it is meaningless on
// a global address and cannot be dialed as written. Two mechanisms reach the
// refusal and both are pinned, because only one of them is the zone check:
// netip.ParseAddr accepts a zone on IPv6, so the v6 forms are refused inside the
// IP branch, while the v4 forms fail to parse and are refused by the gate for
// carrying a '%'.
//
// The loopback and private v4 cases are the sharp ones. Before the fix,
// IsPublicHost("127.0.0.1%eth0") returned true.
func TestCanonicalHostGate_refusesZoneIdentifiers(t *testing.T) {
	t.Parallel()
	hosts := []string{
		"2606:4700::1111%eth0", // global v6, refused by the zone check
		"fe80::1%eth0",         // link-local v6, refused twice over
		"127.0.0.1%eth0",       // loopback v4, refused by the gate
		"10.0.0.1%eth0",        // private v4, refused by the gate
		"8.8.8.8%eth0",         // public v4, still not a host
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			if IsPublicHost(host) {
				t.Errorf("IsPublicHost(%q) = true, want false: a zone identifier is "+
					"not part of a host", host)
			}
		})
	}
}

// What the gate accepts. This is the half that stops the refusals above from
// being achieved by refusing everything, and it is where a regression would
// show up as a real host that stopped working.
func TestCanonicalHostGate_acceptsRealHosts(t *testing.T) {
	t.Parallel()
	hosts := []string{
		"example.com",
		"api.example.com",
		"cdn.assets.example.co.uk",
		"example.com.",                           // one root label, canonical FQDN syntax
		"EXAMPLE.COM",                            // case is not the gate's business
		"xn--bcher-kva.de",                       // IDN A-label
		"a.xn--p1ai",                             // IDN A-label TLD
		"3com.com",                               // a label may begin with a digit
		"svc.3internal",                          // so may the rightmost one, if not numeric
		"my_service.example.com",                 // underscore: see isHostLabelByte
		"a-b.example.com",                        // interior hyphen
		"93.184.216.34",                          // bare public v4
		"2606:4700:4700::1111",                   // bare public v6
		"::ffff:93.184.216.34",                   // IPv4-mapped public
		strings.Repeat("a.", 125) + "com",        // exactly maxDNSName bytes
		strings.Repeat("d", 63) + ".example.com", // exactly maxDNSLabel bytes
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			if !IsPublicHost(host) {
				verr := hostValidationError(host)
				t.Errorf("IsPublicHost(%q) = false, want true: %v", host, verr)
			}
		})
	}
}

// The structural refusals, each with the Kind a consumer branches on. Grouped
// here rather than folded into the table above because the Kind is the contract:
// KindInvalidHost means "not a host at all", KindNonPublicIP means "a host that
// points somewhere private", and conflating them would give a caller the wrong
// remedy.
func TestCanonicalHostGate_structuralRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		host string
		kind ErrorKind
	}{
		"empty":               {"", KindEmptyHost},
		"root dot alone":      {".", KindEmptyHost},
		"two trailing dots":   {"example.com..", KindInvalidHost},
		"interior double dot": {"example..com", KindInvalidHost},
		"single label":        {"internal", KindBareHostname},
		"leading hyphen":      {"-bad.example.com", KindInvalidHost},
		"trailing hyphen":     {"bad-.example.com", KindInvalidHost},
		"interior space":      {"example .com", KindInvalidHost},
		"interior tab":        {"example.com\t.evil", KindInvalidHost},
		"non ascii u label":   {"b\u00fccher.de", KindInvalidHost},
		// A single-label U-label. This is the one input whose Kind depends on the
		// explicit non-ASCII check rather than on the label byte class: without
		// that check it reports KindBareHostname, blaming the missing dot for a
		// problem that is really the encoding.
		"non ascii single label": {"b\u00fccher", KindInvalidHost},
		"bracketed v6":           {"[2606:4700:4700::1111]", KindInvalidHost},
		"bracketed private v6":   {"[::ffff:192.168.1.1]", KindInvalidHost},
		"oversized name":         {strings.Repeat("a.", 200) + "com", KindInvalidHost},
		"oversized label":        {strings.Repeat("d", 64) + ".example.com", KindInvalidHost},
		"userinfo separator":     {"user@example.com", KindInvalidHost},
		"port separator":         {"example.com:443", KindInvalidHost},
		"path separator":         {"example.com/x", KindInvalidHost},
		"percent encoded":        {"example%2ecom.test", KindInvalidHost},
		"dotted octal ipv4":      {"0177.0.0.1", KindNonPublicIP},
		"dotted hex ipv4":        {"0x7f.0.0.1", KindNonPublicIP},
		"fully dotted hex ipv4":  {"0x7f.0x0.0x0.0x1", KindNonPublicIP},
		"short form ipv4":        {"127.1", KindNonPublicIP},
		"oversized inet_aton":    {"192.168.257", KindNonPublicIP},
		"link local inet_aton":   {"169.254.16962", KindNonPublicIP},
		"five numeric labels":    {"1.2.3.4.5", KindNonPublicIP},
		"bare 0x rightmost":      {"example.0x", KindNonPublicIP},
		"localhost":              {"localhost", KindLocalhost},
		"localhost trailing dot": {"localhost.", KindLocalhost},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			verr := hostValidationError(tc.host)
			if verr == nil {
				t.Fatalf("hostValidationError(%q) = nil, want a refusal", tc.host)
			}
			if verr.Kind != tc.kind {
				t.Errorf("hostValidationError(%q) Kind = %d, want %d (%s)",
					tc.host, verr.Kind, tc.kind, reasonLabel(tc.kind))
			}
		})
	}
}

// An oversized host is refused in constant work, because the length bound is
// checked before the host is split into labels. This is the ladder that used to
// live on the accept path: a 64 KiB host can no longer be accepted, so the
// property moved to where that input actually lands.
//
// The bound is a ceiling plus a growth bound rather than an equality, for the
// same reason as the other refusal ladders: building the *Error interpolates the
// host, so fmt.Sprintf's buffer growth is visible and is logarithmic in the
// payload. Logarithmic is not amplification.
func TestOversizedHostRefusalIsConstant(t *testing.T) {
	pinBlockLogger(t)

	var counts []float64
	for _, n := range []int{300, 4096, 65536} {
		host := strings.Repeat("b", n) + ".example.com"
		if IsPublicHost(host) {
			t.Fatalf("IsPublicHost(%d-byte host) = true, want false: the fixture must "+
				"witness the REFUSAL path to be measuring it", n)
		}
		counts = append(counts, testing.AllocsPerRun(100, func() {
			boolSink = IsPublicHost(host)
		}))
	}
	for i, got := range counts {
		if got > maxRefusalAllocs {
			t.Errorf("refusing an oversized host allocated %v times per run at rung %d, "+
				"want at most %v", got, i, float64(maxRefusalAllocs))
		}
	}
	if grown := counts[len(counts)-1] - counts[0]; grown > maxRefusalGrowth {
		t.Errorf("refusing an oversized host grew by %v allocations from 300 bytes to "+
			"64 KiB, want at most %v: a refusal must not track the payload",
			grown, float64(maxRefusalGrowth))
	}
	t.Logf("oversized-host refusal across 300..65536 bytes: %v", counts)
}

// The gate is SYNTACTIC. A well-formed public-looking name that RESOLVES to a
// private address still passes, and this test pins that so nobody reads the
// refusals above as a stronger guarantee than they are.
//
// Each of these is a real SSRF target. metadata.google.internal and metadata.goog
// are documented Google Cloud aliases for 169.254.169.254, the one spelling the
// gate does refuse. RFC 6761 section 6.3 puts the whole .localhost subtree on
// loopback, and systemd-resolved synthesizes localhost.localdomain the same way.
//
// Only SafeTransport's post-resolution checks stop these, which is why the README
// tells a caller to pair validation with it rather than treating a nil error as
// proof the destination is public.
func TestCanonicalHostGate_isSyntacticOnly(t *testing.T) {
	t.Parallel()
	hosts := []string{
		"metadata.google.internal",
		"metadata.goog",
		"instance-data.ec2.internal",
		"a.localhost",
		"localhost.localdomain",
		"printer.local",
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			if !IsPublicHost(host) {
				t.Errorf("IsPublicHost(%q) = false, want true: the gate judges SYNTAX. "+
					"If this starts refusing, the syntactic-only contract in the README "+
					"and in this test's doc comment is stale and both must be updated",
					host)
			}
		})
	}
}
