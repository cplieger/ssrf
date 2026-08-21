package ssrf

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// This file carries two kinds of check, and they answer different questions.
//
//   - The Benchmark functions feed the weekly benchmark tracker with a trend
//     series. The tracker compares each series against the previous run and
//     comments when the ratio crosses its threshold, so a series already
//     reporting 0 allocs/op is watched for free: any allocation at all makes the
//     ratio infinite and alerts at every threshold.
//   - The Test functions below gate what that arithmetic CANNOT see. A count
//     that must stay CONSTANT rather than zero is invisible to a ratio check (2
//     to 3 is 1.5, and the comparison is strict, so the chart stays silent), and
//     a count that must stay EQUAL across input classes has no ratio at all.
//     Those are the contracts here. The `== 0` assertions are defense in depth:
//     they fail at merge time naming the function, instead of arriving as a
//     chart comment a week later.
//
// WHAT THE MEASUREMENT FOUND, so the next reader does not have to re-derive it
// (go1.27.0, linux/amd64; the counts below are what the tests log today):
//
//   - IsPublicAddr is allocation-free on every address class this library
//     distinguishes: public and blocked, v4 and v6, each RFC 1918 range, every
//     embedded-IPv4 wrapper (6to4, NAT64, Teredo with its recursive re-check,
//     IPv4-compatible), a zone-bearing literal, and the zero Addr. The seven
//     series the tracker already watches are a sample of that set;
//     [publicAddrClasses] is the whole of it.
//   - The net.Dialer Control hook's ACCEPT path is allocation-free too, and no
//     benchmark covers it. That hook is the socket-time half of the
//     DNS-rebinding defense, so it runs once per connection the transport opens.
//   - IsPublicHost is allocation-free on an accepted IP LITERAL and costs a
//     constant 2 on an accepted dotted hostname: netip.ParseAddr heap-allocates
//     its error when the host is not an IP, and looksLikeNumericIPv4 splits the
//     host into labels. Constant is the load-bearing word. The 2 holds from one
//     label to 32768 of them and from a 16-byte label to a 64 KiB one, so the
//     split's slice grows in BYTES while the count does not move.
//   - ValidateURL is flat in the URL's size on every class measured: 3
//     allocations for an accepted hostname, 1 for an accepted IP literal (the
//     *url.URL itself), 6 refusing a private IP, 7 refusing a mapped metadata
//     address, 5 refusing a scheme and 4 refusing localhost — each unchanged
//     from a 16-byte path to a 64 KiB one.
//   - Validating a resolver's answer costs a constant 5 allocations whether the
//     resolver returned 1 address or 512, and refusing a poisoned answer costs a
//     constant 14 either way. A hostile resolver cannot amplify the guard by
//     answering with more addresses, and it makes no difference whether the
//     poisoned address arrives first or last.
//   - Refusal is consistently MORE expensive than acceptance here: 0 -> 7 in the
//     Control hook, 5 -> 14 in the dial path, 3 -> 6 in ValidateURL, 2 -> 9 in
//     the redirect policy. The asymmetry is inherent to returning a structured
//     *Error and emitting one bounded Warn, and the refusal path is the one an
//     attacker picks. So the property asserted below is not "refusal is as cheap
//     as acceptance" — it is not — but "refusal is BOUNDED and does not track
//     the attacker's payload".
//   - Two refusals do move with the payload, both logarithmically, and both are
//     bounded rather than pinned. A rejected HOST is interpolated into the
//     *Error message and the block log, which measures 8 allocations from a
//     16-byte bare hostname through a 4 KiB one and 13 at 64 KiB. A rejected
//     redirect HOP is worse in kind: the policy logs req.URL.Redacted(), so the
//     whole URL is materialized, giving 9 through 4 KiB and 12 at 64 KiB with a
//     byte cost proportional to what the far end sent. Both are fmt.Sprintf and
//     the log handler doubling buffers, so the growth is logarithmic in the
//     payload rather than proportional to it.
//   - The Control hook's malformed-address refusal has the same logarithmic shape
//     (5 allocations at 16 bytes, 6 at 4 KiB, 11 at 64 KiB) and is deliberately
//     NOT asserted: that address is built by this package from an
//     already-validated IP literal, so its length is not a caller's to choose.
//
// Every fixture is built at package scope or before the measured closure, never
// inside it: a strings.Repeat or a fmt.Sprintf inside an AllocsPerRun closure
// measures the fixture instead of the function under test. None of these
// contracts has a platform axis — nothing here touches a path, a separator or a
// syscall — so unlike pathinside's equivalents they need no GOOS skip.

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

// --- host-classification benchmarks: ValidateURL host/IP classification ---

func BenchmarkValidateHost_PublicIP(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://93.184.216.34")
	}
}

func BenchmarkValidateHost_PrivateIP(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://192.168.1.1")
	}
}

func BenchmarkValidateHost_Localhost(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://localhost")
	}
}

func BenchmarkValidateHost_DottedHostname(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://api.example.com")
	}
}

func BenchmarkValidateHost_BareHostname(b *testing.B) {
	for b.Loop() {
		ValidateURL("https://internal")
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

// --- per-connection and per-hop benchmarks ---
//
// Two series, added because each catches a regression no other check here can,
// and each is worth a permanent chart series for a different reason.
//
// BenchmarkSafeControl_AcceptedIP measures a path with no series at all until
// now, on the strongest arithmetic the tracker has: it reports 0 allocs/op, so
// any allocation makes the ratio infinite and alerts at every threshold. The
// hook runs once per connection the transport opens, which is what makes a
// per-call allocation there worth a weekly watch.
//
// BenchmarkRedirectPolicy_AcceptedHop covers the blind spot documented on
// TestRedirectPolicyAcceptedHopCostIsIndependentOfURLSize: a CONSTANT cost
// increase. Re-parsing the hop URL doubles this series (2 allocs/op to 4) while
// leaving the shape contract green, and a doubling is a ratio the tracker
// comments on.
//
// Both use a fixed input on purpose. A size ladder here would buy nothing the
// contract tests do not already own, and every b.Run name becomes a series the
// weekly run pays for.

func BenchmarkSafeControl_AcceptedIP(b *testing.B) {
	control := safeControl(isPublicAddr, map[uint16]struct{}{443: {}})
	b.ReportAllocs()
	for b.Loop() {
		if err := control("tcp4", "8.8.8.8:443", nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedirectPolicy_AcceptedHop(b *testing.B) {
	policy := SafeRedirectPolicy(nil)
	target, err := url.Parse("https://api.example.com/resource/123?q=1")
	if err != nil {
		b.Fatalf("Setup: url.Parse: %v", err)
	}
	req := &http.Request{URL: target}
	var via []*http.Request
	b.ReportAllocs()
	for b.Loop() {
		if err := policy(req, via); err != nil {
			b.Fatal(err)
		}
	}
}

// --- allocation contracts ---

// boolSink and errSink absorb every result so the compiler cannot discard the
// call being measured. testing.AllocsPerRun runs the closure, which is already
// enough, but a store to a package-level variable makes that independent of the
// optimizer.
var (
	boolSink bool
	errSink  error
)

// publicAddrClasses is every address class isPublicAddr distinguishes, keyed by
// class rather than by literal so a failure names the RULE that regressed. It
// covers each blocked range the README lists, both verdicts for every embedded-
// IPv4 wrapper (a wrapper whose embedded address is public must be as cheap as
// one whose embedded address is not, or the cost itself leaks the verdict), a
// zone-bearing literal, and the zero Addr — which reaches the IsValid guard and
// nothing else, and is the one input a caller can produce without parsing.
var publicAddrClasses = map[string]netip.Addr{
	"public_v4":                netip.MustParseAddr("8.8.8.8"),
	"private_10_8":             netip.MustParseAddr("10.0.0.1"),
	"private_172_16_12":        netip.MustParseAddr("172.16.0.1"),
	"private_192_168_16":       netip.MustParseAddr("192.168.1.1"),
	"loopback_v4":              netip.MustParseAddr("127.0.0.1"),
	"link_local_v4":            netip.MustParseAddr("169.254.169.254"),
	"cgnat":                    netip.MustParseAddr("100.64.0.1"),
	"unspecified_v4":           netip.MustParseAddr("0.0.0.0"),
	"this_host_0_8":            netip.MustParseAddr("0.1.2.3"),
	"multicast_v4":             netip.MustParseAddr("224.0.0.1"),
	"broadcast_v4":             netip.MustParseAddr("255.255.255.255"),
	"reserved_240_4":           netip.MustParseAddr("240.0.0.1"),
	"ietf_proto_assign":        netip.MustParseAddr("192.0.0.1"),
	"testnet_1":                netip.MustParseAddr("192.0.2.1"),
	"testnet_2":                netip.MustParseAddr("198.51.100.1"),
	"testnet_3":                netip.MustParseAddr("203.0.113.1"),
	"benchmarking_v4":          netip.MustParseAddr("198.18.0.1"),
	"deprecated_6to4_relay":    netip.MustParseAddr("192.88.99.1"),
	"public_v6":                netip.MustParseAddr("2606:4700:4700::1111"),
	"loopback_v6":              netip.MustParseAddr("::1"),
	"link_local_v6":            netip.MustParseAddr("fe80::1"),
	"unique_local_v6":          netip.MustParseAddr("fd00::1"),
	"multicast_v6":             netip.MustParseAddr("ff02::1"),
	"unspecified_v6":           netip.MustParseAddr("::"),
	"site_local_v6":            netip.MustParseAddr("fec0::1"),
	"discard_only_v6":          netip.MustParseAddr("100::1"),
	"benchmarking_v6":          netip.MustParseAddr("2001:2::1"),
	"documentation_v6":         netip.MustParseAddr("2001:db8::1"),
	"documentation_3fff":       netip.MustParseAddr("3fff::1"),
	"srv6_sid":                 netip.MustParseAddr("5f00::1"),
	"mapped_public_v4":         netip.MustParseAddr("::ffff:8.8.8.8"),
	"mapped_private_v4":        netip.MustParseAddr("::ffff:192.168.1.1"),
	"6to4_public_embed":        netip.MustParseAddr("2002:0808:0808::1"),
	"6to4_private_embed":       netip.MustParseAddr("2002:c0a8:0101::1"),
	"nat64_public_embed":       netip.MustParseAddr("64:ff9b::8.8.8.8"),
	"nat64_private_embed":      netip.MustParseAddr("64:ff9b::192.168.1.1"),
	"nat64_local":              netip.MustParseAddr("64:ff9b:1::1"),
	"teredo_public":            netip.MustParseAddr("2001:0:4136:e378:8000:63bf:f7f7:f7f7"),
	"teredo_private_client":    netip.MustParseAddr("2001:0:4136:e378:8000:63bf:3f57:fefe"),
	"teredo_private_server":    netip.MustParseAddr("2001:0:0a00:0001:8000:63bf:f7f7:f7f7"),
	"ipv4_compatible_public":   netip.MustParseAddr("::8.8.8.8"),
	"ipv4_compatible_loopback": netip.MustParseAddr("::127.0.0.1"),
	"zone_bearing_literal":     netip.MustParseAddr("fe80::1%eth0"),
	"zero_value":               {},
}

// publicHostIPLiterals is the set of accepted IP-literal hosts, in the spellings
// a caller actually hands IsPublicHost: bare, bracketed as URL authority
// syntax, and each transition-mechanism wrapper whose embedded IPv4 is public.
var publicHostIPLiterals = map[string]string{
	"bare_public_v4":         "93.184.216.34",
	"bare_public_v6":         "2606:4700:4700::1111",
	"bracketed_public_v6":    "[2606:4700:4700::1111]",
	"mapped_public_v4":       "::ffff:93.184.216.34",
	"bracketed_mapped_v4":    "[::ffff:93.184.216.34]",
	"public_6to4_embed":      "2002:0808:0808::1",
	"public_nat64_embed":     "64:ff9b::8.8.8.8",
	"public_teredo":          "2001:0:4136:e378:8000:63bf:f7f7:f7f7",
	"public_ipv4_compatible": "::8.8.8.8",
}

// controlAcceptClasses is every address class the Control hook ADMITS, across
// both dialer networks and both allowed ports. Only the accept path is here: it
// is the one that runs on a legitimate connection, and it is the one whose cost
// is a flat zero.
var controlAcceptClasses = map[string]struct {
	network string
	address string
}{
	"public_v4_default_port":   {"tcp4", "8.8.8.8:443"},
	"public_v4_alternate_port": {"tcp4", "8.8.8.8:8443"},
	"public_v6":                {"tcp6", "[2606:4700:4700::1111]:443"},
	"mapped_public_v4":         {"tcp4", "[::ffff:8.8.8.8]:443"},
	"public_6to4_embed":        {"tcp6", "[2002:0808:0808::1]:443"},
	"public_nat64_embed":       {"tcp6", "[64:ff9b::8.8.8.8]:443"},
}

// controlPorts is the two-port allowlist the Control-hook contracts run under,
// so the accept path is exercised for a port that is first in the map and one
// that is not.
var controlPorts = map[uint16]struct{}{443: {}, 8443: {}}

// payloadLadder is the attacker-payload size ladder in bytes. Each rung is 16x
// the previous, so a cost that became proportional to the input reports ~16x
// between rungs instead of standing still — well past any plausible measurement
// noise, and AllocsPerRun's integer division absorbs the rest.
var payloadLadder = []int{16, 256, 4096, 65536}

// resolverAnswerLadder is the number of addresses a hostile resolver answers
// with. It spans maxDialIPs (8) in both directions on purpose: the dial cap must
// bound dial ATTEMPTS without bounding how many addresses get VALIDATED, so the
// validation cost is measured well past the cap.
var resolverAnswerLadder = []int{1, 2, 8, 64, 512}

// benchDialer is the dialer the dial-path contracts hand to safeDialContext. It
// is never used to open a socket: every measured call is refused during
// validation, before any connect.
var benchDialer = &net.Dialer{}

// maxRefusalAllocs is a deliberately generous ceiling. The point of the refusal
// contracts is that the number does not track the attacker's payload, not that
// it is any particular small value; the largest measured refusal is 14.
const maxRefusalAllocs = 24

// maxConstantDrift is how far a count this file calls CONSTANT may sit above the
// count at the smallest input on the ladder.
//
// It is not zero because the battery runs under -race, and the race runtime's own
// allocations land in the same process-wide counter testing.AllocsPerRun reads.
// Measured over repeated runs: fixtures that are exactly flat without -race
// jitter by 1 in either direction with it, unrelated to input size (a rejected
// localhost URL read 5-4-4-4 in one run and 4-5-5-4 in the next). An exact
// equality assertion is therefore not stable in the invocation CI uses, so the
// contract is stated as a bound instead. The sensitivity that matters is
// unaffected: each rung of payloadLadder is 16x the previous, so a cost that
// became per-byte or per-label reports hundreds of extra allocations, not two.
const maxConstantDrift = 2

// maxRefusalGrowth is how much the refusal count may rise across the whole
// payload ladder — a 4096x increase in input. It is additive slack for the
// logarithmic buffer growth inside fmt.Sprintf and the log handler, and it is
// far below what a per-byte or per-label cost would produce.
const maxRefusalGrowth = 8

// pinBlockLogger points slog.Default() at a real formatting handler writing to
// io.Discard for the duration of the test.
//
// Two reasons it is not left at the ambient default. A rejection emits one Warn,
// so measuring 100 runs against the default handler would write the 64 KiB
// fixtures to stderr a hundred times. And the ambient handler is a consumer's
// choice, so an assertion measured against it would be an assertion about
// whatever the test binary inherited. A TextHandler still formats the record and
// still grows its buffer, so a regression that starts allocating per log line
// remains visible — that is the half a slog.DiscardHandler would hide, and it is
// worth 3 allocations of difference at the 64 KiB rung.
//
// Restored through t.Cleanup rather than defer: a defer does not run on a
// subtest's failure path, which would leak the discard handler into the rest of
// the package.
func pinBlockLogger(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestIsPublicAddrIsAllocationFree pins the strongest contract in the package:
// IsPublicAddr allocates nothing, on any address class, whatever its verdict.
//
// This is the predicate every other entry point ends in — ValidateURL and
// IsPublicHost for a literal host, the dial path for every resolved address, the
// Control hook for every connected socket — so an allocation here is paid once
// per outbound request at minimum, and once per resolved address on a
// multi-answer name.
//
// It also states the property the seven benchmark series only sample. Those
// series make the tracker alert if any of their seven inputs starts allocating;
// this table says the same of all 44, including the classes with no series at
// all (multicast, broadcast, ULA, NAT64, Teredo, the zero Addr).
//
// What it catches, red-checked rather than assumed: adding a single
// slog.Default().Debug line naming the rejected address costs 2 allocations per
// call even though the default level DISCARDS it, because the variadic args slice
// is built and the address boxed into an `any` before Enabled is consulted — and
// hoisting an fmt.Sprintf error message above the branch that returns it costs
// the same on the accept path. Both look harmless and both pass the entire
// behavioural suite. What it does NOT catch, also measured: collecting the
// blocked prefixes into a []netip.Prefix literal and ranging over it stays at
// zero, because escape analysis keeps that literal on the stack.
//
// No t.Parallel here or in the siblings below: testing.AllocsPerRun pins
// GOMAXPROCS to 1 and reads process-wide allocation counters, so a concurrent
// sibling's allocations would land in this measurement.
func TestIsPublicAddrIsAllocationFree(t *testing.T) {
	for class, addr := range publicAddrClasses {
		t.Run(class, func(t *testing.T) {
			if got := testing.AllocsPerRun(200, func() {
				boolSink = IsPublicAddr(addr)
			}); got != 0 {
				t.Errorf("IsPublicAddr(%q) allocated %v times per run, want 0: this "+
					"runs on every outbound URL and on every address a resolver "+
					"returns, so the cost here is paid per connection", addr, got)
			}
		})
	}
}

// TestIsPublicHostIsAllocationFreeForIPLiterals pins the accept path of the
// host-level predicate for the input class that can be judged without parsing
// anything: a host that IS an IP literal.
//
// The asymmetry is the shape of the function, and it is worth stating rather
// than glossing. A literal reaches netip.ParseAddr, which succeeds and allocates
// nothing, and the verdict is then IsPublicAddr's. A dotted NAME makes the same
// ParseAddr fail, and a failed parse heap-allocates its error — that class is
// held to a constant instead, by TestHostValidationCostIsIndependentOfHostSize.
//
// Bracketed spellings are in the table because they take a different route: the
// bracket strip is a slice of the caller's string, so it must not become a
// strings.Trim-and-copy. This is the pre-filter path a caller uses to sift a
// list of hosts without emitting block logs, so it is the one most likely to run
// in a loop.
func TestIsPublicHostIsAllocationFreeForIPLiterals(t *testing.T) {
	for class, host := range publicHostIPLiterals {
		t.Run(class, func(t *testing.T) {
			if !IsPublicHost(host) {
				t.Fatalf("IsPublicHost(%q) = false, want true: the fixture must "+
					"witness the ACCEPT path to be measuring it", host)
			}
			if got := testing.AllocsPerRun(200, func() {
				boolSink = IsPublicHost(host)
			}); got != 0 {
				t.Errorf("IsPublicHost(%q) allocated %v times per run, want 0: "+
					"accepting an IP literal must not build a second string, since "+
					"this is the silent pre-filter callers run over whole host lists",
					host, got)
			}
		})
	}
}

// TestControlHookAcceptPathIsAllocationFree pins the socket-time half of the
// DNS-rebinding defense, which nothing else in this repo measures.
//
// safeControl's returned hook fires on every connection the transport opens,
// after the OS has resolved the address and before the TCP handshake completes.
// Its accept path is a SplitHostPort over the caller's string, a port lookup, a
// netip.ParseAddr of a literal and one policy call — all of which measured at
// zero — so allocation-free is the honest description of it and the number a
// regression should be held to.
//
// This is the contract the weekly chart is most blind to: there is no
// BenchmarkSafeControl series at all, so today nothing would notice this path
// starting to allocate per connection.
func TestControlHookAcceptPathIsAllocationFree(t *testing.T) {
	control := safeControl(isPublicAddr, controlPorts)

	for class, tc := range controlAcceptClasses {
		t.Run(class, func(t *testing.T) {
			if err := control(tc.network, tc.address, nil); err != nil {
				t.Fatalf("safeControl(%q, %q) = %v, want nil: the fixture must "+
					"witness the ACCEPT path to be measuring it", tc.network, tc.address, err)
			}
			if got := testing.AllocsPerRun(200, func() {
				errSink = control(tc.network, tc.address, nil)
			}); got != 0 {
				t.Errorf("safeControl(%q, %q) allocated %v times per run, want 0: "+
					"the Control hook re-validates the connected IP on every socket "+
					"this transport opens", tc.network, tc.address, got)
			}
		})
	}
}

// TestControlHookAcceptPathIsAllocationFreeUnderACustomPolicy holds the same
// contract when the address predicate is a caller's closure rather than this
// package's own.
//
// Separate from the table above because the collaborator differs, not the input:
// WithAddressPolicy is the documented way to widen or narrow the verdict, and
// the question here is whether routing through an AddressPolicy value costs
// anything by itself. It does not — the policy is already an AddressPolicy field
// on the config, so no boxing happens at the call. A refactor that started
// wrapping the caller's policy per call would show up here.
func TestControlHookAcceptPathIsAllocationFreeUnderACustomPolicy(t *testing.T) {
	allowAll := func(netip.Addr) bool { return true }
	control := safeControl(allowAll, controlPorts)
	const network, address = "tcp4", "10.0.0.1:443"

	if err := control(network, address, nil); err != nil {
		t.Fatalf("safeControl(%q, %q) with an allow-all policy = %v, want nil",
			network, address, err)
	}
	if got := testing.AllocsPerRun(200, func() {
		errSink = control(network, address, nil)
	}); got != 0 {
		t.Errorf("safeControl(%q, %q) under a custom AddressPolicy allocated %v "+
			"times per run, want 0: injecting a policy must not add a per-socket "+
			"cost", network, address, got)
	}
}

// TestValidateURLCostIsIndependentOfURLSize is the contract the weekly chart
// cannot express: ValidateURL's allocation count does not move as the URL grows.
//
// The tracker watches five ValidateURL series, each at one fixed input, so it
// sees the count for that input drift. What it cannot see is a cost that scales:
// a rewrite whose per-call count tracks the path length, the query length or the
// label count would hold every existing series exactly where it is while turning
// the guard into the amplifier it exists to prevent. An attacker picks the URL,
// so that is the property worth pinning.
//
// The ladder spans 16 bytes to 64 KiB — 4096x — and the assertion is equality
// with the smallest rung, not a threshold, because these classes measured
// exactly flat. Both verdicts are represented: the grown part of every fixture
// here is the path or the query, which no message interpolates, so an accepted
// and a rejected URL are equally flat. Growing the HOST is a different property
// and lives in TestRefusalCostDoesNotGrowWithTheHost.
//
// The two hostname-shape rows are the point of the test. A 32768-label host
// still costs what a one-label host costs, because looksLikeNumericIPv4 splits
// into one slice whose LENGTH grows while the allocation count does not — and a
// 64 KiB single label costs the same again, so nothing in the path is per-byte.
func TestValidateURLCostIsIndependentOfURLSize(t *testing.T) {
	pinBlockLogger(t)

	tests := map[string]struct {
		build   func(n int) string
		blocked bool
	}{
		"accepts_public_hostname_with_long_path": {
			build: func(n int) string { return "https://api.example.com/" + strings.Repeat("p", n) },
		},
		"accepts_public_ip_with_long_query": {
			build: func(n int) string { return "https://93.184.216.34/x?q=" + strings.Repeat("v", n) },
		},
		"accepts_hostname_with_many_labels": {
			build: func(n int) string { return "https://" + strings.Repeat("a.", n/2) + "com/x" },
		},
		"accepts_hostname_with_one_long_label": {
			build: func(n int) string { return "https://" + strings.Repeat("d", n) + ".example.com/x" },
		},
		"rejects_private_ip_with_long_path": {
			build:   func(n int) string { return "https://10.0.0.1/" + strings.Repeat("p", n) },
			blocked: true,
		},
		"rejects_mapped_metadata_ip_with_long_path": {
			build: func(n int) string {
				return "https://[::ffff:169.254.169.254]/" + strings.Repeat("p", n)
			},
			blocked: true,
		},
		"rejects_bad_scheme_with_long_path": {
			build:   func(n int) string { return "http://api.example.com/" + strings.Repeat("p", n) },
			blocked: true,
		},
		"rejects_localhost_with_long_path": {
			build:   func(n int) string { return "https://localhost/" + strings.Repeat("p", n) },
			blocked: true,
		},
	}

	for class, tc := range tests {
		t.Run(class, func(t *testing.T) {
			var counts []float64
			for _, n := range payloadLadder {
				raw := tc.build(n)
				if err := ValidateURL(raw); (err != nil) != tc.blocked {
					t.Fatalf("ValidateURL(%s) error = %v, want blocked = %v: the "+
						"fixture must witness the path it claims to measure",
						describeURL(raw), err, tc.blocked)
				}
				counts = append(counts, testing.AllocsPerRun(100, func() {
					errSink = ValidateURL(raw)
				}))
			}
			for i, got := range counts {
				if got-counts[0] > maxConstantDrift {
					t.Errorf("ValidateURL allocated %v times per run at payload size "+
						"%d bytes but %v at %d bytes, want at most %v more: validation "+
						"cost must not scale with a URL an attacker supplies", got,
						payloadLadder[i], counts[0], payloadLadder[0], float64(maxConstantDrift))
				}
			}
			t.Logf("ValidateURL costs %v allocations across %d..%d bytes",
				counts, payloadLadder[0], payloadLadder[len(payloadLadder)-1])
		})
	}
}

// TestHostValidationCostIsIndependentOfHostSize holds the same property one
// layer down, for the silent predicate.
//
// IsPublicHost is the entry point with no URL parsing in front of it, so this is
// the classification cost on its own: a constant 2 allocations for an accepted
// dotted hostname, from one label to 32768 and from a 16-byte label to a 64 KiB
// one. Worth pinning separately from ValidateURL because it is documented as the
// cheap pre-filter — the thing a caller runs over a whole list of hosts — and
// because a per-label cost introduced here would be invisible in ValidateURL's
// larger constant.
func TestHostValidationCostIsIndependentOfHostSize(t *testing.T) {
	tests := map[string]func(n int) string{
		"many_labels":    func(n int) string { return strings.Repeat("a.", n/2) + "com" },
		"one_long_label": func(n int) string { return strings.Repeat("d", n) + ".example.com" },
	}

	for class, build := range tests {
		t.Run(class, func(t *testing.T) {
			var counts []float64
			for _, n := range payloadLadder {
				host := build(n)
				if !IsPublicHost(host) {
					t.Fatalf("IsPublicHost(%s) = false, want true: the fixture must "+
						"witness the ACCEPT path to be measuring it", describeURL(host))
				}
				counts = append(counts, testing.AllocsPerRun(100, func() {
					boolSink = IsPublicHost(host)
				}))
			}
			for i, got := range counts {
				if got-counts[0] > maxConstantDrift {
					t.Errorf("IsPublicHost allocated %v times per run at host size %d "+
						"bytes but %v at %d bytes, want at most %v more: judging a host "+
						"must not cost per label or per byte", got, payloadLadder[i],
						counts[0], payloadLadder[0], float64(maxConstantDrift))
				}
			}
			t.Logf("IsPublicHost costs %v allocations across %d..%d bytes",
				counts, payloadLadder[0], payloadLadder[len(payloadLadder)-1])
		})
	}
}

// TestRefusalCostDoesNotGrowWithTheHost holds the property that matters on the
// one path where allocation-freedom is not available, and where the input is by
// definition the attacker's.
//
// Every rejection builds a *ssrf.Error carrying a message that interpolates the
// offending host, and emits one Warn carrying it as an attribute. So a refusal
// allocates, and unlike the classes above its count is not perfectly flat: the
// measured shape is 8 allocations for ValidateURL from a 16-byte bare hostname
// through a 4 KiB one, then 13 at 64 KiB, as fmt.Sprintf and the log handler
// double their buffers. That is logarithmic in the payload.
//
// Logarithmic is not amplification, and the distinction is the whole point of
// the test. An attacker who can make a refusal a hundred times more expensive by
// sending a hundred times more host has found an amplification vector inside the
// SSRF guard. One who can add four allocations by sending four thousand times
// more host has not. So the assertion is a ceiling plus a bound on GROWTH across
// the ladder, rather than the equality the flat classes get.
//
// Byte volume does grow with the input — the error message contains the host,
// and so does the log line — and this test deliberately does not gate that. A
// consumer that logs a rejected host is choosing to write attacker-sized data to
// its log sink; the library's job is to keep the WORK bounded, which is what the
// count measures.
func TestRefusalCostDoesNotGrowWithTheHost(t *testing.T) {
	pinBlockLogger(t)

	// Each builder returns a HOST that must be refused, so the rejected string
	// is what grows across the ladder.
	tests := map[string]func(n int) string{
		"bare_hostname":       func(n int) string { return strings.Repeat("b", n) },
		"numeric_ipv4_labels": func(n int) string { return strings.Repeat("1", n) + ".1" },
		"dotted_octal_ipv4":   func(n int) string { return "0177." + strings.Repeat("0", n) + ".0.1" },
		"whitespace_padded":   func(n int) string { return strings.Repeat("b", n) + " x" },
	}

	for class, build := range tests {
		t.Run(class, func(t *testing.T) {
			var urlCounts, hostCounts []float64
			for _, n := range payloadLadder {
				host := build(n)
				raw := "https://" + host
				if IsPublicHost(host) {
					t.Fatalf("IsPublicHost(%s) = true, want false: the fixture must "+
						"witness the REFUSAL path to be measuring it", describeURL(host))
				}
				urlCounts = append(urlCounts, testing.AllocsPerRun(100, func() {
					errSink = ValidateURL(raw)
				}))
				hostCounts = append(hostCounts, testing.AllocsPerRun(100, func() {
					boolSink = IsPublicHost(host)
				}))
			}
			checkBoundedRefusal(t, "ValidateURL", urlCounts)
			checkBoundedRefusal(t, "IsPublicHost", hostCounts)
			t.Logf("refusal cost across %d..%d bytes: ValidateURL %v, IsPublicHost %v",
				payloadLadder[0], payloadLadder[len(payloadLadder)-1], urlCounts, hostCounts)
		})
	}
}

// TestResolvedAddressValidationCostIsIndependentOfAnswerSize is the dial-time
// half of the amplification question, and the contract with the most attacker
// leverage behind it: the size of a DNS answer is chosen by whoever controls the
// name being resolved.
//
// The transport validates EVERY address a resolver returns before it dials any
// of them, and it deliberately validates them all even though maxDialIPs caps
// the number it will attempt. That is the fail-closed order — truncating first
// would let a resolver hide an internal address behind eight public ones — and
// it means the validation loop runs as long as the answer is. This pins that
// running it 512 times costs the same allocation count as running it once, for
// both verdicts.
//
// The accept half is measured through resolveAndValidate rather than the whole
// dial function, because a successful validation is followed by a real connect
// that would dominate the measurement. The refuse half goes through the actual
// safeDialContext entry point: it returns before any socket is created, so the
// production path is measurable as-is, and the poisoned address is placed LAST
// so every address in the answer is validated before the refusal.
func TestResolvedAddressValidationCostIsIndependentOfAnswerSize(t *testing.T) {
	pinBlockLogger(t)

	ctx := t.Context()
	var acceptCounts, refuseCounts []float64

	for _, k := range resolverAnswerLadder {
		public := publicAnswer(k)
		poisoned := publicAnswer(k)
		poisoned[k-1] = netip.MustParseAddr("169.254.169.254") // cloud metadata service

		publicResolver := &mockResolver{ips: public}
		if _, err := resolveAndValidate(ctx, publicResolver, isPublicAddr, "h.example.com", KindNonPublicIP); err != nil {
			t.Fatalf("resolveAndValidate over %d public addresses = %v, want nil: the "+
				"fixture must witness the ACCEPT path to be measuring it", k, err)
		}
		acceptCounts = append(acceptCounts, testing.AllocsPerRun(100, func() {
			_, errSink = resolveAndValidate(ctx, publicResolver, isPublicAddr, "h.example.com", KindNonPublicIP)
		}))

		dial := safeDialContext(benchDialer, isPublicAddr, &mockResolver{ips: poisoned}, controlPorts)
		if _, err := dial(ctx, "tcp", "h.example.com:443"); err == nil {
			t.Fatalf("dial with a poisoned %d-address answer = nil, want an error: the "+
				"fixture must witness the REFUSAL path to be measuring it", k)
		}
		refuseCounts = append(refuseCounts, testing.AllocsPerRun(100, func() {
			_, errSink = dial(ctx, "tcp", "h.example.com:443")
		}))
	}

	for i := range acceptCounts {
		if acceptCounts[i]-acceptCounts[0] > maxConstantDrift {
			t.Errorf("resolveAndValidate allocated %v times per run for a %d-address "+
				"answer but %v for a %d-address one, want at most %v more: validating a "+
				"resolver's answer must not cost per address", acceptCounts[i],
				resolverAnswerLadder[i], acceptCounts[0], resolverAnswerLadder[0],
				float64(maxConstantDrift))
		}
		if refuseCounts[i]-refuseCounts[0] > maxConstantDrift {
			t.Errorf("the dial path allocated %v times per run refusing a %d-address "+
				"answer but %v refusing a %d-address one, want at most %v more: a hostile "+
				"resolver must not amplify the guard by answering with more addresses",
				refuseCounts[i], resolverAnswerLadder[i], refuseCounts[0],
				resolverAnswerLadder[0], float64(maxConstantDrift))
		}
	}
	t.Logf("resolver-answer cost from %d to %d addresses: accept %v, refuse %v",
		resolverAnswerLadder[0], resolverAnswerLadder[len(resolverAnswerLadder)-1],
		acceptCounts, refuseCounts)
}

// TestRefusalCostIsIndependentOfWhereThePoisonedAddressSits records that the
// dial path has no cheap refusal and no expensive one.
//
// resolveAndValidate fails closed on the FIRST non-public address, so a poisoned
// answer could plausibly cost less when the poison arrives first. It does not:
// the counts are identical, because the per-address work that the early exit
// skips allocates nothing at all — which is TestIsPublicAddrIsAllocationFree
// stated as a cost. The consequence worth knowing is that an attacker cannot
// route the guard down a cheaper branch by ordering the answer, and neither can
// a legitimate caller be penalized for one.
func TestRefusalCostIsIndependentOfWhereThePoisonedAddressSits(t *testing.T) {
	pinBlockLogger(t)

	ctx := t.Context()
	const k = 64
	metadata := netip.MustParseAddr("169.254.169.254")

	first := publicAnswer(k)
	first[0] = metadata
	last := publicAnswer(k)
	last[k-1] = metadata

	counts := map[string]float64{}
	for position, answer := range map[string][]netip.Addr{"first": first, "last": last} {
		resolver := &mockResolver{ips: answer}
		if _, err := resolveAndValidate(ctx, resolver, isPublicAddr, "h.example.com", KindNonPublicIP); err == nil {
			t.Fatalf("resolveAndValidate with the poisoned address %s = nil, want an "+
				"error: the fixture must witness the REFUSAL path", position)
		}
		counts[position] = testing.AllocsPerRun(100, func() {
			_, errSink = resolveAndValidate(ctx, resolver, isPublicAddr, "h.example.com", KindNonPublicIP)
		})
	}

	if diff := counts["first"] - counts["last"]; diff > maxConstantDrift || diff < -maxConstantDrift {
		t.Errorf("resolveAndValidate allocated %v times per run with the poisoned "+
			"address first and %v with it last, want the two within %v: the position of "+
			"a blocked address in a %d-address answer must not change what refusing it "+
			"costs", counts["first"], counts["last"], float64(maxConstantDrift), k)
	}
	if counts["last"] > maxRefusalAllocs {
		t.Errorf("resolveAndValidate allocated %v times per run refusing a %d-address "+
			"answer, want at most %d: refusing a poisoned DNS answer must stay bounded",
			counts["last"], k, maxRefusalAllocs)
	}
}

// TestRedirectPolicyAcceptedHopCostIsIndependentOfURLSize pins the per-hop cost
// of the redirect gate on the path a legitimate chain takes.
//
// Every hop in a redirect chain is a URL the far end chose, so this is the one
// entry point whose input is attacker-supplied by construction rather than by
// accident. An accepted hop costs a flat 2 allocations from a 16-byte URL to a
// 64 KiB one — cheaper than ValidateURL's 3, because the policy re-validates the
// *url.URL net/http is about to dial instead of re-parsing its text.
//
// The limit of a shape contract, measured and worth stating: re-parsing the hop
// (url.Parse(u.String()), the regression classifyURL's own doc comment warns
// about) takes the accepted hop from 2 allocations to 4 and stays PERFECTLY FLAT
// across the ladder, because URL.String pre-sizes its builder from the URL's
// component lengths. So this test does not catch it — nothing about a constant
// cost is visible to a test that gates the slope. That gap is what
// BenchmarkRedirectPolicy_AcceptedHop exists for: 2 to 4 is a ratio the weekly
// tracker alerts on. What this test does catch is a per-byte or per-label cost
// on the hop, which the tracker's fixed-input series cannot see.
func TestRedirectPolicyAcceptedHopCostIsIndependentOfURLSize(t *testing.T) {
	pinBlockLogger(t)

	policy := SafeRedirectPolicy(nil)
	var via []*http.Request

	var counts []float64
	for _, n := range payloadLadder {
		req := mustHopRequest(t, "https://api.example.com/"+strings.Repeat("p", n))
		if err := policy(req, via); err != nil {
			t.Fatalf("SafeRedirectPolicy hop %s = %v, want nil: the fixture must "+
				"witness the ACCEPT path to be measuring it",
				describeURL(req.URL.String()), err)
		}
		counts = append(counts, testing.AllocsPerRun(100, func() {
			errSink = policy(req, via)
		}))
	}
	for i, got := range counts {
		if got-counts[0] > maxConstantDrift {
			t.Errorf("SafeRedirectPolicy allocated %v times per run at hop URL size "+
				"%d bytes but %v at %d bytes, want at most %v more: a redirect target is "+
				"chosen by the far end, so per-hop cost must not scale with it", got,
				payloadLadder[i], counts[0], payloadLadder[0], float64(maxConstantDrift))
		}
	}
	t.Logf("an accepted hop costs %v allocations across %d..%d bytes",
		counts, payloadLadder[0], payloadLadder[len(payloadLadder)-1])
}

// TestRedirectRefusalCostDoesNotGrowWithTheHopURL records the one refusal in this
// package whose cost is driven by the whole URL rather than by the host, and
// bounds it.
//
// The measurement is the reason this is a separate test from the accepted hop
// above: refusing a hop costs a flat 9 allocations from 16 bytes through 4 KiB
// and 12 at 64 KiB, where refusing the same host through ValidateURL is flat.
// The difference is the log line. ValidateURL logs the HOST; the redirect policy
// logs req.URL.Redacted(), which calls URL.String() and therefore materializes
// the entire hop URL — path, query and all — into a fresh string on every
// refusal.
//
// That is a deliberate diagnostic (a blocked redirect is not diagnosable from
// the host alone, since the chain is the interesting part), and the allocation
// COUNT stays bounded, which is what this asserts. The BYTE cost is genuinely
// proportional to the URL the far end sent, and this test does not gate that:
// the caller who wants a bound there bounds its own log sink. Recorded here so
// the next reader does not mistake the flat count for a flat cost.
func TestRedirectRefusalCostDoesNotGrowWithTheHopURL(t *testing.T) {
	pinBlockLogger(t)

	policy := SafeRedirectPolicy(nil)
	var via []*http.Request

	tests := map[string]func(n int) string{
		"private_hop":       func(n int) string { return "https://10.0.0.1/" + strings.Repeat("p", n) },
		"scheme_downgrade":  func(n int) string { return "http://api.example.com/" + strings.Repeat("p", n) },
		"metadata_ip_hop":   func(n int) string { return "https://169.254.169.254/" + strings.Repeat("p", n) },
		"bare_hostname_hop": func(n int) string { return "https://internal/" + strings.Repeat("p", n) },
	}

	for class, build := range tests {
		t.Run(class, func(t *testing.T) {
			var counts []float64
			for _, n := range payloadLadder {
				req := mustHopRequest(t, build(n))
				if err := policy(req, via); err == nil {
					t.Fatalf("SafeRedirectPolicy hop %s = nil, want an error: the "+
						"fixture must witness the REFUSAL path to be measuring it",
						describeURL(req.URL.String()))
				}
				counts = append(counts, testing.AllocsPerRun(100, func() {
					errSink = policy(req, via)
				}))
			}
			checkBoundedRefusal(t, "SafeRedirectPolicy", counts)
			t.Logf("refusing a hop across %d..%d bytes: %v",
				payloadLadder[0], payloadLadder[len(payloadLadder)-1], counts)
		})
	}
}

// checkBoundedRefusal asserts that a refusal's allocation counts along
// payloadLadder stay under maxRefusalAllocs and rise by at most
// maxRefusalGrowth across the whole ladder. It reports with t.Errorf rather than
// aborting, so every rung of a failing class is visible in one run, and it takes
// the function's name so each failure says whose counts these are.
func checkBoundedRefusal(t *testing.T, fn string, counts []float64) {
	t.Helper()
	for i, got := range counts {
		if got > maxRefusalAllocs {
			t.Errorf("%s allocated %v times per run refusing a %d-byte host, want at "+
				"most %v: refusal is the path an attacker picks, so it must stay bounded",
				fn, got, payloadLadder[i], float64(maxRefusalAllocs))
		}
	}
	if grown := counts[len(counts)-1] - counts[0]; grown > maxRefusalGrowth {
		t.Errorf("%s allocated %v more times per run refusing a %d-byte host than a "+
			"%d-byte one, want at most %v more: %dx the payload must not buy an "+
			"attacker a proportional cost", fn, grown,
			payloadLadder[len(payloadLadder)-1], payloadLadder[0], float64(maxRefusalGrowth),
			payloadLadder[len(payloadLadder)-1]/payloadLadder[0])
	}
}

// mustHopRequest builds the *http.Request a CheckRedirect function receives for
// one hop. It is a test helper, so it fails inside itself rather than handing a
// second error back to every call site.
func mustHopRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	target, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("Setup: url.Parse(%s): %v", describeURL(raw), err)
	}
	return &http.Request{URL: target}
}

// publicAnswer returns k distinct public IPv4 addresses, the shape of a resolver
// answer for a name behind a large load balancer — or of one an attacker pads to
// make the validation loop as long as possible.
func publicAnswer(k int) []netip.Addr {
	answer := make([]netip.Addr, k)
	for i := range answer {
		answer[i] = netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)})
	}
	return answer
}

// describeURL renders a fixture for a failure message without pasting 64 KiB of
// filler into it: a long string is reported as its head plus its length, so the
// message stays readable while still identifying which rung failed.
func describeURL(s string) string {
	const head = 48
	if len(s) <= head {
		return strconv.Quote(s)
	}
	return strconv.Quote(s[:head]) + "...(" + strconv.Itoa(len(s)) + " bytes)"
}
