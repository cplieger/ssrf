package ssrf

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/runesafe/v2"
)

// hostileRunes carries one rune from each class runesafe treats as unsafe,
// preceded by the log-forgery shape the sanitizer is often assumed to be for.
//
// The forgery half is deliberately included to pin what is NOT a threat here:
// both stdlib handlers escape a newline (TextHandler quotes the whole value,
// JSONHandler emits \n), so the second "record" never materializes. The three
// runes after it are the real exposure, because JSONHandler escapes only what
// JSON requires — everything below U+0020 — and emits these RAW.
const hostileRunes = "\nlevel=INFO msg=\"all clear\"" +
	"\u0085" + // C1 NEL, a single-rune escape introducer on a terminal
	"\u202e" + // Bidi_Control RLO, Trojan-Source reordering
	"\u2028" + // JS line terminator, legal unescaped in JSON
	"\u007f" // DEL

// --- The helpers ---

// Each ForLog helper must strip every unsafe rune and hold its bound. The
// bounds are asserted as n+len("...") because the marker sits outside the cap:
// SanitizeSingleLineBounded returns at most n bytes of payload plus the marker.
func TestForLogHelpersSanitizeAndBound(t *testing.T) {
	t.Parallel()
	const marker = 3 // len("...")
	cases := []struct {
		name  string
		fn    func(string) string
		bound int
	}{
		{"hostForLog", hostForLog, maxHostLog},
		{"addrForLog", addrForLog, maxAddrLog},
		{"urlForLog", urlForLog, maxURLLog},
		{"portForLog", portForLog, maxPortLog},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.fn("evil.example" + hostileRunes)
			for _, r := range got {
				if runesafe.IsUnsafeSingleLine(r) {
					t.Errorf("%s(hostile) = %q, want no unsafe rune; found U+%04X", tc.name, got, r)
				}
			}

			long := tc.fn(strings.Repeat("b", 70000))
			if len(long) > tc.bound+marker {
				t.Errorf("%s(70000 bytes) returned %d bytes, want at most %d: an "+
					"attacker-sized value must not reach the log sink whole",
					tc.name, len(long), tc.bound+marker)
			}

			// A well-formed value at the bound is passed through untouched, so
			// the bound never costs a real diagnostic.
			legal := strings.Repeat("b", tc.bound)
			if got := tc.fn(legal); got != legal {
				t.Errorf("%s(%d legal bytes) truncated a value inside its bound", tc.name, tc.bound)
			}
		})
	}
}

// errTextForLog renders, sanitizes and bounds; a nil error is the empty string
// rather than the "%!v(PANIC=" shape a naive render would produce.
func TestErrTextForLog(t *testing.T) {
	t.Parallel()
	if got := errTextForLog(nil); got != "" {
		t.Errorf("errTextForLog(nil) = %q, want %q", got, "")
	}

	got := errTextForLog(ssrfErr(KindDNSFailed, "h", "lookup failed for "+hostileRunes, nil))
	for _, r := range got {
		if runesafe.IsUnsafeSingleLine(r) {
			t.Errorf("errTextForLog(hostile) = %q, want no unsafe rune; found U+%04X", got, r)
		}
	}

	long := errTextForLog(ssrfErr(KindDNSFailed, "h", strings.Repeat("b", 70000), nil))
	if len(long) > maxErrLog+3 {
		t.Errorf("errTextForLog(70000 bytes) returned %d bytes, want at most %d", len(long), maxErrLog+3)
	}
}

// maxHostLog must be RFC 1035's presentation limit, so no resolvable host is
// ever truncated. Pinned as a value because the whole argument for capping at
// 253 rather than lower is that a legal name fits.
func TestMaxHostLogIsTheDNSNameLimit(t *testing.T) {
	t.Parallel()
	if maxHostLog != 253 {
		t.Errorf("maxHostLog = %d, want 253 (RFC 1035 presentation limit): a smaller "+
			"bound truncates resolvable hosts, a larger one bounds nothing real", maxHostLog)
	}
	// The longest legal name survives whole.
	longest := strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 63)+".", 4), ".")
	if len(longest) != 255 {
		t.Fatalf("fixture is %d bytes, want 255: the builder is wrong", len(longest))
	}
	legal := longest[:maxHostLog]
	if got := hostForLog(legal); got != legal {
		t.Errorf("hostForLog truncated a %d-byte legal DNS name", len(legal))
	}
}

// --- The transport path, end to end ---

// captureJSON points slog.Default() at a JSONHandler for the duration of the
// test and returns the buffer. JSON is the sink that matters: it is what
// subflux runs, and it is the handler that emits C1 and Bidi_Control raw, so a
// missing sanitize is only visible here. Restored with t.Cleanup rather than
// defer, which would not run on a subtest's failure path.
func captureJSON(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// assertLogIsSafe is a domain comparison, not an assertion helper: it takes no
// *testing.T and returns what is wrong, so the Test function stays the place a
// failure is reported.
func unsafeRunesIn(s string) []rune {
	var found []rune
	for _, r := range s {
		if runesafe.IsUnsafeSingleLine(r) {
			found = append(found, r)
		}
	}
	return found
}

// Every refusal the transport logs must reach the sink sanitized and bounded,
// whichever branch produced it. This drives the real entry points rather than
// the helpers, so a site added later without a helper fails here.
func TestTransportRefusalLogsAreSafe(t *testing.T) {
	hostile := "evil.example" + hostileRunes
	huge := strings.Repeat("b", 70000)

	cases := map[string]func(t *testing.T){
		"dial invalid address": func(t *testing.T) {
			dial := safeDialContext(&net.Dialer{}, isPublicAddr, &mockResolver{}, controlPorts)
			// No port separator, so SplitHostPort fails.
			_, _ = dial(t.Context(), "tcp", hostile)
		},
		"dial bad port": func(t *testing.T) {
			dial := safeDialContext(&net.Dialer{}, isPublicAddr, &mockResolver{}, controlPorts)
			_, _ = dial(t.Context(), "tcp", net.JoinHostPort(hostile, "not-a-port"+huge))
		},
		"dial port not allowed": func(t *testing.T) {
			dial := safeDialContext(&net.Dialer{}, isPublicAddr, &mockResolver{}, controlPorts)
			_, _ = dial(t.Context(), "tcp", net.JoinHostPort(hostile, "9999"))
		},
		"dial dns failed": func(t *testing.T) {
			r := &mockResolver{err: &net.DNSError{Err: "no such host" + hostileRunes, Name: hostile}}
			dial := safeDialContext(&net.Dialer{}, isPublicAddr, r, controlPorts)
			_, _ = dial(t.Context(), "tcp", net.JoinHostPort(hostile, "443"))
		},
		"dial no ips resolved": func(t *testing.T) {
			dial := safeDialContext(&net.Dialer{}, isPublicAddr, &mockResolver{}, controlPorts)
			_, _ = dial(t.Context(), "tcp", net.JoinHostPort(hostile, "443"))
		},
		"dial resolved ip denied": func(t *testing.T) {
			r := &mockResolver{ips: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
			dial := safeDialContext(&net.Dialer{}, isPublicAddr, r, controlPorts)
			_, _ = dial(t.Context(), "tcp", net.JoinHostPort(hostile, "443"))
		},
		"dial capped": func(t *testing.T) {
			r := &mockResolver{ips: loopbackIPs(maxDialIPs + 1)}
			dial := safeDialContext(&net.Dialer{Timeout: 50 * time.Millisecond},
				func(netip.Addr) bool { return true }, r, map[uint16]struct{}{1: {}})
			_, _ = dial(t.Context(), "tcp", net.JoinHostPort(hostile, "1"))
		},
		"redirect blocked": func(t *testing.T) {
			policy := SafeRedirectPolicy(nil)
			req := &http.Request{URL: &url.URL{
				Scheme: "https",
				Host:   "10.0.0.1",
				Path:   "/" + hostile + huge,
			}}
			_ = policy(req, nil)
		},
		"control unparseable ip": func(t *testing.T) {
			ctrl := safeControl(isPublicAddr, controlPorts)
			_ = ctrl("tcp4", net.JoinHostPort(hostile, "443"), nil)
		},
		"control invalid address": func(t *testing.T) {
			ctrl := safeControl(isPublicAddr, controlPorts)
			_ = ctrl("tcp4", hostile, nil)
		},
	}

	for name, drive := range cases {
		t.Run(name, func(t *testing.T) {
			buf := captureJSON(t)
			drive(t)

			// JSONHandler terminates each record with a newline, so the check
			// runs per record: scanning the whole buffer would report that
			// terminator as an unsafe rune.
			records := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
			if buf.Len() == 0 {
				t.Fatalf("no log line emitted: the case must witness the refusal path to be measuring it")
			}
			for _, line := range records {
				if bad := unsafeRunesIn(line); len(bad) > 0 {
					t.Errorf("refusal log = %q, want no unsafe rune; found %q: a JSON handler "+
						"escapes only what JSON requires, so C1 and Bidi_Control survive unsanitized",
						line, bad)
				}
				if len(line) > maxLogLine {
					t.Errorf("refusal log is %d bytes, want at most %d: refusal volume must not "+
						"track what the caller sent", len(line), maxLogLine)
				}
			}
		})
	}
}

// maxLogLine is the ceiling one refusal record may occupy. It is the sum of the
// widest bounds a single line can carry (a URL plus an error) with room for the
// fixed keys, timestamp and level, and it is deliberately generous: the property
// under test is that the line does not track the 70000-byte input, not that it
// hits any particular size.
const maxLogLine = maxURLLog + maxErrLog + 512
