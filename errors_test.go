package ssrf

import (
	"errors"
	"testing"
)

// TestError_Kind verifies each validation failure surfaces the documented
// machine-readable ErrorKind via errors.As(*Error).
func TestError_Kind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		kind ErrorKind
	}{
		{"bad scheme", "http://example.com/f", KindBadScheme},
		{"empty host", "https:///f", KindEmptyHost},
		{"localhost", "https://localhost/f", KindLocalhost},
		{"bare hostname", "https://internal/f", KindBareHostname},
		{"non-public IP", "https://127.0.0.1/f", KindNonPublicIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateURL(tc.url)
			if err == nil {
				t.Fatalf("ValidateURL(%q) = nil, want error", tc.url)
			}
			var ssrfError *Error
			if !errors.As(err, &ssrfError) {
				t.Fatalf("ValidateURL(%q) error is not *Error: %T", tc.url, err)
			}
			if ssrfError.Kind != tc.kind {
				t.Errorf("ValidateURL(%q) error Kind = %d, want %d", tc.url, ssrfError.Kind, tc.kind)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	t.Parallel()
	err := ValidateURL("not a url at all ://")
	if err == nil {
		t.Skip("URL parsed without error")
	}
	var ssrfError *Error
	if errors.As(err, &ssrfError) {
		// KindInvalidURL should wrap the url.Parse error
		if ssrfError.Kind == KindInvalidURL && ssrfError.Err == nil {
			t.Error("KindInvalidURL should wrap underlying parse error")
		}
	}
}

func TestError_Unwrap_chain(t *testing.T) {
	t.Parallel()
	base := errors.New("dns boom")
	err := ssrfErr(KindDNSFailed, "h", "lookup failed", base)
	if !errors.Is(err, base) {
		t.Errorf("errors.Is(ssrfErr(..., base), base) = false, want true")
	}
	if got := errors.Unwrap(err); got != base {
		t.Errorf("errors.Unwrap(err) = %v, want %v", got, base)
	}
	plain := ssrfErr(KindBadScheme, "", "no underlying", nil)
	if got := errors.Unwrap(plain); got != nil {
		t.Errorf("errors.Unwrap(plain) = %v, want nil", got)
	}
}

// TestErrorKind_constants_distinct_and_nonzero verifies the iota-based Kind
// constants stay distinct and non-zero (a zero Kind would collide with the
// unset value an unwrapped error reports).
func TestErrorKind_constants_distinct_and_nonzero(t *testing.T) {
	t.Parallel()
	kinds := []ErrorKind{
		KindInvalidURL, KindBadScheme, KindEmptyHost, KindLocalhost,
		KindBareHostname, KindNonPublicIP, KindDNSFailed, KindPolicyDenied,
		KindBadPort, KindTooManyRedirects,
	}
	seen := make(map[ErrorKind]bool, len(kinds))
	for _, k := range kinds {
		if k == 0 {
			t.Errorf("Kind constant has zero value")
		}
		if seen[k] {
			t.Errorf("duplicate Kind value: %d", k)
		}
		seen[k] = true
	}
}

func TestReasonLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want string
		kind ErrorKind
	}{
		{"invalid url", "invalid_url", KindInvalidURL},
		{"bad scheme", "scheme", KindBadScheme},
		{"empty host", "empty_host", KindEmptyHost},
		{"localhost", "localhost", KindLocalhost},
		{"bare hostname", "bare_hostname", KindBareHostname},
		{"non public ip", "non_public_ip", KindNonPublicIP},
		{"dns failed", "dns_failed", KindDNSFailed},
		{"policy denied", "policy_denied", KindPolicyDenied},
		{"bad port", "bad_port", KindBadPort},
		{"too many redirects", "too_many_redirects", KindTooManyRedirects},
		{"unknown zero value", "blocked", ErrorKind(0)},
		{"unknown high value", "blocked", ErrorKind(999)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := reasonLabel(tc.kind); got != tc.want {
				t.Errorf("reasonLabel(%d) = %q, want %q", tc.kind, got, tc.want)
			}
		})
	}
}

func TestReasonLabel_exhaustive(t *testing.T) {
	t.Parallel()
	seen := make(map[string]ErrorKind)
	for k := KindInvalidURL; k <= KindTooManyRedirects; k++ {
		label := reasonLabel(k)
		if label == "blocked" {
			t.Errorf("reasonLabel(%d) hit the default %q; add a dedicated case", k, label)
		}
		if prev, dup := seen[label]; dup {
			t.Errorf("label %q reused by kinds %d and %d", label, prev, k)
		}
		seen[label] = k
	}
}
