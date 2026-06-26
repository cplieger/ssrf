package ssrf

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// newTestReq builds a GET request for redirect-policy tests.
func newTestReq(rawURL string) (*http.Request, error) {
	return http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
}

func TestSafeRedirectPolicy_blocks_private_redirect(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("https://192.168.1.77/internal")
	err := policy(req, nil)
	if err == nil {
		t.Error("SafeRedirectPolicy() = nil, want error for private redirect")
	}
}

func TestSafeRedirectPolicy_blocks_http_downgrade(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("http://example.com/file.txt")
	err := policy(req, nil)
	if err == nil {
		t.Error("SafeRedirectPolicy() = nil, want error for http scheme downgrade")
	}
}

func TestSafeRedirectPolicy_allows_public_redirect(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("https://cdn.example.com/file.txt")
	err := policy(req, nil)
	if err != nil {
		t.Errorf("SafeRedirectPolicy() = %v, want nil for public redirect", err)
	}
}

func TestSafeRedirectPolicy_stops_after_10_redirects(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("https://example.com/file")
	via := make([]*http.Request, 10)
	err := policy(req, via)
	if err == nil {
		t.Error("SafeRedirectPolicy() = nil, want error after 10 redirects")
	}
}

// The hop-cap denial must report KindTooManyRedirects, not a blanket
// KindNonPublicIP — "stopped after N redirects" is not an IP condition.
func TestSafeRedirectPolicy_hop_cap_kind(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("https://example.com/file")
	via := make([]*http.Request, maxRedirects)
	err := policy(req, via)

	var ssrfErr *Error
	if !errors.As(err, &ssrfErr) {
		t.Fatalf("SafeRedirectPolicy() error = %v, want *ssrf.Error", err)
	}
	if ssrfErr.Kind != KindTooManyRedirects {
		t.Errorf("hop-cap denial Kind = %v, want KindTooManyRedirects", ssrfErr.Kind)
	}
}

// A redirect blocked because the target URL failed validation must propagate
// the inner Kind (e.g. KindBadScheme for an http downgrade) so callers
// inspecting errors.As(&ssrf.Error).Kind see the real reason.
func TestSafeRedirectPolicy_propagates_inner_kind(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	cases := []struct {
		name string
		url  string
		want ErrorKind
	}{
		{"http downgrade", "http://example.com/file.txt", KindBadScheme},
		{"private IP", "https://192.168.1.77/internal", KindNonPublicIP},
		{"bare hostname", "https://internal/file", KindBareHostname},
		{"localhost", "https://localhost/file", KindLocalhost},
		{"empty host", "https:///file", KindEmptyHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, _ := newTestReq(tc.url)
			err := policy(req, nil)
			var ssrfErr *Error
			if !errors.As(err, &ssrfErr) {
				t.Fatalf("SafeRedirectPolicy(%q) error = %v, want *ssrf.Error", tc.url, err)
			}
			if ssrfErr.Kind != tc.want {
				t.Errorf("SafeRedirectPolicy(%q) Kind = %v, want %v", tc.url, ssrfErr.Kind, tc.want)
			}
		})
	}
}

// Even when a caller supplies a custom next, the 10-redirect cap must
// still apply — next could be a trivial passthrough that has no cap.
func TestSafeRedirectPolicy_caps_redirects_with_custom_next(t *testing.T) {
	t.Parallel()
	called := false
	next := func(_ *http.Request, _ []*http.Request) error {
		called = true
		return nil
	}
	policy := SafeRedirectPolicy(next)
	req, _ := newTestReq("https://example.com/file")
	via := make([]*http.Request, 10)
	err := policy(req, via)
	if err == nil {
		t.Error("SafeRedirectPolicy() with custom next = nil, want error at 10-redirect cap")
	}
	if called {
		t.Error("SafeRedirectPolicy() called next past the 10-redirect cap")
	}
}

func TestSafeRedirectPolicy_delegates_to_next(t *testing.T) {
	t.Parallel()
	called := false
	next := func(_ *http.Request, _ []*http.Request) error {
		called = true
		return nil
	}
	policy := SafeRedirectPolicy(next)
	req, _ := newTestReq("https://example.com/file")
	err := policy(req, nil)
	if err != nil {
		t.Errorf("SafeRedirectPolicy() = %v, want nil", err)
	}
	if !called {
		t.Error("SafeRedirectPolicy() did not call next function")
	}
}

func TestSafeRedirectPolicy_propagates_next_error(t *testing.T) {
	t.Parallel()
	nextErr := errors.New("custom redirect policy error")
	next := func(_ *http.Request, _ []*http.Request) error {
		return nextErr
	}
	policy := SafeRedirectPolicy(next)
	req, _ := newTestReq("https://example.com/file")
	err := policy(req, nil)
	if !errors.Is(err, nextErr) {
		t.Errorf("SafeRedirectPolicy() = %v, want %v", err, nextErr)
	}
}

func TestSafeRedirectPolicy_nil_next_under_limit_allows(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicy(nil)
	req, _ := newTestReq("https://example.com/file")
	via := make([]*http.Request, 5) // under 10
	err := policy(req, via)
	if err != nil {
		t.Errorf("SafeRedirectPolicy(nil) with %d redirects = %v, want nil", len(via), err)
	}
}

func TestSafeRedirectPolicyWithSchemes_blocks_disallowed(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}}
	policy := SafeRedirectPolicyWithSchemes(schemes, nil)
	req, _ := newTestReq("http://example.com/f")
	err := policy(req, nil)
	if err == nil {
		t.Error("redirect to http should be blocked")
	}
}

func TestSafeRedirectPolicyWithSchemes_allows_configured(t *testing.T) {
	t.Parallel()
	schemes := map[string]struct{}{"https": {}, "http": {}}
	policy := SafeRedirectPolicyWithSchemes(schemes, nil)
	req, _ := newTestReq("http://example.com/f")
	err := policy(req, nil)
	if err != nil {
		t.Errorf("redirect to http should be allowed, got: %v", err)
	}
}

func TestSafeRedirectPolicyWithSchemes_caps_and_delegates(t *testing.T) {
	t.Parallel()
	called := false
	next := func(_ *http.Request, _ []*http.Request) error {
		called = true
		return nil
	}
	policy := SafeRedirectPolicyWithSchemes(nil, next)

	req, _ := newTestReq("https://example.com/file")
	via := make([]*http.Request, 10)
	if err := policy(req, via); err == nil {
		t.Error("SafeRedirectPolicyWithSchemes() = nil, want error at 10-redirect cap")
	}
	if called {
		t.Error("next called past the 10-redirect cap")
	}

	// Under the cap, a valid https public target delegates to next.
	if err := policy(req, nil); err != nil {
		t.Errorf("SafeRedirectPolicyWithSchemes() = %v, want nil under cap", err)
	}
	if !called {
		t.Error("SafeRedirectPolicyWithSchemes() did not delegate to next under cap")
	}
}

func TestAllowedSchemes_helper(t *testing.T) {
	t.Parallel()
	s := AllowedSchemes(WithAllowedSchemes("http", "https"))
	if _, ok := s["http"]; !ok {
		t.Error("AllowedSchemes should include http")
	}
	if _, ok := s["https"]; !ok {
		t.Error("AllowedSchemes should include https")
	}
}

func TestWithAllowedSchemes_empty_retains_default(t *testing.T) {
	t.Parallel()
	s := AllowedSchemes(WithAllowedSchemes())
	if _, ok := s["https"]; !ok {
		t.Errorf("AllowedSchemes(WithAllowedSchemes()) = %v, want https retained", s)
	}
	if len(s) != 1 {
		t.Errorf("empty WithAllowedSchemes widened the set to %v, want {https}", s)
	}
}

// A nil Option element in the AllowedSchemes variadic must be skipped, not
// dereferenced (which would panic), and must not disturb the resulting set.
func TestNilOption_AllowedSchemes(t *testing.T) {
	t.Parallel()
	s := AllowedSchemes(nil, nil, WithAllowedSchemes("https", "http"), nil)
	if s == nil {
		t.Fatal("AllowedSchemes with nil elements returned nil")
	}
	if _, ok := s["https"]; !ok {
		t.Error("missing https in result")
	}
	if _, ok := s["http"]; !ok {
		t.Error("missing http in result")
	}
}

// A nil schemes map passed to SafeRedirectPolicyWithSchemes must default to
// HTTPS-only (block http, allow https), and a nil next must be tolerated.
func TestNilOption_SafeRedirectPolicyWithSchemes(t *testing.T) {
	t.Parallel()
	policy := SafeRedirectPolicyWithSchemes(nil, nil)
	req, _ := newTestReq("http://example.com/evil")
	if err := policy(req, nil); err == nil {
		t.Error("nil schemes map should default to HTTPS-only, blocking http")
	}
	req2, _ := newTestReq("https://example.com/ok")
	if err := policy(req2, nil); err != nil {
		t.Errorf("HTTPS to public domain should pass, got: %v", err)
	}
}
