package ssrf

import "testing"

// TestNilOptionElement ensures a nil Option in the variadic slice is skipped
// rather than dereferenced (which would panic).
func TestNilOptionElement(t *testing.T) {
	if tr := SafeTransport(nil, WithAllowedPorts(443)); tr == nil {
		t.Fatal("SafeTransport(nil, ...) returned nil")
	}
	if s := AllowedSchemes(nil, WithAllowedSchemes("https")); s == nil {
		t.Fatal("AllowedSchemes(nil, ...) returned nil")
	}
}
