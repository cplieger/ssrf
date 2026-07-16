package ssrf_test

import (
	"fmt"
	"net/http"

	"github.com/cplieger/ssrf/v3"
)

func ExampleValidateURL() {
	err := ssrf.ValidateURL("https://example.com/data.json")
	fmt.Println(err)
	// Output: <nil>
}

func ExampleSafeTransport() {
	client := &http.Client{
		Transport: ssrf.SafeTransport(),
	}
	_ = client // use client for outbound requests
}

func ExampleSafeRedirectPolicy() {
	client := &http.Client{
		Transport:     ssrf.SafeTransport(),
		CheckRedirect: ssrf.SafeRedirectPolicy(nil),
	}
	_ = client // use client for outbound requests
}

func ExampleURLPolicy() {
	// Allow plain HTTP alongside HTTPS (e.g. for legacy endpoints).
	policy := ssrf.NewURLPolicy("https", "http")
	client := &http.Client{
		Transport:     ssrf.SafeTransport(ssrf.WithAllowedPorts(443, 80)),
		CheckRedirect: policy.RedirectPolicy(nil),
	}
	_ = client
	fmt.Println(policy.Validate("https://example.com/data.json"))
	// Output: <nil>
}
