package ssrf_test

import (
	"fmt"
	"net/http"

	"github.com/cplieger/ssrf/v2"
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
