//go:build linux

package ssrf

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"
)

// gk_ssrf_u1_resolver is a fixed Resolver that returns the same IP set for any
// queried name, so a test can drive SafeTransport's DEFAULT dialer at a local
// loopback listener without any real DNS.
type gk_ssrf_u1_resolver struct{ ips []netip.Addr }

func (r gk_ssrf_u1_resolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return r.ips, nil
}

// gk_ssrf_u1_keepIdle reads the kernel TCP keep-alive idle period (seconds)
// configured on an established client connection. On Linux a net.Dialer with
// KeepAlive=d sets TCP_KEEPIDLE to d truncated to whole seconds; with
// KeepAlive==0 Go falls back to its 15s default (verified on go1.26).
func gk_ssrf_u1_keepIdle(t *testing.T, c net.Conn) int {
	t.Helper()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("conn type = %T, want *net.TCPConn", c)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() error = %v", err)
	}
	var idle int
	var getErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		idle, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
	}); ctrlErr != nil {
		t.Fatalf("RawConn.Control() error = %v", ctrlErr)
	}
	if getErr != nil {
		t.Fatalf("getsockopt(TCP_KEEPIDLE) error = %v", getErr)
	}
	return idle
}

// TestGkSsrfU1_SafeTransport_defaultDialerKeepAlive pins the KeepAlive value of
// the DEFAULT net.Dialer that SafeTransport builds when no WithDialer option is
// supplied (ssrf.go: `KeepAlive: 30 * time.Second`).
//
// That dialer is sealed inside the safeDialContext closure and is not a field
// on the returned *http.Transport, so its value is observed the only way it is
// observable in-process: by dialing a loopback listener through the transport's
// own DialContext (default dialer, fake resolver -> 127.0.0.1, allow-all policy,
// all ports) and reading the resulting socket's TCP_KEEPIDLE.
//
// Kills the ARITHMETIC_BASE mutant on the `*` in `30 * time.Second`: the
// original yields TCP_KEEPIDLE == 30; the mutated `30 / time.Second` == 0
// yields Go's 15s default (and any other arithmetic mutation yields some value
// != 30), so the exact-30 assertion below distinguishes original from mutant.
func TestGkSsrfU1_SafeTransport_defaultDialerKeepAlive(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Accept (and retain) server-side conns so the loopback handshake reliably
	// completes; close them on cleanup. The accept goroutine exits when the
	// listener is closed.
	var mu sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range accepted {
			_ = c.Close()
		}
		mu.Unlock()
	})

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", ln.Addr().String(), err)
	}

	// No WithDialer => SafeTransport uses its DEFAULT dialer (the line under
	// test). Fake resolver pins every host to loopback; allow-all policy and
	// all-ports open the dial path to the local listener.
	allowAll := func(netip.Addr) bool { return true }
	r := gk_ssrf_u1_resolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	tr := SafeTransport(WithResolver(r), WithPolicy(allowAll), WithAllowedPorts())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tr.DialContext(ctx, "tcp", net.JoinHostPort("gk-ssrf-u1.invalid", portStr))
	if err != nil {
		t.Fatalf("SafeTransport().DialContext(loopback) error = %v, want a successful dial", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	const want = 30 // seconds == 30 * time.Second
	if got := gk_ssrf_u1_keepIdle(t, conn); got != want {
		t.Errorf("SafeTransport default dialer TCP_KEEPIDLE = %d, want %d "+
			"(KeepAlive: 30*time.Second; a shrunk `30/time.Second`==0 yields the 15s Go default)", got, want)
	}
}
