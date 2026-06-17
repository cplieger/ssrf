package ssrf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// budgetResolver answers a DNS lookup only when the context it is handed
// carries at least minBudget of remaining time. It lets a test assert the
// size of the DNS-lookup timeout budget that safeDialContext grants, without
// depending on wall-clock sleeps.
type budgetResolver struct {
	minBudget time.Duration
	ips       []netip.Addr
}

func (b budgetResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	dl, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("DNS context carried no deadline")
	}
	if remaining := time.Until(dl); remaining < b.minBudget {
		return nil, fmt.Errorf("DNS budget too short: %v remaining, need >= %v", remaining, b.minBudget)
	}
	return b.ips, nil
}

// safeDialContext must give the DNS lookup a generous (5s) timeout budget.
// A resolver that needs at least 1s of budget succeeds under real code but
// fails if the 5*time.Second budget is shrunk to 5/time.Second (== 0), which
// would make every DNS lookup time out immediately.
func TestSafeDialContext_gives_dns_lookup_a_generous_budget(t *testing.T) {
	t.Parallel()

	// given: a resolver that only answers with a >=1s budget, returning a
	// loopback IP that passes an allow-all policy.
	allowAll := func(netip.Addr) bool { return true }
	r := budgetResolver{minBudget: time.Second, ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	dial := safeDialContext(&net.Dialer{Timeout: 250 * time.Millisecond}, allowAll, r, map[uint16]struct{}{1: {}})

	// when: dialing through the SSRF dialer (DNS context gets a 5s budget).
	_, err := dial(context.Background(), "tcp", "slow-dns.example:1")

	// then: the lookup had enough budget to succeed, so the failure comes from
	// the loopback dial, NOT a DNS timeout. A shrunk 0s budget would surface as
	// KindDNSFailed instead.
	if err == nil {
		t.Fatalf("dial(slow-dns.example:1) = nil err, want a dial failure on loopback:1")
	}
	var sErr *Error
	if errors.As(err, &sErr) && sErr.Kind == KindDNSFailed {
		t.Errorf("dial(slow-dns.example:1) = KindDNSFailed (%v); want the DNS lookup to succeed under the 5s budget", err)
	}
}

// loopbackIPs builds n distinct 127.0.0.x addresses for dial-cap fixtures.
func loopbackIPs(n int) []netip.Addr {
	ips := make([]netip.Addr, n)
	for i := range ips {
		ips[i] = netip.AddrFrom4([4]byte{127, 0, 0, byte(i + 1)})
	}
	return ips
}

// safeDialContext caps dial attempts only when the resolved set is strictly
// larger than maxDialIPs. At exactly maxDialIPs the full set is dialed and no
// "ssrf dial capped" warning is emitted; one IP over the limit triggers the
// cap and the warning. This pins the boundary so flipping `>` to `>=` (which
// would cap and warn at exactly maxDialIPs) is caught.
//
// Not parallel: it swaps slog.Default() to capture the cap warning.
func TestSafeDialContext_caps_dial_attempts_only_above_maxDialIPs(t *testing.T) {
	allowAll := func(netip.Addr) bool { return true }

	cases := []struct {
		name     string
		resolved int
		wantCap  bool
	}{
		{"exactly maxDialIPs is not capped", maxDialIPs, false},
		{"one over maxDialIPs is capped", maxDialIPs + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			r := &mockResolver{ips: loopbackIPs(tc.resolved)}
			dial := safeDialContext(&net.Dialer{Timeout: 100 * time.Millisecond}, allowAll, r, map[uint16]struct{}{1: {}})

			_, _ = dial(context.Background(), "tcp", "many.example:1")

			gotCap := strings.Contains(buf.String(), "ssrf dial capped")
			if gotCap != tc.wantCap {
				t.Errorf("resolved=%d: %q logged = %v, want %v (log=%q)", tc.resolved, "ssrf dial capped", gotCap, tc.wantCap, buf.String())
			}
		})
	}
}
