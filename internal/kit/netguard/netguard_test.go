package netguard_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/netguard"
)

func TestAllowed(t *testing.T) {
	cases := map[string]bool{
		// Each blocked IPv4 range: its first and last address and the allowed neighbours around it.
		"0.0.0.0": false, "0.255.255.255": false, "1.0.0.0": true,
		"9.255.255.255": true, "10.0.0.0": false, "10.255.255.255": false, "11.0.0.0": true,
		"100.63.255.255": true, "100.64.0.0": false, "100.127.255.255": false, "100.128.0.0": true,
		"126.255.255.255": true, "127.0.0.0": false, "127.255.255.255": false, "128.0.0.0": true,
		"168.63.129.15": true, "168.63.129.16": false, "168.63.129.17": true,
		"169.253.255.255": true, "169.254.0.0": false, "169.254.169.254": false, "169.254.255.255": false, "169.255.0.0": true,
		"172.15.255.255": true, "172.16.0.0": false, "172.31.255.255": false, "172.32.0.0": true,
		"191.255.255.255": true, "192.0.0.0": false, "192.0.0.9": false, "192.0.0.255": false, "192.0.1.0": true,
		"192.0.1.255": true, "192.0.2.0": false, "192.0.2.255": false, "192.0.3.0": true,
		"192.88.98.255": true, "192.88.99.0": false, "192.88.99.255": false, "192.88.100.0": true,
		"192.167.255.255": true, "192.168.0.0": false, "192.168.255.255": false, "192.169.0.0": true,
		"198.17.255.255": true, "198.18.0.0": false, "198.19.255.255": false, "198.20.0.0": true,
		"198.51.99.255": true, "198.51.100.0": false, "198.51.100.255": false, "198.51.101.0": true,
		"203.0.112.255": true, "203.0.113.0": false, "203.0.113.255": false, "203.0.114.0": true,
		"223.255.255.255": true, "224.0.0.0": false, "239.255.255.255": false, "240.0.0.0": false, "255.255.255.255": false,
		"8.8.8.8": true,

		// IPv6: only 2000::/3, minus the blocked ranges inside it.
		"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": false, "2000::": true,
		"2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff": true, "2001::": false, "2001:0:4136:e378::1": false, "2001:2::1": false,
		"2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff": false, "2001:200::": true,
		"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff": true, "2001:db8::": false, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff": false, "2001:db9::": true,
		"2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff": true, "2002::": false, "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff": false, "2003::": true,
		"3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff": true, "3fff::": false, "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff": false, "3fff:1000::": true,
		"3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": true, "4000::": false,
		"2606:4700:4700::1111": true, "5f00::1": false, "64:ff9b::808:808": false, "64:ff9b:1::1": false, "100::1": false,
		"fc00::1": false, "fd00:ec2::254": false, "fe80::1": false, "fec0::1": false, "ff02::1": false, "::": false, "::1": false,

		// Embedded IPv4 is judged as IPv4.
		"::ffff:8.8.8.8": true, "::ffff:127.0.0.1": false, "::ffff:10.0.0.1": false, "::8.8.8.8": true, "::7f00:1": false, "::a00:1": false,

		// A zone is never allowed.
		"::1%lo0": false, "fe80::1%eth0": false, "fd00::1%x": false, "2606:4700:4700::1111%eth0": false,
	}
	for addr, want := range cases {
		assert.Equal(t, want, netguard.Allowed(netip.MustParseAddr(addr)), addr)
	}
	assert.False(t, netguard.Allowed(netip.Addr{}))
}

var loopback = netip.MustParsePrefix("127.0.0.1/32")

func TestDialer_ResolvesOnceAndRefusesAnyBlockedAddress(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/inside", http.StatusFound)
		}
	}))
	defer srv.Close()
	port := netip.MustParseAddrPort(srv.Listener.Addr().String()).Port()

	var lookups atomic.Int64
	rebinding := func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	client := netguard.NewDialer(5*time.Second, netguard.Lookup(rebinding), netguard.Permit(loopback)).Client(5 * time.Second)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://rebind.test:%d/redirect", port), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "redirects are not followed")
	assert.Equal(t, int64(1), hits.Load())
	assert.Equal(t, int64(1), lookups.Load(), "the connection went to the address that was checked")

	cases := map[string][]string{
		"private":               {"10.0.0.1"},
		"metadata":              {"169.254.169.254"},
		"one public, one local": {"8.8.8.8", "127.0.0.2"},
		"ula":                   {"fd00::1"},
	}
	for name, addrs := range cases {
		lookup := func(context.Context, string) ([]netip.Addr, error) {
			out := make([]netip.Addr, len(addrs))
			for i, a := range addrs {
				out[i] = netip.MustParseAddr(a)
			}
			return out, nil
		}
		_, err := netguard.NewDialer(time.Second, netguard.Lookup(lookup), netguard.Permit(loopback)).DialContext(t.Context(), "tcp", "victim.test:443")
		require.ErrorIs(t, err, netguard.ErrBlocked, name)
	}
	for _, literal := range []string{"127.0.0.1:443", "[::1%lo0]:443", "[fe80::1%25eth0]:443"} {
		_, err = netguard.NewDialer(time.Second).DialContext(t.Context(), "tcp", literal)
		require.ErrorIs(t, err, netguard.ErrBlocked, literal)
	}
	require.ErrorIs(t, netguard.HostAllowed("[::1%lo0]"), netguard.ErrBlocked)
	require.ErrorIs(t, netguard.HostAllowed("10.0.0.1"), netguard.ErrBlocked)
	require.NoError(t, netguard.HostAllowed("example.com"))
}
