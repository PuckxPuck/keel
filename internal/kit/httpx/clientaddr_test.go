package httpx_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
)

func TestClientAddress(t *testing.T) {
	nginx := config.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	loopback := config.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	tunnel := netip.MustParseAddr("127.0.0.1")
	tunnelMode := config.Proxy{Edge: config.EdgeCloudflareTunnel, TunnelAddr: tunnel}
	tunnelBehindNginx := config.Proxy{Edge: config.EdgeCloudflareTunnel, TunnelAddr: tunnel, Trusted: loopback}
	socket := &net.UnixAddr{Name: "/run/app/app.sock", Net: "unix"}

	tests := []struct {
		name        string
		proxy       config.Proxy
		remote      string
		local       net.Addr
		headers     http.Header
		wantIP      string
		wantProxied bool
	}{
		{name: "direct", remote: "203.0.113.9:4000", wantIP: "203.0.113.9"},
		{
			name: "forwarded header from an untrusted peer is ignored", proxy: config.Proxy{Trusted: nginx},
			remote: "203.0.113.9:4000", headers: http.Header{"X-Forwarded-For": {"198.51.100.1"}},
			wantIP: "203.0.113.9",
		},
		{
			name: "trusted proxy forwards the client", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"198.51.100.1"}},
			wantIP: "198.51.100.1", wantProxied: true,
		},
		{
			name: "chain stops at the first untrusted hop, not at a spoofed entry", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"9.9.9.9, 198.51.100.1", "10.0.0.2"}},
			wantIP: "198.51.100.1", wantProxied: true,
		},
		{
			name: "trusted proxy without header is the client", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", wantIP: "10.0.0.1", wantProxied: true,
		},
		{
			name: "malformed last entry ends the walk at the verified hop", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"198.51.100.1, not-an-ip"}},
			wantIP: "10.0.0.1", wantProxied: true,
		},
		{
			name: "malformed earlier entry cannot override a verified one", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"198.51.100.1, junk, 10.0.0.2"}},
			wantIP: "10.0.0.2", wantProxied: true,
		},
		{
			name: "ipv6 is normalised", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"2001:DB8:0:0::0001"}},
			wantIP: "2001:db8::1", wantProxied: true,
		},
		{
			name: "ipv4-mapped ipv6 is unmapped", proxy: config.Proxy{Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"::ffff:198.51.100.7"}},
			wantIP: "198.51.100.7", wantProxied: true,
		},
		{
			name: "unix socket peer is unknown unless trusted", proxy: config.Proxy{Trusted: loopback},
			remote: "@", local: socket, headers: http.Header{"X-Forwarded-For": {"198.51.100.1"}},
		},
		{
			name: "trusted unix socket peer forwards the client", proxy: config.Proxy{Trusted: config.TrustedProxies{Unix: true}},
			remote: "@", local: socket, headers: http.Header{"X-Forwarded-For": {"198.51.100.1"}},
			wantIP: "198.51.100.1", wantProxied: true,
		},
		{
			name: "trusted unix socket peer without header stays unknown", proxy: config.Proxy{Trusted: config.TrustedProxies{Unix: true}},
			remote: "@", local: socket, wantProxied: true,
		},
		{
			name: "unix socket peer never matches the tunnel", proxy: tunnelMode,
			remote: "", local: socket, headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1"}},
		},
		{name: "unparseable peer is unknown", proxy: config.Proxy{Trusted: loopback}, remote: "garbage"},
		{
			name: "cloudflare peer is believed", proxy: config.Proxy{Edge: config.EdgeCloudflare},
			remote: "104.16.0.5:443", headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "198.51.100.1", wantProxied: true,
		},
		{
			name: "cloudflare header from a non-cloudflare peer is ignored", proxy: config.Proxy{Edge: config.EdgeCloudflare},
			remote: "203.0.113.9:443", headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "203.0.113.9",
		},
		{
			name: "cloudflare behind a trusted proxy", proxy: config.Proxy{Edge: config.EdgeCloudflare, Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"198.51.100.1, 2606:4700::1"}, "Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "198.51.100.1", wantProxied: true,
		},
		{
			name: "cloudflare header sent straight to the trusted proxy is ignored", proxy: config.Proxy{Edge: config.EdgeCloudflare, Trusted: nginx},
			remote: "10.0.0.1:4000", headers: http.Header{"X-Forwarded-For": {"203.0.113.9"}, "Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "203.0.113.9", wantProxied: true,
		},
		{
			name: "cloudflare header with several values is ignored", proxy: config.Proxy{Edge: config.EdgeCloudflare},
			remote: "104.16.0.5:443", headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1, 198.51.100.2"}},
			wantIP: "104.16.0.5",
		},
		{
			name: "cloudflare header repeated is ignored", proxy: config.Proxy{Edge: config.EdgeCloudflare},
			remote: "104.16.0.5:443", headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1", "198.51.100.2"}},
			wantIP: "104.16.0.5",
		},
		{
			name: "cloudflare header that is not an ip is ignored", proxy: config.Proxy{Edge: config.EdgeCloudflare},
			remote: "104.16.0.5:443", headers: http.Header{"Cf-Connecting-Ip": {"evil"}},
			wantIP: "104.16.0.5",
		},
		{
			name: "tunnel to the app directly is believed", proxy: tunnelMode,
			remote: "127.0.0.1:5000", headers: http.Header{"Cf-Connecting-Ip": {"2001:db8::7"}},
			wantIP: "2001:db8::7", wantProxied: true,
		},
		{
			name: "tunnel through nginx takes the client from the entry cloudflared wrote", proxy: tunnelBehindNginx,
			remote: "127.0.0.1:5000", headers: http.Header{"X-Forwarded-For": {"198.51.100.1, 127.0.0.1"}, "Cf-Connecting-Ip": {"192.0.2.77"}},
			wantIP: "198.51.100.1", wantProxied: true,
		},
		{
			name: "spoofed cloudflare header sent straight to nginx is ignored in tunnel mode", proxy: tunnelBehindNginx,
			remote: "127.0.0.1:5000", headers: http.Header{"X-Forwarded-For": {"203.0.113.9"}, "Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "203.0.113.9", wantProxied: true,
		},
		{
			name: "tunnel header from another peer is ignored", proxy: tunnelMode,
			remote: "192.0.2.50:5000", headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "192.0.2.50",
		},
		{
			name: "cloudflare header is ignored when no edge is configured", proxy: config.Proxy{},
			remote: "104.16.0.5:443", headers: http.Header{"Cf-Connecting-Ip": {"198.51.100.1"}},
			wantIP: "104.16.0.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotIP netip.Addr
			var gotProxied bool
			handler := httpx.ClientAddress(tt.proxy)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotIP, gotProxied = httpx.ClientIP(r.Context()), httpx.Proxied(r.Context())
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			if tt.local != nil {
				req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, tt.local))
			}
			for k, vs := range tt.headers {
				req.Header[k] = vs
			}

			handler.ServeHTTP(httptest.NewRecorder(), req)

			if tt.wantIP == "" {
				assert.False(t, gotIP.IsValid(), "unknown client, got %s", gotIP)
				assert.False(t, gotIP.IsLoopback())
			} else {
				assert.Equal(t, tt.wantIP, gotIP.String())
			}
			assert.Equal(t, tt.wantProxied, gotProxied)
		})
	}
}
