package devlogin_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"

	"github.com/PuckxPuck/keel/internal/kit/auth/devlogin"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
)

func TestGate(t *testing.T) {
	tests := []struct {
		name    string
		env     config.Env
		addr    string
		enabled bool
		ok      bool
	}{
		{"off anywhere", config.EnvProduction, "0.0.0.0:8080", false, true},
		{"local on loopback", config.EnvLocal, "127.0.0.1:8080", true, true},
		{"local on localhost", config.EnvLocal, "localhost:8080", true, true},
		{"local on IPv6 loopback", config.EnvLocal, "[::1]:8080", true, true},
		{"test env", config.EnvTest, "127.0.0.1:8080", true, false},
		{"production", config.EnvProduction, "127.0.0.1:8080", true, false},
		{"all interfaces", config.EnvLocal, "0.0.0.0:8080", true, false},
		{"unix socket", config.EnvLocal, "unix:/run/app.sock", true, false},
	}
	for _, tt := range tests {
		err := devlogin.Gate(tt.env, tt.enabled, tt.addr)
		assert.Equal(t, tt.ok, err == nil, tt.name)
	}
}

// The request gate: a loopback client, a loopback Host and no forwarding header. A tunnel or local
// proxy in front of the dev server shows up as a loopback peer with a public Host or a forwarding
// header, and is refused.
func TestMiddleware_OnlyAStraightLoopbackRequest(t *testing.T) {
	trusted := config.Proxy{Trusted: config.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}
	tests := []struct {
		name    string
		proxy   config.Proxy
		remote  string
		host    string
		headers map[string]string
		want    bool
	}{
		{"loopback client on localhost", config.Proxy{}, "127.0.0.1:5000", "localhost:8080", nil, true},
		{"IPv6 loopback client on [::1]", config.Proxy{}, "[::1]:5000", "[::1]:8080", nil, true},
		{"on 127.0.0.1 without a port", config.Proxy{}, "127.0.0.1:5000", "127.0.0.1", nil, true},
		{"on a .localhost name", config.Proxy{}, "127.0.0.1:5000", "app.localhost:8080", nil, true},
		{"remote client", config.Proxy{}, "203.0.113.9:5000", "localhost:8080", nil, false},
		{"tunnel: loopback peer, public Host", config.Proxy{}, "127.0.0.1:5000", "abc123.ngrok.app", nil, false},
		{"tunnel: loopback peer, X-Forwarded-For", config.Proxy{}, "127.0.0.1:5000", "localhost:8080", map[string]string{"X-Forwarded-For": "203.0.113.9"}, false},
		{"tunnel: X-Forwarded-Host", config.Proxy{}, "127.0.0.1:5000", "localhost:8080", map[string]string{"X-Forwarded-Host": "abc.trycloudflare.com"}, false},
		{"Cloudflare's client header", config.Proxy{}, "127.0.0.1:5000", "localhost:8080", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"}, false},
		{"Forwarded", config.Proxy{}, "127.0.0.1:5000", "localhost:8080", map[string]string{"Forwarded": "for=203.0.113.9"}, false},
		{"X-Real-IP", config.Proxy{}, "127.0.0.1:5000", "localhost:8080", map[string]string{"X-Real-IP": "203.0.113.9"}, false},
		{"through a trusted local proxy", trusted, "127.0.0.1:5000", "localhost:8080", map[string]string{"X-Forwarded-For": "127.0.0.1"}, false},
		{"another loopback address as Host", config.Proxy{}, "127.0.0.1:5000", "127.0.0.2:8080", nil, false},
		{"bare IPv6 Host", config.Proxy{}, "[::1]:5000", "::1", nil, false},
	}
	for _, tt := range tests {
		var got bool
		h := httpx.ClientAddress(tt.proxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			devlogin.Middleware(humatest.NewContext(&huma.Operation{}, r, w), func(hctx huma.Context) {
				got = devlogin.Allowed(hctx.Context())
			})
		}))
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
		r.RemoteAddr, r.Host = tt.remote, tt.host
		for k, v := range tt.headers {
			r.Header.Set(k, v)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		assert.Equal(t, tt.want, got, tt.name)
	}
	assert.False(t, devlogin.Allowed(t.Context()), "without the middleware nothing is allowed")
}
