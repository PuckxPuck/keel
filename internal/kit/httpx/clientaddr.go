package httpx

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

//go:generate go run ../../../tools/cfranges/main.go -out cloudflare_ranges.go

const headerCFConnectingIP = "CF-Connecting-IP"

type clientKey struct{}

type client struct {
	ip         netip.Addr
	proxied    bool
	localProxy bool
}

// ClientIP is the one place code learns who is calling. It is the zero Addr, which is never loopback,
// when the client is unknown: an untrusted unix socket peer, or outside a ClientAddress chain.
func ClientIP(ctx context.Context) netip.Addr {
	c, _ := ctx.Value(clientKey{}).(client)
	return c.ip
}

// Proxied is true when the request arrived through a trusted proxy or a configured edge.
func Proxied(ctx context.Context) bool {
	c, _ := ctx.Value(clientKey{}).(client)
	return c.proxied
}

// LocalProbe is true when the client is on loopback, or the request came through a trusted proxy on
// this host (loopback or a trusted unix socket): the way health probes arrive.
func LocalProbe(ctx context.Context) bool {
	c, _ := ctx.Value(clientKey{}).(client)
	return c.ip.IsLoopback() || c.localProxy
}

// ClientAddress resolves the client once per request and puts it in the context and log attributes.
func ClientAddress(cfg config.Proxy) func(http.Handler) http.Handler {
	res := resolver{
		trusted:   slices.Clone(cfg.Trusted.Prefixes),
		trustUnix: cfg.Trusted.Unix,
		edge:      cfg.Edge,
		tunnel:    normalise(cfg.TunnelAddr),
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, proxied := res.resolve(r)
			logged := "unknown"
			if ip.IsValid() {
				logged = ip.String()
			}
			c := client{ip: ip, proxied: proxied, localProxy: res.localTrustedPeer(r)}
			ctx := context.WithValue(r.Context(), clientKey{}, c)
			ctx = logx.With(ctx, slog.String(logx.KeyClientIP, logged))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type resolver struct {
	trusted   []netip.Prefix
	trustUnix bool
	edge      config.ProxyEdge
	tunnel    netip.Addr
}

// resolve walks X-Forwarded-For from the right while the hop is a trusted proxy; a malformed
// entry ends the walk at the last verified hop. The edge header is consulted only for the hop
// where the walk stopped, never for a hop it passed through.
func (res resolver) resolve(r *http.Request) (ip netip.Addr, proxied bool) {
	hop, trusted := res.peer(r)
	forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	for trusted {
		proxied = true
		next, rest, ok := lastForwarded(forwarded)
		if !ok {
			break
		}
		hop, forwarded, trusted = next, rest, res.isTrusted(next)
	}
	if edgeIP, ok := res.edgeClient(r, hop); ok {
		return edgeIP, true
	}
	return hop, proxied
}

// peer is the connection's address and whether it is a trusted proxy. A unix socket peer has no address.
func (res resolver) peer(r *http.Request) (netip.Addr, bool) {
	if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && local.Network() == "unix" {
		return netip.Addr{}, res.trustUnix
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip := normalise(ap.Addr())
	return ip, res.isTrusted(ip)
}

func (res resolver) localTrustedPeer(r *http.Request) bool {
	hop, trusted := res.peer(r)
	return trusted && (!hop.IsValid() || hop.IsLoopback())
}

func (res resolver) isTrusted(ip netip.Addr) bool {
	return slices.ContainsFunc(res.trusted, func(p netip.Prefix) bool { return p.Contains(ip) })
}

func (res resolver) edgeClient(r *http.Request, hop netip.Addr) (netip.Addr, bool) {
	if !hop.IsValid() {
		return netip.Addr{}, false
	}
	switch res.edge {
	case config.EdgeCloudflare:
		if !slices.ContainsFunc(cloudflareRanges, func(p netip.Prefix) bool { return p.Contains(hop) }) {
			return netip.Addr{}, false
		}
	case config.EdgeCloudflareTunnel:
		if !res.tunnel.IsValid() || hop != res.tunnel {
			return netip.Addr{}, false
		}
	case config.EdgeNone:
		return netip.Addr{}, false
	default:
		return netip.Addr{}, false
	}
	values := r.Header.Values(headerCFConnectingIP)
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	return parseClient(values[0])
}

func lastForwarded(list string) (ip netip.Addr, rest string, ok bool) {
	if strings.TrimSpace(list) == "" {
		return netip.Addr{}, "", false
	}
	entry := list
	if i := strings.LastIndexByte(list, ','); i >= 0 {
		entry, rest = list[i+1:], list[:i]
	}
	ip, ok = parseClient(entry)
	return ip, rest, ok
}

func parseClient(s string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return normalise(ip), true
}

func normalise(ip netip.Addr) netip.Addr { return ip.Unmap().WithZone("") }
