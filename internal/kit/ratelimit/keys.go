package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// Headers reads request headers; huma.Context satisfies it.
type Headers interface {
	Header(name string) string
}

// KeyFunc names the bucket a request counts against.
type KeyFunc func(ctx context.Context, h Headers) string

// ByAddress keys by client address, IPv6 by its /64 so one host cannot rotate through its own block.
func ByAddress(ctx context.Context, _ Headers) string {
	return "a:" + prefixed(httpx.ClientIP(ctx), 32, 64)
}

// ByNetwork keys by the client's /24 (IPv4) or /48 (IPv6).
func ByNetwork(ctx context.Context, _ Headers) string {
	return "n:" + prefixed(httpx.ClientIP(ctx), 24, 48)
}

// ByPrincipal keys by the signed-in user, falling back to the address for anonymous callers.
func ByPrincipal(principals rbac.Principals) KeyFunc {
	return func(ctx context.Context, h Headers) string {
		if p, ok := principals.Principal(ctx); ok {
			return p.Key()
		}
		return ByAddress(ctx, h)
	}
}

// ByHeaderToken keys by a hash of a header's value (an API key, a device token), never the value itself.
func ByHeaderToken(header string) KeyFunc {
	return func(ctx context.Context, h Headers) string {
		v := h.Header(header)
		if v == "" {
			return ByAddress(ctx, h)
		}
		return "t:" + digest(v)
	}
}

func prefixed(ip netip.Addr, v4, v6 int) string {
	if !ip.IsValid() {
		return "unknown"
	}
	bits := v6
	if ip.Is4() {
		bits = v4
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return "unknown"
	}
	return p.String()
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
