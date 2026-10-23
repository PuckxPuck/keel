// Package devlogin signs a developer in as any user without a password, behind gates at two levels:
// config refuses it outside local and off a loopback listener, and each request must come from a
// loopback client, name a loopback host, and carry no forwarding header, so a tunnel or local proxy
// in front of the dev server cannot expose it.
package devlogin

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
)

// Gate is the config check: dev login only in local, and only on a loopback listener.
func Gate(env config.Env, enabled bool, listenAddr string) error {
	if !enabled {
		return nil
	}
	var errs []error
	if env != config.EnvLocal {
		errs = append(errs, errors.New("dev login is only allowed with ENV=local"))
	}
	if !loopbackListener(listenAddr) {
		errs = append(errs, errors.New("dev login needs a loopback listener such as 127.0.0.1:8080"))
	}
	return errors.Join(errs...)
}

func loopbackListener(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && loopbackName(host)
}

// forwardingHeaders are set by proxies and tunnels; any of them means the request did not come
// straight from this machine. They are only checked for presence, never believed.
var forwardingHeaders = []string{
	"Forwarded", "X-Real-Ip", "Cf-Connecting-Ip", "True-Client-Ip", "X-Original-Host",
}

type allowedKey struct{}

// Middleware is the per-request gate, as an operation middleware on the dev login operation: a
// loopback client, a loopback Host, and no forwarding header. Allowed reads its verdict.
func Middleware(hctx huma.Context, next func(huma.Context)) {
	ok := httpx.ClientIP(hctx.Context()).IsLoopback() && !httpx.Proxied(hctx.Context()) && loopbackHost(hctx.Host())
	hctx.EachHeader(func(name, _ string) {
		canonical := strings.ToLower(name)
		if strings.HasPrefix(canonical, "x-forwarded-") {
			ok = false
		}
		for _, h := range forwardingHeaders {
			if canonical == strings.ToLower(h) {
				ok = false
			}
		}
	})
	next(huma.WithValue(hctx, allowedKey{}, ok))
}

// Allowed is the verdict Middleware recorded; false when it did not run.
func Allowed(ctx context.Context) bool {
	ok, _ := ctx.Value(allowedKey{}).(bool)
	return ok
}

// loopbackHost accepts localhost, a name under .localhost, 127.0.0.1 or [::1], with an optional port.
func loopbackHost(host string) bool {
	name := host
	switch h, _, err := net.SplitHostPort(host); {
	case err == nil:
		name = h
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		name = host[1 : len(host)-1]
	case strings.Contains(host, ":"):
		return false
	}
	name = strings.ToLower(name)
	return name == "localhost" || name == "127.0.0.1" || name == "::1" || strings.HasSuffix(name, ".localhost")
}

func loopbackName(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
