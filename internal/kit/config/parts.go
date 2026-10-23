package config

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type App struct {
	Name      string `env:"NAME"`
	PublicURL string `env:"PUBLIC_URL"`
}

func (a App) Validate(prod bool) error {
	if a.PublicURL == "" {
		if prod {
			return errors.New("public URL is required")
		}
		return nil
	}
	u, err := url.Parse(a.PublicURL)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
		return errors.New("public URL must be an absolute http(s) URL")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return errors.New("public URL must not carry credentials, a query or a fragment")
	case prod && u.Scheme != "https":
		return errors.New("public URL must be https in production")
	}
	return nil
}

type HTTP struct {
	Addr              string        `env:"ADDR" envDefault:"127.0.0.1:8080"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"5s"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"120s"`
	MaxHeaderBytes    ByteSize      `env:"MAX_HEADER_BYTES" envDefault:"64KiB"`
	MaxBodyBytes      ByteSize      `env:"MAX_BODY_BYTES" envDefault:"1MiB"`
	ShutdownDrain     time.Duration `env:"SHUTDOWN_DRAIN" envDefault:"5s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
	Docs              bool          `env:"DOCS"`
	CORSOrigins       []string      `env:"CORS_ORIGINS"`
}

func (h HTTP) Validate(prod bool) error {
	var errs []error
	if err := validateAddr(h.Addr); err != nil {
		errs = append(errs, err)
	}

	durations := []struct {
		name string
		d    time.Duration
	}{
		{"read header timeout", h.ReadHeaderTimeout},
		{"read timeout", h.ReadTimeout},
		{"write timeout", h.WriteTimeout},
		{"idle timeout", h.IdleTimeout},
		{"shutdown timeout", h.ShutdownTimeout},
	}
	for _, d := range durations {
		if d.d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", d.name))
		}
	}
	if h.ShutdownDrain < 0 || h.ShutdownDrain >= h.ShutdownTimeout {
		errs = append(errs, errors.New("shutdown drain must be zero or more and shorter than the shutdown timeout"))
	}
	// A stopping server cuts what is still running at drain plus shutdown; a request may run for the write timeout.
	if h.ShutdownDrain+h.ShutdownTimeout < h.WriteTimeout {
		errs = append(errs, errors.New("shutdown drain plus shutdown timeout must be at least the write timeout"))
	}
	if h.MaxHeaderBytes <= 0 || h.MaxHeaderBytes > math.MaxInt32 {
		errs = append(errs, errors.New("max header bytes must be positive and below 2 GiB"))
	}
	if h.MaxBodyBytes <= 0 {
		errs = append(errs, errors.New("max body bytes must be positive"))
	}
	if prod && h.Docs {
		errs = append(errs, errors.New("docs routes must be disabled in production"))
	}
	for _, origin := range h.CORSOrigins {
		if err := validateOrigin(origin, prod); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateAddr(addr string) error {
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("addr %q must be unix: followed by an absolute path", addr)
		}
		return nil
	}
	if _, port, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("addr %q must be host:port or unix:/path", addr)
	} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("addr %q has an invalid port", addr)
	}
	return nil
}

func validateOrigin(origin string, prod bool) error {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("cors origin %q must be an exact origin such as https://app.example.com", origin)
	}
	if prod && u.Scheme != "https" {
		return fmt.Errorf("cors origin %q must be https in production", origin)
	}
	return nil
}

type LogFormat string

const (
	LogJSON LogFormat = "json"
	LogText LogFormat = "text"
)

type Log struct {
	Level  slog.Level `env:"LEVEL" envDefault:"info"`
	Format LogFormat  `env:"FORMAT" envDefault:"json"`
}

func (l Log) Validate(bool) error {
	switch l.Format {
	case LogJSON, LogText:
		return nil
	}
	return fmt.Errorf("format must be json or text, got %q", string(l.Format))
}

type ProxyEdge string

const (
	EdgeNone             ProxyEdge = "none"
	EdgeCloudflare       ProxyEdge = "cloudflare"
	EdgeCloudflareTunnel ProxyEdge = "cloudflare-tunnel"
)

// UnixPeer is the APP_PROXY_TRUSTED token that trusts a peer on the app's unix socket.
const UnixPeer = "unix"

// TrustedProxies is a comma-separated list of CIDRs and, optionally, the token unix.
type TrustedProxies struct {
	Prefixes []netip.Prefix
	Unix     bool
}

func (t *TrustedProxies) UnmarshalText(text []byte) error {
	*t = TrustedProxies{}
	for part := range strings.SplitSeq(string(text), ",") {
		part = strings.TrimSpace(part)
		switch part {
		case "":
			continue
		case UnixPeer:
			t.Unix = true
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return fmt.Errorf("trusted proxy %q must be a CIDR or %s: %w", part, UnixPeer, err)
		}
		t.Prefixes = append(t.Prefixes, prefix)
	}
	return nil
}

func (t TrustedProxies) String() string {
	parts := make([]string, 0, len(t.Prefixes)+1)
	for _, p := range t.Prefixes {
		parts = append(parts, p.String())
	}
	if t.Unix {
		parts = append(parts, UnixPeer)
	}
	return strings.Join(parts, ",")
}

func (t TrustedProxies) Empty() bool { return len(t.Prefixes) == 0 && !t.Unix }

type Proxy struct {
	Trusted    TrustedProxies `env:"TRUSTED"`
	Edge       ProxyEdge      `env:"EDGE" envDefault:"none"`
	TunnelAddr netip.Addr     `env:"TUNNEL_ADDR"`
}

func (p Proxy) Validate(prod bool) error {
	var errs []error
	switch p.Edge {
	case EdgeNone:
		if p.TunnelAddr.IsValid() {
			errs = append(errs, errors.New("tunnel addr is only used with edge cloudflare-tunnel"))
		}
	case EdgeCloudflare:
		if prod && p.Trusted.Empty() {
			errs = append(errs, errors.New("edge cloudflare needs trusted proxies in production"))
		}
		if p.TunnelAddr.IsValid() {
			errs = append(errs, errors.New("tunnel addr is only used with edge cloudflare-tunnel"))
		}
	case EdgeCloudflareTunnel:
		if !p.TunnelAddr.IsValid() {
			errs = append(errs, errors.New("edge cloudflare-tunnel needs a tunnel addr"))
		}
	default:
		errs = append(errs, fmt.Errorf("edge must be none, cloudflare or cloudflare-tunnel, got %q", string(p.Edge)))
	}
	if prod {
		for _, prefix := range p.Trusted.Prefixes {
			if prefix.Bits() == 0 {
				errs = append(errs, fmt.Errorf("trusted proxy %s would trust every address", prefix))
			}
		}
	}
	return errors.Join(errs...)
}
