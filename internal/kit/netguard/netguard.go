// Package netguard connects only to globally reachable addresses, for requests to URLs that tenants or
// providers supply (SSRF): default deny, one resolution per dial, no proxy from the environment.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

var ErrBlocked = errors.New("netguard: the address is not allowed")

var global6 = netip.MustParsePrefix("2000::/3")

// The IANA IPv4 and IPv6 special-purpose blocks that are not globally reachable (a block is refused
// whole even where a smaller entry inside it is reachable), multicast, IPv6 forms that embed or tunnel
// IPv4, and Azure's WireServer, a public address only the host answers.
var (
	blocked4 = prefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
	)
	blocked6 = prefixes(
		"2001::/23", "2001::/32", "2001:db8::/32", "2002::/16", "3fff::/20", "64:ff9b::/96", "64:ff9b:1::/48",
	)
)

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Allowed reports whether a may be connected to: public IPv4 unicast, or IPv6 in 2000::/3, outside every
// blocked range. IPv4-mapped and IPv4-compatible IPv6 are judged as the IPv4 address they carry; any
// address with a zone is refused.
func Allowed(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	a = unwrap(a)
	list := blocked4
	if a.Is6() {
		if !global6.Contains(a) {
			return false
		}
		list = blocked6
	}
	for _, p := range list {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func unwrap(a netip.Addr) netip.Addr {
	if a.Is4In6() {
		return a.Unmap()
	}
	if b := a.As16(); a.Is6() && [12]byte(b[:12]) == [12]byte{} {
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return a
}

// Dialer resolves a host once, refuses it when any of its addresses is not allowed, and connects to a
// checked address, so a second lookup (DNS rebinding) never decides where the connection goes.
type Dialer struct {
	timeout time.Duration
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
	permit  []netip.Prefix
}

type Option func(*Dialer)

// Permit also admits addresses inside prefixes (a test server on loopback). Zones stay refused.
func Permit(p ...netip.Prefix) Option {
	return func(d *Dialer) { d.permit = append(d.permit, p...) }
}

// Lookup replaces the resolver (tests).
func Lookup(fn func(ctx context.Context, host string) ([]netip.Addr, error)) Option {
	return func(d *Dialer) { d.lookup = fn }
}

func NewDialer(timeout time.Duration, opts ...Option) *Dialer {
	d := &Dialer{
		timeout: timeout,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

func (d *Dialer) allowed(a netip.Addr) bool {
	if Allowed(a) {
		return true
	}
	if a.Zone() != "" {
		return false
	}
	for _, p := range d.permit {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("netguard: network %s is not allowed", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{
		Timeout: d.timeout,
		// The address actually dialled is checked again, whatever produced it.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !d.allowed(ap.Addr()) {
				return ErrBlocked
			}
			return nil
		},
	}
	var errs []error
	for _, a := range addrs {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if strings.Contains(host, "%") {
		return nil, ErrBlocked
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !d.allowed(a) {
			return nil, ErrBlocked
		}
		return []netip.Addr{a}, nil
	}
	addrs, err := d.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netguard: resolve: %w", err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("netguard: the host has no addresses")
	}
	for _, a := range addrs {
		if !d.allowed(a) {
			return nil, ErrBlocked
		}
	}
	return addrs, nil
}

// Transport uses the dialer and never a proxy from the environment.
func (d *Dialer) Transport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}
}

// Client is Transport with an overall timeout and no redirects.
func (d *Dialer) Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     d.Transport(timeout),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// HostAllowed refuses a URL host that names a zone or a literal address that is not allowed; a name is
// checked when it is dialled.
func HostAllowed(host string) error {
	if strings.Contains(host, "%") {
		return ErrBlocked
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !Allowed(a) {
		return ErrBlocked
	}
	return nil
}
