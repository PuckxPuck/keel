// Package realm routes requests to realms by host. A realm bundles hosts, a base path, an OpenAPI
// document, a permission catalogue and its session settings.
package realm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"golang.org/x/net/idna"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// MFA is a realm's second-factor policy.
type MFA string

const (
	MFAOff      MFA = "off"
	MFAOptional MFA = "optional"
	MFARequired MFA = "required"
)

func (m MFA) Valid() bool {
	switch m {
	case MFAOff, MFAOptional, MFARequired:
		return true
	}
	return false
}

// Loader builds a signed-in user's principal; rbac.Loader is one.
type Loader interface {
	Load(ctx context.Context, tx db.Transaction, userID users.ID) (rbac.Principal, error)
}

type Realm struct {
	Name string
	// Hosts are matched exactly, ignoring port, case and one trailing dot; internationalised names
	// match their punycode form. A realm without hosts takes every host no other realm claims; at most
	// one realm may do that.
	Hosts    []string
	BasePath string
	// SpecPath serves the realm's OpenAPI document there whatever the docs setting (the public api realm).
	SpecPath  string
	Catalogue *rbac.Catalogue
	// Cookie names the realm's session cookie (auth adds __Host- in production); realms must not share
	// one. Empty means the realm takes no cookie sessions.
	Cookie   string
	Idle     time.Duration
	Absolute time.Duration
	MFA      MFA
	Loader   Loader
}

// Set holds every realm with its router and Huma API; it is the http.Handler for API routes.
type Set struct {
	realms   []*mounted
	byName   map[string]*mounted
	byHost   map[string]*mounted
	fallback *mounted
}

type mounted struct {
	realm  Realm
	router chi.Router
	api    huma.API
}

var (
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	cookiePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ValidCookie is true for a cookie name a realm may use: letters, digits, - and _, at most 64, not
// starting with "__" (auth adds the __Host- prefix itself).
func ValidCookie(name string) bool {
	return cookiePattern.MatchString(name) && !strings.HasPrefix(name, "__")
}

// New builds one router and Huma API per realm; opts apply to every API, with the realm's base path.
func New(opts httpx.Options, realms ...Realm) (*Set, error) {
	s := &Set{byName: map[string]*mounted{}, byHost: map[string]*mounted{}}
	var errs []error
	for _, r := range realms {
		if err := s.add(r, opts); err != nil {
			errs = append(errs, err)
		}
	}
	if len(realms) == 0 {
		errs = append(errs, errors.New("realm: at least one realm is required"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Set) add(r Realm, opts httpx.Options) error {
	switch {
	case !namePattern.MatchString(r.Name):
		return fmt.Errorf("realm: name %q must be lower case letters, digits, - and _", r.Name)
	case s.byName[r.Name] != nil:
		return fmt.Errorf("realm: %s is declared twice", r.Name)
	case r.Catalogue == nil:
		return fmt.Errorf("realm: %s has no permission catalogue", r.Name)
	case len(r.Hosts) == 0 && s.fallback != nil:
		return fmt.Errorf("realm: %s and %s both have no hosts; only one realm may take unclaimed hosts", s.fallback.realm.Name, r.Name)
	case r.MFA != "" && !r.MFA.Valid():
		return fmt.Errorf("realm: %s has MFA %q; use off, optional or required", r.Name, r.MFA)
	case r.Cookie != "" && !ValidCookie(r.Cookie):
		return fmt.Errorf("realm: %s has an invalid cookie name %q", r.Name, r.Cookie)
	}
	for _, other := range s.realms {
		if r.Cookie != "" && other.realm.Cookie == r.Cookie {
			return fmt.Errorf("realm: %s and %s share the cookie %s", other.realm.Name, r.Name, r.Cookie)
		}
	}
	router := httpx.NewRouter()
	opts.BasePath, opts.Realm, opts.SpecPath = r.BasePath, r.Name, r.SpecPath
	m := &mounted{realm: r, router: router, api: httpx.NewAPI(router, opts)}
	for _, h := range r.Hosts {
		host, err := hostOf(h)
		if err == nil && !isASCII(host) {
			host, err = idna.Lookup.ToASCII(host)
		}
		if err != nil || host == "" {
			return fmt.Errorf("realm: %s has an invalid host %q", r.Name, h)
		}
		if other := s.byHost[host]; other != nil {
			return fmt.Errorf("realm: host %s is claimed by %s and %s", host, other.realm.Name, r.Name)
		}
		s.byHost[host] = m
	}
	if len(r.Hosts) == 0 {
		s.fallback = m
	}
	s.realms = append(s.realms, m)
	s.byName[r.Name] = m
	return nil
}

// API is the Huma API of the named realm; nil when there is no such realm.
func (s *Set) API(name string) huma.API {
	if m := s.byName[name]; m != nil {
		return m.api
	}
	return nil
}

// Realm is the named realm's definition.
func (s *Set) Realm(name string) (Realm, bool) {
	if m := s.byName[name]; m != nil {
		return m.realm, true
	}
	return Realm{}, false
}

// Each calls fn for every realm in the order they were given.
func (s *Set) Each(fn func(r Realm, api huma.API)) {
	for _, m := range s.realms {
		fn(m.realm, m.api)
	}
}

// For names the realm a Host header routes to, or "" when it routes nowhere or is malformed.
func (s *Set) For(rawHost string) string {
	m, err := s.route(rawHost)
	if err != nil || m == nil {
		return ""
	}
	return m.realm.Name
}

// Host is a Host header as routing compares it: lower case, without port or one trailing dot,
// internationalised names in punycode. ok is false for a malformed header.
func Host(rawHost string) (string, bool) {
	host, err := hostOf(rawHost)
	if err != nil {
		return "", false
	}
	if !isASCII(host) {
		// A name that is not valid IDNA cannot equal a configured host, so it only reaches the fallback.
		host, _ = idna.Lookup.ToASCII(host)
	}
	return host, true
}

func (s *Set) route(rawHost string) (*mounted, error) {
	host, ok := Host(rawHost)
	if !ok {
		return nil, errMalformedHost
	}
	if m := s.byHost[host]; m != nil {
		return m, nil
	}
	return s.fallback, nil
}

func (s *Set) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, err := s.route(r.Host)
	if err != nil {
		problem.Write(w, r, problem.New(http.StatusBadRequest, "bad_request", "the Host header is malformed"))
		return
	}
	if m == nil {
		problem.Write(w, r, problem.New(http.StatusNotFound, problem.CodeNotFound, "no such route"))
		return
	}
	ctx := httpx.WithRealm(r.Context(), m.realm.Name)
	ctx = logx.With(ctx, slog.String("realm", m.realm.Name))
	m.router.ServeHTTP(w, r.WithContext(ctx))
}

var errMalformedHost = errors.New("realm: malformed host")

// hostOf parses a Host header the way net.SplitHostPort does, refusing malformed brackets and ports,
// and returns the host lower-cased without one trailing dot. Brackets are accepted only around an IPv6
// literal, so "[ops.example.test]" never becomes "ops.example.test".
func hostOf(raw string) (string, error) {
	host := raw
	bracketed := strings.HasPrefix(raw, "[")
	if bracketed || strings.Contains(raw, ":") {
		h, port, err := net.SplitHostPort(raw)
		switch {
		case err == nil && validPort(port):
			host = h
		case err != nil && bracketed && strings.HasSuffix(raw, "]"):
			host = raw[1 : len(raw)-1]
		default:
			return "", errMalformedHost
		}
	}
	if bracketed {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", errMalformedHost
		}
		return addr.String(), nil
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, "[]:/@ ") {
		return "", errMalformedHost
	}
	return strings.ToLower(host), nil
}

func validPort(port string) bool {
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && port[0] != '+'
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
