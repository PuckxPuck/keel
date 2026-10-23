package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/auth/devlogin"
	"github.com/PuckxPuck/keel/internal/kit/auth/password"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/auth/totp"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
)

const EnvPrefix = "APP_"

type Config struct {
	Env         config.Env `env:"ENV,required,notEmpty"`
	App         config.App
	HTTP        config.HTTP        `envPrefix:"HTTP_"`
	Log         config.Log         `envPrefix:"LOG_"`
	Proxy       config.Proxy       `envPrefix:"PROXY_"`
	Database    db.Config          `envPrefix:"DATABASE_"`
	Rate        ratelimit.Config   `envPrefix:"RATE_"`
	Idempotency idempotency.Config `envPrefix:"IDEMPOTENCY_"`
	Jobs        jobs.Config        `envPrefix:"JOBS_"`
	Audit       AuditConfig        `envPrefix:"AUDIT_"`
	Session     SessionConfig      `envPrefix:"SESSION_"`
	Realm       RealmsConfig       `envPrefix:"REALM_"`
	Password    password.Config    `envPrefix:"PASSWORD_"`
	Tokens      tokens.Config      `envPrefix:"TOKENS_"`
	MFA         totp.Config        `envPrefix:"MFA_"`
	OIDC        OIDCConfig         `envPrefix:"OIDC_"`
	Passkey     PasskeyConfig      `envPrefix:"PASSKEY_"`
	APIKey      APIKeyConfig       `envPrefix:"APIKEY_"`
	Tenancy     TenancyConfig      `envPrefix:"TENANCY_"`
	DevLogin    bool               `env:"DEV_LOGIN"`
	Mail        MailConfig         `envPrefix:"MAIL_"`
	Files       FilesConfig        `envPrefix:"FILES_"`
	XLSX        XLSXConfig         `envPrefix:"XLSX_"`
	PDF         PDFConfig          `envPrefix:"PDF_"`
	Feed        FeedConfig         `envPrefix:"FEED_"`
	WebhooksOut WebhooksOutConfig  `envPrefix:"WEBHOOKS_OUT_"`
	Connection  ConnectionConfig   `envPrefix:"CONNECTION_"`
	Otel        OtelConfig         `envPrefix:"OTEL_"`
}

// FeedConfig is APP_FEED_*: how long change feeds keep tombstones; an older feed token resyncs.
type FeedConfig struct {
	TombstoneRetention time.Duration `env:"TOMBSTONE_RETENTION" envDefault:"720h"`
}

func (f FeedConfig) Validate(bool) error {
	if f.TombstoneRetention < time.Hour {
		return errors.New("tombstone retention must be at least 1h")
	}
	return nil
}

// httpPoolReserve is the app pool left for requests when every in-serve worker holds a connection.
const httpPoolReserve = 4

// workerPoolReserve is the app pool app worker keeps for lease renewals and the reaper.
const workerPoolReserve = 2

type AuditConfig struct {
	Chain bool `env:"CHAIN"`
}

// SessionConfig is the default every realm block falls back to, and the signing keys.
type SessionConfig struct {
	Cookie   string        `env:"COOKIE" envDefault:"session"`
	Idle     time.Duration `env:"IDLE" envDefault:"2h"`
	Absolute time.Duration `env:"ABSOLUTE" envDefault:"12h"`
	// Keys sign cursors and short-lived values (HMAC): base64, newest first; the first signs, all verify.
	Keys []config.Secret `env:"KEYS"`
}

const minSigningKey = 32

func (s SessionConfig) Validate(bool) error {
	var errs []error
	if s.Idle <= 0 || s.Absolute < s.Idle {
		errs = append(errs, errors.New("session idle must be positive and absolute at least as long"))
	}
	if !realm.ValidCookie(s.Cookie) {
		errs = append(errs, fmt.Errorf("cookie name %q must be letters, digits, - and _ (at most 64) and not start with __", s.Cookie))
	}
	for i, k := range s.Keys {
		if key, err := decodeKey(k); err != nil || len(key) < minSigningKey {
			errs = append(errs, fmt.Errorf("key %d must be base64 of at least %d bytes", i+1, minSigningKey))
		}
	}
	return errors.Join(errs...)
}

func decodeKey(k config.Secret) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(k.Reveal()))
}

// localSigningKey stands in for APP_SESSION_KEYS in local development: values it signs do not survive a
// restart.
var localSigningKey = sync.OnceValue(func() []byte {
	b := make([]byte, minSigningKey)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b
})

// SigningKeys are APP_SESSION_KEYS decoded, newest first, for paging.NewKeyset and files.NewURLSigner.
// Validation requires them outside local; without them, local signs with a per-process random key.
func (c Config) SigningKeys() [][]byte {
	if len(c.Session.Keys) == 0 {
		return [][]byte{localSigningKey()}
	}
	out := make([][]byte, 0, len(c.Session.Keys))
	for _, k := range c.Session.Keys {
		if key, err := decodeKey(k); err == nil {
			out = append(out, key)
		}
	}
	return out
}

// RealmsConfig holds one block per realm (APP_REALM_<NAME>_*).
type RealmsConfig struct {
	Tenant RealmConfig    `envPrefix:"TENANT_"`
	API    APIRealmConfig `envPrefix:"API_"`
	// Operator is served only on its hosts (tenancy); without hosts the realm is off.
	Operator RealmConfig `envPrefix:"OPERATOR_"`
}

// RealmConfig overrides the session defaults for one realm; empty values fall back to them.
type RealmConfig struct {
	Hosts    []string      `env:"HOSTS"`
	Cookie   string        `env:"COOKIE"`
	Idle     time.Duration `env:"IDLE"`
	Absolute time.Duration `env:"ABSOLUTE"`
	MFA      realm.MFA     `env:"MFA"`
}

func (r RealmConfig) Validate(bool) error {
	var errs []error
	if r.Cookie != "" && !realm.ValidCookie(r.Cookie) {
		errs = append(errs, fmt.Errorf("cookie name %q must be letters, digits, - and _ (at most 64) and not start with __", r.Cookie))
	}
	if r.MFA != "" && !r.MFA.Valid() {
		errs = append(errs, fmt.Errorf("MFA must be off, optional or required, got %q", r.MFA))
	}
	if r.Idle < 0 || r.Absolute < 0 {
		errs = append(errs, errors.New("idle and absolute must not be negative"))
	}
	return errors.Join(errs...)
}

// apply fills a realm's session settings from its block and the defaults.
func (r RealmConfig) apply(base realm.Realm, s SessionConfig) realm.Realm {
	base.Hosts = r.Hosts
	base.Cookie, base.Idle, base.Absolute, base.MFA = s.Cookie, s.Idle, s.Absolute, realm.MFAOff
	if r.Cookie != "" {
		base.Cookie = r.Cookie
	}
	if r.Idle > 0 {
		base.Idle = r.Idle
	}
	if r.Absolute > 0 {
		base.Absolute = r.Absolute
	}
	if r.MFA != "" {
		base.MFA = r.MFA
	}
	return base
}

// Validate checks rules across parts: dev login's gates, signing keys outside local, and MFA keys for
// realms that use MFA.
func (c Config) Validate(bool) error {
	var errs []error
	if err := devlogin.Gate(c.Env, c.DevLogin, c.HTTP.Addr); err != nil {
		errs = append(errs, err)
	}
	if c.Env != config.EnvLocal && len(c.Session.Keys) == 0 {
		errs = append(errs, errors.New("APP_SESSION_KEYS is required outside local"))
	}
	errs = append(errs, c.validateOIDC(), c.validateTenancy(), c.validateParts())
	for _, r := range configuredRealms(c) {
		if r.Absolute < r.Idle {
			errs = append(errs, fmt.Errorf("realm %s: absolute expiry must be at least the idle expiry", r.Name))
		}
		if r.MFA != realm.MFAOff && len(c.MFA.Keys) == 0 {
			errs = append(errs, fmt.Errorf("realm %s uses MFA %s, which needs APP_MFA_KEYS", r.Name, r.MFA))
		}
	}
	return errors.Join(errs...)
}

// validateParts checks rules across the optional parts and the pools they share.
func (c Config) validateParts() error {
	var errs []error
	if c.Jobs.ShutdownGrace >= c.HTTP.ShutdownTimeout {
		errs = append(errs, errors.New("APP_JOBS_SHUTDOWN_GRACE must be shorter than APP_HTTP_SHUTDOWN_TIMEOUT, which bounds workers and requests together"))
	}
	workers := c.Jobs.Workers()
	switch {
	case c.Jobs.InServe && c.Database.MaxOpen < workers+httpPoolReserve:
		errs = append(errs, fmt.Errorf("APP_DATABASE_MAX_OPEN is %d: serve runs %d workers on the app pool, so it needs at least %d more for requests",
			c.Database.MaxOpen, workers, httpPoolReserve))
	case !c.Jobs.InServe && c.Database.MaxOpen < workers+workerPoolReserve:
		errs = append(errs, fmt.Errorf("APP_DATABASE_MAX_OPEN is %d: app worker runs %d workers on the app pool, so it needs at least %d more",
			c.Database.MaxOpen, workers, workerPoolReserve))
	}
	return errors.Join(errs...)
}

// LoadConfig reads the configuration from environ in os.Environ form.
func LoadConfig(environ []string) (Config, error) {
	return config.LoadFrom[Config](EnvPrefix, environ)
}
