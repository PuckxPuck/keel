// Package ratelimit limits requests per class: token buckets in memory for general traffic, fixed
// windows in the database for security counters (D31).
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Rate is Limit requests per Period, written as "60/1m".
type Rate struct {
	Limit  int
	Period time.Duration
}

func ParseRate(s string) (Rate, error) {
	count, period, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return Rate{}, fmt.Errorf("rate %q must look like 60/1m", s)
	}
	n, err := strconv.Atoi(count)
	if err != nil || n < 1 {
		return Rate{}, fmt.Errorf("rate %q needs a whole count of at least 1", s)
	}
	d, err := time.ParseDuration(period)
	if err != nil || d < time.Second {
		return Rate{}, fmt.Errorf("rate %q needs a period of at least 1s", s)
	}
	return Rate{Limit: n, Period: d}, nil
}

func (r *Rate) UnmarshalText(text []byte) error {
	parsed, err := ParseRate(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

func (r Rate) String() string { return strconv.Itoa(r.Limit) + "/" + r.Period.String() }

func (r Rate) valid() bool { return r.Limit >= 1 && r.Period >= time.Second }

// Decision is one store's answer for one request.
type Decision struct {
	Allowed    bool
	Limit      int
	Window     time.Duration
	Remaining  int
	Reset      time.Duration
	RetryAfter time.Duration
}

// Store counts hits per key.
type Store interface {
	Take(ctx context.Context, key string, rate Rate) (Decision, error)
}

const (
	ClassPreAuth  = "preauth"
	ClassAuth     = "auth"
	ClassAPIRead  = "api-read"
	ClassAPIWrite = "api-write"
	ClassHeavy    = "heavy"
	ClassWebhook  = "webhook"
	ClassHealth   = "health"
	// ClassAPIKey and ClassAPITenant limit every request on the public api realm, by key and by tenant
	// across its keys, on top of the operation's own class.
	ClassAPIKey    = "api-key"
	ClassAPITenant = "api-tenant"
)

// Config holds the default classes' rates (APP_RATE_*).
type Config struct {
	PreAuth   Rate `env:"PREAUTH" envDefault:"3000/1m"`
	Auth      Rate `env:"AUTH" envDefault:"30/1m"`
	APIRead   Rate `env:"API_READ" envDefault:"600/1m"`
	APIWrite  Rate `env:"API_WRITE" envDefault:"120/1m"`
	Heavy     Rate `env:"HEAVY" envDefault:"30/1h"`
	Webhook   Rate `env:"WEBHOOK" envDefault:"120/1m"`
	Health    Rate `env:"HEALTH" envDefault:"6000/1m"`
	APIKey    Rate `env:"API_KEY" envDefault:"600/1m"`
	APITenant Rate `env:"API_TENANT" envDefault:"1200/1m"`
	MaxKeys   int  `env:"MAX_KEYS" envDefault:"50000"`
}

func (c Config) Validate(bool) error {
	var errs []error
	for name, r := range map[string]Rate{
		ClassPreAuth: c.PreAuth, ClassAuth: c.Auth, ClassAPIRead: c.APIRead, ClassAPIWrite: c.APIWrite,
		ClassHeavy: c.Heavy, ClassWebhook: c.Webhook, ClassHealth: c.Health, ClassAPIKey: c.APIKey, ClassAPITenant: c.APITenant,
	} {
		if !r.valid() {
			errs = append(errs, fmt.Errorf("rate for %s must be at least 1 per period of 1s or more", name))
		}
	}
	if c.MaxKeys < 1 {
		errs = append(errs, errors.New("rate limit max keys must be at least 1"))
	}
	return errors.Join(errs...)
}
