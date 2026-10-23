package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
)

// FailureStore counts attempts where every replica sees them; ratelimit.DBStore is the one (D31).
type FailureStore interface {
	Take(ctx context.Context, key string, rate ratelimit.Rate) (ratelimit.Decision, error)
	Reset(ctx context.Context, key string) error
	Refund(ctx context.Context, key string, rate ratelimit.Rate) error
}

// Limit is one counter: a key (built with Key) and how many attempts it allows per period. A success
// clears a Reset counter (one account's count) and gives the attempt back on the others.
type Limit struct {
	Key   string
	Rate  ratelimit.Rate
	Reset bool
}

// Key builds a counter key from parts, hashing ones that may be personal (an email address).
func Key(kind string, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "authfail:" + kind + ":" + hex.EncodeToString(h.Sum(nil)[:16])
}

// Address is the client's address key for counters, and false when the address is unknown: keys that
// pair it with an account would put every such caller in one bucket, so callers skip them.
func Address(ctx context.Context) (string, bool) {
	return ratelimit.ByAddress(ctx, nil), httpx.ClientIP(ctx).IsValid()
}

// Failures refuses a caller whose counters are full until their window ends: a delay that only the
// counted key feels, never a lockout a third party can impose on someone else's account.
type Failures struct {
	store FailureStore
}

func NewFailures(store FailureStore) *Failures { return &Failures{store: store} }

// ThrottledError is 429 rate_limited with Retry-After.
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string { return "too many failed attempts" }

// GetHeaders makes Huma send Retry-After with the problem.
func (e *ThrottledError) GetHeaders() http.Header {
	secs := max(1, int64((e.RetryAfter+time.Second-1)/time.Second))
	return http.Header{"Retry-After": []string{strconv.FormatInt(secs, 10)}}
}

// Attempt counts one attempt on every counter before the secret is checked and refuses when any is
// over its limit. The count comes back from the same statement that adds it, so a concurrent burst
// cannot all pass. A store failure refuses too (fail closed).
func (f *Failures) Attempt(ctx context.Context, limits ...Limit) error {
	var refused *ThrottledError
	for _, l := range limits {
		d, err := f.store.Take(ctx, l.Key, l.Rate)
		if err != nil {
			return fmt.Errorf("failure counter: %w", err)
		}
		if !d.Allowed {
			if refused == nil {
				refused = &ThrottledError{}
			}
			refused.RetryAfter = max(refused.RetryAfter, d.RetryAfter)
		}
	}
	if refused != nil {
		return refused
	}
	return nil
}

// Succeeded clears the Reset counters and gives the attempt back on the others.
func (f *Failures) Succeeded(ctx context.Context, limits ...Limit) error {
	var errs []error
	for _, l := range limits {
		if l.Reset {
			errs = append(errs, f.store.Reset(ctx, l.Key))
		} else {
			errs = append(errs, f.store.Refund(ctx, l.Key, l.Rate))
		}
	}
	return errors.Join(errs...)
}

// Fail counts one failure on l and reports whether the count has reached its limit, for caps on
// consecutive failures that a success clears.
func (f *Failures) Fail(ctx context.Context, l Limit) (reached bool, err error) {
	d, err := f.store.Take(ctx, l.Key, l.Rate)
	if err != nil {
		return false, fmt.Errorf("failure counter: %w", err)
	}
	return !d.Allowed || d.Remaining == 0, nil
}

// Mapper answers ThrottledError with 429 rate_limited and a missing session with 401.
func Mapper(err error) (*problem.Problem, bool) {
	var t *ThrottledError
	switch {
	case errors.As(err, &t):
		return problem.New(http.StatusTooManyRequests, ratelimit.CodeRateLimited, "too many attempts; retry after the time in Retry-After"), true
	case errors.Is(err, ErrNoSession):
		return problem.New(http.StatusUnauthorized, CodeUnauthenticated, "sign in to continue"), true
	}
	return nil, false
}
