package connections

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	"golang.org/x/oauth2"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/netguard"
)

var (
	ErrProviderUnavailable = errors.New("connections: the provider could not be reached; try again later")
	ErrProviderFailed      = errors.New("connections: the provider refused or failed the request")
)

// oauthCodes are the RFC 6749 error codes: the only provider text that may appear in an error.
var oauthCodes = []string{
	"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope",
	"access_denied", "unsupported_response_type", "server_error", "temporarily_unavailable",
}

// providerError classifies err from a provider call into ErrProviderUnavailable or ErrProviderFailed
// with a safe code; response bodies, headers and adapter messages are dropped.
func providerError(op string, err error) error {
	var re *oauth2.RetrieveError
	var ne net.Error
	switch {
	case errors.As(err, &re):
		code, status := "error", 0
		if re.Response != nil {
			status = re.Response.StatusCode
			code = "status " + strconv.Itoa(status)
		}
		if slices.Contains(oauthCodes, re.ErrorCode) {
			code = re.ErrorCode
		}
		if status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
			return fmt.Errorf("%w (%s: %s)", ErrProviderUnavailable, op, code)
		}
		return fmt.Errorf("%w (%s: %s)", ErrProviderFailed, op, code)
	case errors.Is(err, netguard.ErrBlocked):
		return fmt.Errorf("%w (%s: blocked address)", ErrProviderFailed, op)
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return fmt.Errorf("%w (%s: timeout)", ErrProviderUnavailable, op)
	case errors.As(err, &ne):
		return fmt.Errorf("%w (%s: network)", ErrProviderUnavailable, op)
	}
	return fmt.Errorf("%w (%s)", ErrProviderFailed, op)
}

func invalidGrant(err error) bool {
	var re *oauth2.RetrieveError
	return errors.As(err, &re) && re.ErrorCode == "invalid_grant"
}

// Client calls the provider's API as the connection. Requests go only to the provider's API origins,
// each with a current token; redirects are followed only within the same origin; 429 and 5xx answers are
// retried with backoff when the request can be replayed.
func (s *Service) Client(id ID) *http.Client {
	return s.apiClient(func(ctx context.Context) (Provider, string, string, error) { return s.token(ctx, id) })
}

type tokenFunc func(ctx context.Context) (p Provider, access, tokenType string, err error)

func (s *Service) apiClient(token tokenFunc) *http.Client {
	base := s.client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{
		Timeout:   s.client.Timeout,
		Transport: &transport{svc: s, token: token, base: base},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 || origin(req.URL) != origin(via[0].URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

type transport struct {
	svc   *Service
	token tokenFunc
	base  http.RoundTripper
}

const (
	maxRetries     = 3
	retryBase      = 500 * time.Millisecond
	maxRetryAfter  = 30 * time.Second
	drainOnRetries = 64 << 10
)

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	p, access, tokenType, err := t.token(req.Context())
	if err != nil {
		return nil, err
	}
	if !slices.Contains(t.svc.origins[p.Name()], origin(req.URL)) {
		return nil, ErrOriginNotAllowed
	}
	if tokenType == "" {
		tokenType = "Bearer"
	}
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	for attempt := 0; ; attempt++ {
		r := req.Clone(req.Context())
		r.Header.Set("Authorization", tokenType+" "+access)
		if attempt > 0 && req.GetBody != nil {
			if r.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		resp, err := t.base.RoundTrip(r)
		if err != nil || attempt == maxRetries || !replayable ||
			(resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < http.StatusInternalServerError) {
			return resp, err
		}
		wait := retryWait(resp, attempt, clock.Wall(req.Context()).Now())
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainOnRetries))
		_ = resp.Body.Close()
		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
}

func retryWait(resp *http.Response, attempt int, at time.Time) time.Duration {
	after := resp.Header.Get("Retry-After")
	if secs, err := strconv.Atoi(after); err == nil && secs >= 0 {
		return min(time.Duration(secs)*time.Second, maxRetryAfter)
	}
	if when, err := http.ParseTime(after); err == nil {
		return min(max(when.Sub(at), 0), maxRetryAfter)
	}
	d := retryBase << attempt
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) //nolint:gosec // jitter, not secrecy
}
