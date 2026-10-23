// Package webhooks notifies other systems of events (outbound): endpoints, events recorded in the
// causing transaction, signed deliveries (Standard Webhooks) by jobs over an SSRF-safe client.
package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/netguard"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/seal"
)

type (
	endpointTag struct{}
	eventTag    struct{}
	deliveryTag struct{}
)

type (
	EndpointID = ids.ID[endpointTag]
	EventID    = ids.ID[eventTag]
	DeliveryID = ids.ID[deliveryTag]
)

// Config is APP_WEBHOOKS_OUT_*.
type Config struct {
	Timeout   time.Duration `env:"TIMEOUT" envDefault:"10s"`
	AllowHTTP bool          `env:"ALLOW_HTTP"`
	// Keys encrypt endpoint secrets; empty means the app passes APP_CONNECTION_KEYS instead.
	Keys         []config.Secret `env:"KEYS"`
	DisableAfter int             `env:"DISABLE_AFTER" envDefault:"10"`
	Retain       time.Duration   `env:"RETAIN" envDefault:"720h"`
	// SecretOverlap is how long a rotated-out secret still signs beside the new one, so a receiver can
	// switch without refusing deliveries.
	SecretOverlap time.Duration `env:"SECRET_OVERLAP" envDefault:"24h"`
}

func (c Config) Validate(prod bool) error {
	var errs []error
	if c.Timeout < time.Second || c.Timeout > time.Minute {
		errs = append(errs, errors.New("webhooks out timeout must be 1s to 1m"))
	}
	if prod && c.AllowHTTP {
		errs = append(errs, errors.New("webhooks out allow http is refused in production"))
	}
	if c.DisableAfter < 1 {
		errs = append(errs, errors.New("webhooks out disable after must be at least 1"))
	}
	if c.SecretOverlap < 0 || c.SecretOverlap > 7*24*time.Hour {
		errs = append(errs, errors.New("webhooks out secret overlap must be 0 to 168h"))
	}
	if c.Retain < 24*time.Hour {
		errs = append(errs, errors.New("webhooks out retain must be at least 24h"))
	}
	for i, k := range c.Keys {
		errs = append(errs, config.RequireStrong(fmt.Sprintf("webhooks out key %d", i+1), k, prod))
	}
	return errors.Join(errs...)
}

type Status string

const (
	Active   Status = "active"
	Disabled Status = "disabled"
)

type DeliveryStatus string

const (
	Pending   DeliveryStatus = "pending"
	Succeeded DeliveryStatus = "succeeded"
	Failed    DeliveryStatus = "failed"
	Skipped   DeliveryStatus = "skipped"
)

const (
	KindDeliver     = "webhooks.deliver"
	kindPrune       = "webhooks.prune"
	maxEvents       = 50
	maxURL          = 2048
	maxDescription  = 200
	maxEventPayload = 64 << 10
	maxResponseRead = 64 << 10
	userAgent       = "keel-webhooks/1"
)

// DefaultRetries are the delays between attempts: about three days in all.
var DefaultRetries = []time.Duration{
	5 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour, 24 * time.Hour,
}

type Options struct {
	Queue  *jobs.Queue
	Tx     jobs.TxRunner
	Keys   *seal.Keyring
	Config Config
	// Audit records endpoint changes when set.
	Audit *audit.Recorder
	// OnDisabled runs in the transaction that disables a failing endpoint; apps email the admins here.
	OnDisabled func(ctx context.Context, tx db.Transaction, ep Endpoint) error
	// Client delivers; nil means the SSRF-safe client with the configured timeout.
	Client *http.Client
	// Retries replaces DefaultRetries (tests).
	Retries []time.Duration
}

type Service struct {
	o       Options
	client  *http.Client
	retries []time.Duration
}

func New(o Options) (*Service, error) {
	if o.Queue == nil || o.Tx == nil || o.Keys == nil {
		return nil, errors.New("webhooks: queue, transaction runner and keys are required")
	}
	if err := o.Config.Validate(false); err != nil {
		return nil, err
	}
	s := &Service{o: o, client: o.Client, retries: o.Retries}
	if s.client == nil {
		s.client = netguard.NewDialer(o.Config.Timeout).Client(o.Config.Timeout)
	}
	if len(s.retries) == 0 {
		s.retries = DefaultRetries
	}
	o.Queue.Handle(KindDeliver, jobs.Typed(s.deliver), jobs.MaxAttempts(len(s.retries)+1), jobs.Backoff(s.backoff),
		jobs.Timeout(2*o.Config.Timeout))
	o.Queue.Handle(kindPrune, func(ctx context.Context, _ jobs.Job) error { return s.prune(ctx) }, jobs.Global())
	o.Queue.Schedule(kindPrune, kindPrune, "23 4 * * *", time.UTC)
	return s, nil
}

func (s *Service) backoff(attempt int) time.Duration {
	return s.retries[min(max(attempt, 1), len(s.retries))-1]
}

type Endpoint struct {
	ID             EndpointID `json:"id"`
	URL            string     `json:"url"`
	Description    string     `json:"description"`
	Events         []string   `json:"events"`
	Status         Status     `json:"status"`
	FailureCount   int        `json:"failureCount"`
	DisabledAt     *time.Time `json:"disabledAt"`
	DisabledReason string     `json:"disabledReason"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	Version        int        `json:"version"`
}

type NewEndpoint struct {
	URL         string
	Description string
	Events      []string
}

var (
	ErrInvalidURL      = errors.New("webhooks: the URL must be an absolute https URL without credentials")
	ErrInvalidEvents   = errors.New("webhooks: events must be 1 to 50 event types or *")
	ErrInvalidEvent    = errors.New("webhooks: invalid event type or payload")
	ErrEndpointMissing = errors.New("webhooks: endpoint not found")
	ErrDeliveryMissing = errors.New("webhooks: delivery not found")
)

var eventPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

func (s *Service) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxURL || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return ErrInvalidURL
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !s.o.Config.AllowHTTP) || strings.Contains(u.Host, "%") {
		return ErrInvalidURL
	}
	if s.o.Config.AllowHTTP {
		return nil
	}
	return netguard.HostAllowed(u.Hostname())
}

func checkEvents(events []string) error {
	if len(events) == 0 || len(events) > maxEvents {
		return ErrInvalidEvents
	}
	for _, e := range events {
		if e != "*" && !eventPattern.MatchString(e) {
			return ErrInvalidEvents
		}
	}
	return nil
}

// NewSecret is a Standard Webhooks signing secret: whsec_ and 32 random bytes in base64.
func NewSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return "whsec_" + base64.StdEncoding.EncodeToString(b[:])
}

// CreateEndpoint adds an endpoint and returns its signing secret, shown to the caller once.
func (s *Service) CreateEndpoint(ctx context.Context, tx db.Transaction, in NewEndpoint) (Endpoint, string, error) {
	if err := s.checkURL(in.URL); err != nil {
		return Endpoint{}, "", err
	}
	if err := checkEvents(in.Events); err != nil {
		return Endpoint{}, "", err
	}
	if utf8.RuneCountInString(in.Description) > maxDescription {
		return Endpoint{}, "", fmt.Errorf("webhooks: description is longer than %d characters", maxDescription)
	}
	now := wallNow(ctx)
	ep := Endpoint{
		ID: ids.NewOf[endpointTag](), URL: in.URL, Description: in.Description, Events: slices.Clone(in.Events),
		Status: Active, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	secret := NewSecret()
	events, err := json.Marshal(ep.Events)
	if err != nil {
		return Endpoint{}, "", err
	}
	q := "INSERT INTO webhook_endpoints (id, url, description, events, secret, status, failure_count, created_at, updated_at, version) " +
		"VALUES (?, ?, ?, ?, ?, 'active', 0, ?, ?, 1)"
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), ep.ID, ep.URL, ep.Description, string(events),
		s.o.Keys.Seal([]byte(secret), ep.ID[:]), now, now); err != nil {
		return Endpoint{}, "", fmt.Errorf("webhooks: create endpoint: %w", err)
	}
	return ep, secret, s.audit(ctx, tx, "webhook_endpoint.create", ep.ID, nil, ep)
}

// RotateSecret replaces the secret of the endpoint at version and returns the new one, shown once. The
// old secret keeps signing beside it for SecretOverlap. Endpoint changes at a version other than the
// stored one are *occ.StaleError.
func (s *Service) RotateSecret(ctx context.Context, tx db.Transaction, id EndpointID, version int) (string, error) {
	secret := NewSecret()
	// previous_secret is assigned before secret: MySQL applies assignments left to right.
	if err := s.update(ctx, tx, id, version, "previous_secret = secret, previous_secret_until = ?, secret = ?",
		wallNow(ctx).Add(s.o.Config.SecretOverlap), s.o.Keys.Seal([]byte(secret), id[:])); err != nil {
		return "", err
	}
	return secret, s.audit(ctx, tx, "webhook_endpoint.rotate_secret", id, nil, nil)
}

// EnableEndpoint turns a disabled endpoint back on with a clean failure count.
func (s *Service) EnableEndpoint(ctx context.Context, tx db.Transaction, id EndpointID, version int) error {
	if err := s.update(ctx, tx, id, version, "status = 'active', failure_count = 0, disabled_at = NULL, disabled_reason = NULL"); err != nil {
		return err
	}
	return s.audit(ctx, tx, "webhook_endpoint.enable", id, nil, nil)
}

// DisableEndpoint stops deliveries to the endpoint until it is enabled again.
func (s *Service) DisableEndpoint(ctx context.Context, tx db.Transaction, id EndpointID, version int) error {
	if err := s.update(ctx, tx, id, version, "status = 'disabled', disabled_at = ?, disabled_reason = 'manual'", wallNow(ctx)); err != nil {
		return err
	}
	return s.audit(ctx, tx, "webhook_endpoint.disable", id, nil, nil)
}

func (s *Service) DeleteEndpoint(ctx context.Context, tx db.Transaction, id EndpointID, version int) error {
	before, err := s.Endpoint(ctx, tx, id)
	if err != nil {
		return err
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM webhook_endpoints WHERE id = ? AND version = ?"), id, version)
	if err != nil {
		return fmt.Errorf("webhooks: delete endpoint: %w", err)
	}
	if err := occ.Check(ctx, res, s.current(tx, id)); err != nil {
		return err
	}
	return s.audit(ctx, tx, "webhook_endpoint.delete", id, before, nil)
}

func (s *Service) update(ctx context.Context, tx db.Transaction, id EndpointID, version int, set string, args ...any) error {
	q := db.Rebind(tx.Dialect(), "UPDATE webhook_endpoints SET "+set+", version = version + 1, updated_at = ? WHERE id = ? AND version = ?")
	res, err := tx.Q().ExecContext(ctx, q, append(args, wallNow(ctx), id, version)...)
	if err != nil {
		return fmt.Errorf("webhooks: update endpoint: %w", err)
	}
	return occ.Check(ctx, res, s.current(tx, id))
}

func (s *Service) current(tx db.Transaction, id EndpointID) func(ctx context.Context) (occ.Current, error) {
	return func(ctx context.Context) (occ.Current, error) {
		ep, err := s.Endpoint(ctx, tx, id)
		if err != nil {
			return occ.Current{}, err
		}
		return occ.Current{Version: ep.Version, ChangedAt: ep.UpdatedAt}, nil
	}
}

func (s *Service) audit(ctx context.Context, tx db.Transaction, action string, id EndpointID, before, after any) error {
	if s.o.Audit == nil {
		return nil
	}
	return s.o.Audit.Record(ctx, tx, audit.Event{Action: action, Entity: "webhook_endpoint", EntityID: id.String(), Before: before, After: after})
}

const endpointColumns = "id, url, description, events, status, failure_count, disabled_at, disabled_reason, created_at, updated_at, version"

func (s *Service) Endpoint(ctx context.Context, tx db.Transaction, id EndpointID) (Endpoint, error) {
	list, err := s.queryEndpoints(ctx, tx, "SELECT "+endpointColumns+" FROM webhook_endpoints WHERE id = ?", id)
	if err != nil {
		return Endpoint{}, err
	}
	if len(list) == 0 {
		return Endpoint{}, ErrEndpointMissing
	}
	return list[0], nil
}

func (s *Service) Endpoints(ctx context.Context, tx db.Transaction) ([]Endpoint, error) {
	return s.queryEndpoints(ctx, tx, "SELECT "+endpointColumns+" FROM webhook_endpoints ORDER BY created_at, id")
}

func (s *Service) queryEndpoints(ctx context.Context, tx db.Transaction, query string, args ...any) ([]Endpoint, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), query), args...)
	if err != nil {
		return nil, fmt.Errorf("webhooks: endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Endpoint
	for rows.Next() {
		var ep Endpoint
		var events []byte
		var reason *string
		if err := rows.Scan(&ep.ID, &ep.URL, &ep.Description, &events, &ep.Status, &ep.FailureCount, &ep.DisabledAt, &reason,
			&ep.CreatedAt, &ep.UpdatedAt, &ep.Version); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(events, &ep.Events); err != nil {
			return nil, fmt.Errorf("webhooks: endpoint events: %w", err)
		}
		if reason != nil {
			ep.DisabledReason = *reason
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// Emit records an event in tx and queues a delivery to every active endpoint subscribed to its type, so
// a rolled-back change notifies nobody. Payloads carry ids and a small snapshot (at most 64 KiB).
func (s *Service) Emit(ctx context.Context, tx db.Transaction, eventType string, payload any) (EventID, error) {
	if !eventPattern.MatchString(eventType) {
		return EventID{}, ErrInvalidEvent
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > maxEventPayload {
		return EventID{}, errors.Join(ErrInvalidEvent, err)
	}
	now := wallNow(ctx)
	id := ids.NewOf[eventTag]()
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "INSERT INTO webhook_events (id, type, payload, created_at) VALUES (?, ?, ?, ?)"),
		id, eventType, string(raw), now); err != nil {
		return EventID{}, fmt.Errorf("webhooks: emit: %w", err)
	}
	endpoints, err := s.queryEndpoints(ctx, tx, "SELECT "+endpointColumns+" FROM webhook_endpoints WHERE status = 'active'")
	if err != nil {
		return EventID{}, err
	}
	for _, ep := range endpoints {
		if !slices.Contains(ep.Events, "*") && !slices.Contains(ep.Events, eventType) {
			continue
		}
		if _, err := s.queueDelivery(ctx, tx, id, ep.ID, now); err != nil {
			return EventID{}, err
		}
	}
	return id, nil
}

type deliverPayload struct {
	Delivery DeliveryID `json:"delivery"`
}

func (s *Service) queueDelivery(ctx context.Context, tx db.Transaction, event EventID, endpoint EndpointID, now time.Time) (DeliveryID, error) {
	id := ids.NewOf[deliveryTag]()
	q := "INSERT INTO webhook_out_deliveries (id, event_id, endpoint_id, status, attempts, created_at, updated_at) VALUES (?, ?, ?, 'pending', 0, ?, ?)"
	args := []any{id, event, endpoint, now, now}
	// An operator transaction (a replay from the shell) sets no tenant for the column default; the
	// context carries the delivery's.
	if tenant, ok := db.TenantOf(ctx); ok && tx.Tenancy() {
		q = "INSERT INTO webhook_out_deliveries (id, event_id, endpoint_id, status, attempts, created_at, updated_at, tenant_id) VALUES (?, ?, ?, 'pending', 0, ?, ?, ?)"
		args = append(args, tenant)
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), args...); err != nil {
		return DeliveryID{}, fmt.Errorf("webhooks: queue delivery: %w", err)
	}
	if _, err := s.o.Queue.Enqueue(ctx, tx, KindDeliver, deliverPayload{Delivery: id}); err != nil {
		return DeliveryID{}, err
	}
	return id, nil
}

// Replay sends a delivery's event to its endpoint again as a new delivery with the same webhook-id, so
// a receiver that already applied it can recognise it. Under tenancy the new delivery and its job are
// the original delivery's tenant's, also when tx is an operator transaction.
func (s *Service) Replay(ctx context.Context, tx db.Transaction, id DeliveryID) (DeliveryID, error) {
	cols := "event_id, endpoint_id"
	if tx.Tenancy() {
		cols += ", tenant_id"
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT "+cols+" FROM webhook_out_deliveries WHERE id = ?"), id)
	if err != nil {
		return DeliveryID{}, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return DeliveryID{}, errors.Join(rows.Err(), ErrDeliveryMissing)
	}
	var event EventID
	var endpoint EndpointID
	var tenant uuid.UUID
	dest := []any{&event, &endpoint}
	if tx.Tenancy() {
		dest = append(dest, &tenant)
	}
	if err := rows.Scan(dest...); err != nil {
		return DeliveryID{}, err
	}
	if err := rows.Close(); err != nil {
		return DeliveryID{}, err
	}
	if tenant != uuid.Nil {
		ctx = db.WithTenant(ctx, tenant)
	}
	return s.queueDelivery(ctx, tx, event, endpoint, wallNow(ctx))
}

// Delivery is one attempt series of an event to an endpoint.
type Delivery struct {
	ID             DeliveryID
	EventID        EventID
	EventType      string
	EndpointID     EndpointID
	Status         DeliveryStatus
	Attempts       int
	LastStatusCode *int
	LastErrorCode  *string
	CreatedAt      time.Time
}

// Deliveries lists the latest deliveries, newest first.
func (s *Service) Deliveries(ctx context.Context, tx db.Transaction, limit int) ([]Delivery, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT d.id, d.event_id, e.type, d.endpoint_id, d.status, d.attempts, "+
		"d.last_status_code, d.last_error_code, d.created_at FROM webhook_out_deliveries d JOIN webhook_events e ON e.id = d.event_id "+
		"ORDER BY d.created_at DESC, d.id DESC LIMIT ?"), limit)
	if err != nil {
		return nil, fmt.Errorf("webhooks: deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.EventID, &d.EventType, &d.EndpointID, &d.Status, &d.Attempts, &d.LastStatusCode, &d.LastErrorCode, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Service) prune(ctx context.Context) error {
	before := wallNow(ctx).Add(-s.o.Config.Retain)
	for {
		var n int64
		err := s.o.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			q := "DELETE FROM webhook_events WHERE id IN (SELECT id FROM webhook_events WHERE created_at < ? LIMIT 500)"
			if tx.Dialect() == db.MySQL {
				q = "DELETE FROM webhook_events WHERE created_at < ? ORDER BY created_at LIMIT 500"
			}
			res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), before)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil || n < 500 {
			return err
		}
	}
}

func wallNow(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

// RekeyResult counts the secrets Rekey rewrapped and those no configured key opens.
type RekeyResult struct {
	Rewrapped  int
	Unreadable int
}

const rekeyBatch = 100

// Rekey reseals every endpoint secret that an older key opened with the newest key, in batches, so the
// older key can then be removed.
func (s *Service) Rekey(ctx context.Context) (RekeyResult, error) {
	var total RekeyResult
	after := "00000000-0000-0000-0000-000000000000"
	for {
		var batch RekeyResult
		var n int
		var last string
		err := s.o.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			batch, n, last = RekeyResult{}, 0, after
			rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(),
				"SELECT id, secret, previous_secret, previous_secret_until FROM webhook_endpoints WHERE id > ? ORDER BY id LIMIT ? FOR UPDATE"), after, rekeyBatch)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			type row struct {
				id               EndpointID
				sealed, previous []byte
				until            *time.Time
			}
			var list []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.sealed, &r.previous, &r.until); err != nil {
					return err
				}
				list = append(list, r)
			}
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				return err
			}
			for _, r := range list {
				n, last = n+1, r.id.String()
				plain, stale, err := s.o.Keys.Open(r.sealed, r.id[:])
				switch {
				case err != nil:
					batch.Unreadable++
				case stale:
					if err := s.reseal(ctx, tx, r.id, r.sealed, plain); err != nil {
						return err
					}
					batch.Rewrapped++
				}
				expired := r.until == nil || !r.until.After(wallNow(ctx))
				if err := s.resealPrevious(ctx, tx, r.id, r.previous, expired); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return total, fmt.Errorf("webhooks: rekey: %w", err)
		}
		total.Rewrapped += batch.Rewrapped
		total.Unreadable += batch.Unreadable
		if n < rekeyBatch {
			return total, nil
		}
		after = last
	}
}

// resealPrevious rewraps a rotated-out secret an older key opened; one past its overlap, or one no key
// opens, is dropped, since it could never sign again.
func (s *Service) resealPrevious(ctx context.Context, tx db.Transaction, id EndpointID, sealed []byte, expired bool) error {
	if len(sealed) == 0 {
		return nil
	}
	if expired {
		_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(),
			"UPDATE webhook_endpoints SET previous_secret = NULL, previous_secret_until = NULL WHERE id = ?"), id)
		return err
	}
	plain, stale, err := s.o.Keys.Open(sealed, id[:])
	var next []byte
	switch {
	case err != nil:
	case stale:
		next = s.o.Keys.Seal(plain, id[:])
	default:
		return nil
	}
	_, err = tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE webhook_endpoints SET previous_secret = ? WHERE id = ?"), next, id)
	return err
}
