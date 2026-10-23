package webhooks

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/netguard"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

type target struct {
	status       DeliveryStatus
	endpoint     Endpoint
	sealed       []byte
	previous     []byte
	eventID      EventID
	eventType    string
	payload      json.RawMessage
	eventCreated time.Time
}

func (s *Service) load(ctx context.Context, tx db.Transaction, id DeliveryID) (target, bool, error) {
	q := "SELECT d.status, d.endpoint_id, p.url, p.status, p.secret, " +
		"CASE WHEN p.previous_secret_until > ? THEN p.previous_secret END, e.id, e.type, e.payload, e.created_at " +
		"FROM webhook_out_deliveries d JOIN webhook_endpoints p ON p.id = d.endpoint_id JOIN webhook_events e ON e.id = d.event_id WHERE d.id = ?"
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), wallNow(ctx), id)
	if err != nil {
		return target{}, false, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return target{}, false, rows.Err()
	}
	var t target
	var payload []byte
	if err := rows.Scan(&t.status, &t.endpoint.ID, &t.endpoint.URL, &t.endpoint.Status, &t.sealed, &t.previous, &t.eventID, &t.eventType, &payload, &t.eventCreated); err != nil {
		return target{}, false, err
	}
	t.payload = payload
	return t, true, rows.Close()
}

type attempt struct {
	ok     bool
	status int
	code   string
	err    error
}

// deliver posts one attempt. Every outcome write carries the job attempt as the delivery's generation and
// applies only when it is newer than the stored one, so a worker that lost its lease cannot overwrite the
// outcome of the run that replaced it.
func (s *Service) deliver(ctx context.Context, job jobs.Job, p deliverPayload) error {
	gen := job.Attempt
	var t target
	var found bool
	err := s.o.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		if t, found, err = s.load(ctx, tx, p.Delivery); err != nil || !found {
			return err
		}
		if t.status == Pending && t.endpoint.Status != Active {
			_, err = setDelivery(ctx, tx, p.Delivery, gen, Skipped, attempt{code: "endpoint_disabled"}, false)
		}
		return err
	})
	if err != nil || !found || t.status != Pending || t.endpoint.Status != Active {
		return err
	}
	if u, err := url.Parse(t.endpoint.URL); err != nil || (u.Scheme != "https" && !s.o.Config.AllowHTTP) {
		return s.refuse(ctx, p.Delivery, gen, "insecure_url", errors.New("webhooks: the endpoint URL is not https"))
	}
	secret, stale, err := s.o.Keys.Open(t.sealed, t.endpoint.ID[:])
	if err != nil {
		return s.refuse(ctx, p.Delivery, gen, "secret", fmt.Errorf("webhooks: endpoint secret: %w", err))
	}
	secrets := []string{string(secret)}
	// A previous secret no key opens only loses its overlap; the current one still signs.
	if old, _, err := s.o.Keys.Open(t.previous, t.endpoint.ID[:]); len(t.previous) > 0 && err == nil {
		secrets = append(secrets, string(old))
	}
	a := s.post(ctx, t, secrets)
	if !a.ok && ctx.Err() != nil {
		// Shutdown or a lost lease cut the attempt short; the queue runs it again without spending it.
		return context.Cause(ctx)
	}
	final := job.Attempt >= job.MaxAttempts
	err = s.o.Tx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Transaction) error {
		if stale {
			if err := s.reseal(ctx, tx, t.endpoint.ID, t.sealed, secret); err != nil {
				return err
			}
		}
		return s.recordAttempt(ctx, tx, p.Delivery, t.endpoint.ID, gen, a, final)
	})
	switch {
	case err != nil:
		return err
	case a.ok:
		return nil
	}
	return a.err
}

// refuse fails the delivery for good: retrying cannot help.
func (s *Service) refuse(ctx context.Context, id DeliveryID, gen int, code string, cause error) error {
	err := s.o.Tx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Transaction) error {
		_, err := setDelivery(ctx, tx, id, gen, Failed, attempt{code: code, err: cause}, false)
		return err
	})
	return jobs.Permanent(errors.Join(cause, err))
}

// reseal rewraps a secret an older key opened with the current key, unless it changed meanwhile.
func (s *Service) reseal(ctx context.Context, tx db.Transaction, id EndpointID, old, secret []byte) error {
	_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE webhook_endpoints SET secret = ? WHERE id = ? AND secret = ?"),
		s.o.Keys.Seal(secret, id[:]), id, old)
	return err
}

func (s *Service) post(ctx context.Context, t target, secrets []string) attempt {
	body, err := json.Marshal(struct {
		Type      string          `json:"type"`
		Timestamp time.Time       `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}{t.eventType, t.eventCreated, t.payload})
	if err != nil {
		return attempt{code: "encode", err: err}
	}
	msgID, now := t.eventID.String(), wallNow(ctx)
	sigs := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		sig, err := webhook.Sign(secret, msgID, now, body)
		if err != nil {
			return attempt{code: "secret", err: err}
		}
		sigs = append(sigs, sig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint.URL, bytes.NewReader(body))
	if err != nil {
		return attempt{code: "request", err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(webhook.HeaderID, msgID)
	req.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
	req.Header.Set(webhook.HeaderSignature, strings.Join(sigs, " "))
	resp, err := s.client.Do(req)
	if err != nil {
		code := "network"
		if errors.Is(err, netguard.ErrBlocked) {
			code = "blocked_address"
		}
		return attempt{code: code, err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseRead)) // only the status matters
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return attempt{ok: true, status: resp.StatusCode}
	}
	return attempt{status: resp.StatusCode, code: "http_status", err: fmt.Errorf("webhooks: endpoint answered %d", resp.StatusCode)}
}

// recordAttempt counts consecutive failures on the endpoint. A delivery that has spent its last attempt
// disables the endpoint once that count reaches DisableAfter, so one bad night does not, but days of
// failures do. Only the write that wins the generation check touches the endpoint.
func (s *Service) recordAttempt(ctx context.Context, tx db.Transaction, id DeliveryID, endpoint EndpointID, gen int, a attempt, final bool) error {
	status := Pending
	switch {
	case a.ok:
		status = Succeeded
	case final:
		status = Failed
	}
	won, err := setDelivery(ctx, tx, id, gen, status, a, true)
	if err != nil || !won {
		return err
	}
	now := wallNow(ctx)
	if a.ok {
		_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE webhook_endpoints SET failure_count = 0 WHERE id = ? AND failure_count > 0"), endpoint)
		return err
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE webhook_endpoints SET failure_count = failure_count + 1 WHERE id = ?"), endpoint); err != nil {
		return err
	}
	if !final {
		return nil
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE webhook_endpoints SET status = 'disabled', disabled_at = ?, "+
		"disabled_reason = 'failing', version = version + 1, updated_at = ? WHERE id = ? AND status = 'active' AND failure_count >= ?"),
		now, now, endpoint, s.o.Config.DisableAfter)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 || s.o.OnDisabled == nil {
		return err
	}
	ep, err := s.Endpoint(ctx, tx, endpoint)
	if err != nil {
		return err
	}
	return s.o.OnDisabled(ctx, tx, ep)
}

// setDelivery records an outcome of generation gen and reports whether it was newer than the stored one.
func setDelivery(ctx context.Context, tx db.Transaction, id DeliveryID, gen int, status DeliveryStatus, a attempt, attempted bool) (bool, error) {
	var code, msg sql.NullString
	var httpStatus sql.NullInt64
	if a.code != "" {
		code = sql.NullString{String: a.code, Valid: true}
	}
	if a.err != nil {
		msg = sql.NullString{String: jobs.Redact(a.err.Error()), Valid: true}
	}
	if a.status != 0 {
		httpStatus = sql.NullInt64{Int64: int64(a.status), Valid: true}
	}
	var delivered sql.NullTime
	now := wallNow(ctx)
	if status == Succeeded {
		delivered = sql.NullTime{Time: now, Valid: true}
	}
	inc := 0
	if attempted {
		inc = 1
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE webhook_out_deliveries SET status = ?, generation = ?, attempts = attempts + ?, "+
		"last_status_code = ?, last_error_code = ?, last_error = ?, delivered_at = ?, updated_at = ? WHERE id = ? AND generation < ?"),
		string(status), gen, inc, httpStatus, code, msg, delivered, now, id, gen)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
