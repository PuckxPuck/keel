// Package webhook verifies and signs Standard Webhooks (https://www.standardwebhooks.com), verifies the
// timestamped hex scheme (t=<unix>,v1=<hex>), and records delivery ids so a replayed delivery is recognised.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"

	DefaultTolerance = 5 * time.Minute
	secretPrefix     = "whsec_"
	maxID            = 255
	maxSignatureLen  = 2048
	// maxSignatures bounds the work one request can cause: each is compared with every secret's MAC.
	maxSignatures = 5
	// MinSecretBytes is the shortest decoded secret production accepts.
	MinSecretBytes = 24
	CodeInvalid    = "webhook_signature_invalid"
)

var (
	ErrMissingHeaders = errors.New("webhook: missing webhook-id, webhook-timestamp or webhook-signature")
	ErrTimestamp      = errors.New("webhook: timestamp is invalid or outside the tolerance")
	ErrSignature      = errors.New("webhook: no matching signature")
	ErrSecret         = errors.New("webhook: secret must be whsec_ followed by base64")
	ErrWeakSecret     = errors.New("webhook: secret must decode to at least 24 bytes in production")
	ErrSource         = errors.New("webhook: source must be 1 to 64 lower case letters, digits, - and _")
)

// Headers are the three Standard Webhooks headers; embed it in a Huma input struct.
type Headers struct {
	ID        string `header:"webhook-id" maxLength:"255"`
	Timestamp string `header:"webhook-timestamp" maxLength:"20"`
	Signature string `header:"webhook-signature" maxLength:"2048"`
}

func HeadersOf(h http.Header) Headers {
	return Headers{ID: h.Get(HeaderID), Timestamp: h.Get(HeaderTimestamp), Signature: h.Get(HeaderSignature)}
}

// Options configure one sender. Source names it (deliveries are recorded per source, since ids are only
// unique per sender); Secrets are newest first, so a secret rotates without downtime.
type Options struct {
	Source     string
	Secrets    []string
	Tolerance  time.Duration
	Production bool
}

// Verifier checks one sender's deliveries.
type Verifier struct {
	source    string
	keys      [][]byte
	tolerance time.Duration
}

var sourcePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func NewVerifier(o Options) (*Verifier, error) {
	if !sourcePattern.MatchString(o.Source) {
		return nil, ErrSource
	}
	if len(o.Secrets) == 0 {
		return nil, errors.New("webhook: at least one secret is required")
	}
	v := &Verifier{source: o.Source, tolerance: o.Tolerance}
	if v.tolerance <= 0 {
		v.tolerance = DefaultTolerance
	}
	for _, s := range o.Secrets {
		key, err := decodeSecret(s)
		if err != nil {
			return nil, err
		}
		if o.Production && len(key) < MinSecretBytes {
			return nil, ErrWeakSecret
		}
		v.keys = append(v.keys, key)
	}
	return v, nil
}

// Verify checks the timestamp against the wall clock and the signature in constant time; the caller
// then passes h.ID to v.Seen in the transaction that applies the delivery.
func (v *Verifier) Verify(ctx context.Context, h Headers, body []byte) error {
	if h.Timestamp == "" || h.Signature == "" || !validID(h.ID) || len(h.Signature) > maxSignatureLen {
		return ErrMissingHeaders
	}
	sec, err := strconv.ParseInt(h.Timestamp, 10, 64)
	if err != nil {
		return ErrTimestamp
	}
	now := clock.Wall(ctx).Now()
	ts := time.Unix(sec, 0)
	if ts.Before(now.Add(-v.tolerance)) || ts.After(now.Add(v.tolerance)) {
		return ErrTimestamp
	}
	sigs := parseSignatures(h.Signature)
	if len(sigs) == 0 {
		return ErrSignature
	}
	for _, key := range v.keys {
		want := mac(key, h.ID, h.Timestamp, body)
		for _, sig := range sigs {
			if hmac.Equal(sig, want) {
				return nil
			}
		}
	}
	return ErrSignature
}

// Sign returns the webhook-signature value for a delivery.
func Sign(secret, id string, ts time.Time, body []byte) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return "v1," + base64.StdEncoding.EncodeToString(mac(key, id, strconv.FormatInt(ts.Unix(), 10), body)), nil
}

func mac(key []byte, id, ts string, body []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id))
	h.Write([]byte{'.'})
	h.Write([]byte(ts))
	h.Write([]byte{'.'})
	h.Write(body)
	return h.Sum(nil)
}

func decodeSecret(s string) ([]byte, error) {
	raw, ok := strings.CutPrefix(s, secretPrefix)
	if !ok {
		return nil, ErrSecret
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) == 0 {
		return nil, ErrSecret
	}
	return key, nil
}

// parseSignatures reads up to maxSignatures space-separated "v1,<base64>" entries, skipping other
// versions and junk.
func parseSignatures(header string) [][]byte {
	var out [][]byte
	for _, entry := range strings.Fields(header) {
		if len(out) == maxSignatures {
			break
		}
		version, sig, ok := strings.Cut(entry, ",")
		if !ok || version != "v1" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(sig)
		if err != nil || len(raw) != sha256.Size {
			continue
		}
		out = append(out, raw)
	}
	return out
}

// Seen records the delivery id for this sender in tx and reports whether it was already recorded. Call
// it in the transaction that applies the delivery, so a rolled-back delivery can be retried.
func (v *Verifier) Seen(ctx context.Context, tx db.Transaction, id string) (bool, error) {
	return seen(ctx, tx, v.source, id)
}

func seen(ctx context.Context, tx db.Transaction, source, id string) (bool, error) {
	if !validID(id) {
		return false, ErrMissingHeaders
	}
	q := "INSERT INTO webhook_deliveries (source, id, received_at) VALUES (?, ?, ?) ON CONFLICT (source, id) DO NOTHING"
	if tx.Dialect() == db.MySQL {
		q = "INSERT INTO webhook_deliveries (source, id, received_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE id = id"
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), source, id, clock.Wall(ctx).Now().UTC())
	if err != nil {
		return false, fmt.Errorf("record webhook delivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

// Prune deletes delivery ids received before before; keep them longer than any sender retries.
func Prune(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM webhook_deliveries WHERE received_at < ?"), before.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune webhook deliveries: %w", err)
	}
	return res.RowsAffected()
}

func validID(s string) bool {
	if s == "" || len(s) > maxID {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Mapper answers every verification failure the same way, so a sender learns nothing about which check failed.
func Mapper(err error) (*problem.Problem, bool) {
	if errors.Is(err, ErrMissingHeaders) || errors.Is(err, ErrTimestamp) || errors.Is(err, ErrSignature) || errors.Is(err, ErrDeliveryID) {
		return problem.New(http.StatusUnauthorized, CodeInvalid, "the webhook signature is missing or invalid"), true
	}
	return nil, false
}
