package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
)

// ErrDeliveryID is a delivery whose id is missing, not 1 to 255 printable ASCII characters, or not a string.
var ErrDeliveryID = errors.New("webhook: the delivery id is missing or invalid")

// TimestampedOptions configure one sender that signs with a timestamped hex HMAC-SHA256 header,
// `t=<unix>,v1=<hex>` over "{t}.{raw body}" (the scheme Stripe uses). Secrets are used as they are, newest
// first. Header names the signature header. The delivery id comes from the IDHeader header or, when the
// id is only in the signed body, from the IDField top-level string field of the JSON body; set one.
type TimestampedOptions struct {
	Source     string
	Secrets    []string
	Tolerance  time.Duration
	Production bool
	Header     string
	IDHeader   string
	IDField    string
}

// TimestampedVerifier checks one sender's deliveries signed with the timestamped hex scheme.
type TimestampedVerifier struct {
	source    string
	keys      [][]byte
	tolerance time.Duration
	header    string
	idHeader  string
	idField   string
}

func NewTimestampedVerifier(o TimestampedOptions) (*TimestampedVerifier, error) {
	if !sourcePattern.MatchString(o.Source) {
		return nil, ErrSource
	}
	if o.Header == "" {
		return nil, errors.New("webhook: the signature header name is required")
	}
	if (o.IDHeader == "") == (o.IDField == "") {
		return nil, errors.New("webhook: set exactly one of the delivery id header and the delivery id field")
	}
	if len(o.Secrets) == 0 {
		return nil, errors.New("webhook: at least one secret is required")
	}
	v := &TimestampedVerifier{source: o.Source, tolerance: o.Tolerance, header: o.Header, idHeader: o.IDHeader, idField: o.IDField}
	if v.tolerance <= 0 {
		v.tolerance = DefaultTolerance
	}
	for _, s := range o.Secrets {
		if s == "" {
			return nil, errors.New("webhook: a secret is empty")
		}
		if o.Production && len(s) < MinSecretBytes {
			return nil, ErrWeakSecret
		}
		v.keys = append(v.keys, []byte(s))
	}
	return v, nil
}

// Verify checks the signed time against the wall clock and the signature in constant time, then returns
// the delivery id; the caller passes it to v.Seen in the transaction that applies the delivery.
func (v *TimestampedVerifier) Verify(ctx context.Context, h http.Header, body []byte) (string, error) {
	value := h.Get(v.header)
	if value == "" || len(value) > maxSignatureLen {
		return "", ErrMissingHeaders
	}
	stamp, sigs, ok := parseTimestamped(value)
	if !ok {
		return "", ErrMissingHeaders
	}
	sec, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return "", ErrTimestamp
	}
	now := clock.Wall(ctx).Now()
	ts := time.Unix(sec, 0)
	if ts.Before(now.Add(-v.tolerance)) || ts.After(now.Add(v.tolerance)) {
		return "", ErrTimestamp
	}
	if !v.matches(stamp, sigs, body) {
		return "", ErrSignature
	}
	return v.deliveryID(h, body)
}

func (v *TimestampedVerifier) matches(stamp string, sigs [][]byte, body []byte) bool {
	for _, key := range v.keys {
		want := timestampedMAC(key, stamp, body)
		for _, sig := range sigs {
			if hmac.Equal(sig, want) {
				return true
			}
		}
	}
	return false
}

func (v *TimestampedVerifier) deliveryID(h http.Header, body []byte) (string, error) {
	id := h.Get(v.idHeader)
	if v.idField != "" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			return "", ErrDeliveryID
		}
		if err := json.Unmarshal(fields[v.idField], &id); err != nil {
			return "", ErrDeliveryID
		}
	}
	if !validID(id) {
		return "", ErrDeliveryID
	}
	return id, nil
}

// Seen records the delivery id for this sender in tx and reports whether it was already recorded.
func (v *TimestampedVerifier) Seen(ctx context.Context, tx db.Transaction, id string) (bool, error) {
	return seen(ctx, tx, v.source, id)
}

// SignTimestamped returns the signature header value for a delivery.
func SignTimestamped(secret string, ts time.Time, body []byte) string {
	stamp := strconv.FormatInt(ts.Unix(), 10)
	return "t=" + stamp + ",v1=" + hex.EncodeToString(timestampedMAC([]byte(secret), stamp, body))
}

func timestampedMAC(key []byte, stamp string, body []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(stamp))
	h.Write([]byte{'.'})
	h.Write(body)
	return h.Sum(nil)
}

// parseTimestamped reads one t and up to maxSignatures v1 entries from comma-separated key=value pairs,
// skipping other schemes. A second t, or an entry that is not key=value, makes the header malformed.
func parseTimestamped(header string) (stamp string, sigs [][]byte, ok bool) {
	for entry := range strings.SplitSeq(header, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(entry), "=")
		if !found {
			return "", nil, false
		}
		switch key {
		case "t":
			if stamp != "" {
				return "", nil, false
			}
			stamp = value
		case "v1":
			raw, err := hex.DecodeString(value)
			if err == nil && len(raw) == sha256.Size && len(sigs) < maxSignatures {
				sigs = append(sigs, raw)
			}
		}
	}
	return stamp, sigs, stamp != ""
}
