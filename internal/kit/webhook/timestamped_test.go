package webhook_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

// The vectors were computed with openssl dgst -sha256 -hmac over "1700000000." and the body.
const (
	oldSecret = "old-secret-that-is-long-enough-1" //nolint:gosec // a test-only secret
	newSecret = "new-secret-that-is-long-enough-2" //nolint:gosec // a test-only secret
	tsBody    = `{"id":"evt_1","type":"thing.happened"}`
	tsAt      = 1700000000
	oldSig    = "cc29d76a4bc4e6bcd29e300ec27b2bbf56266deccf3fe59281467d6917fb4d05"
	newSig    = "7535042d37ac58cea108b8957f96dbda50d3bf78c858dea87cbf38083c022551"
	sigHeader = "X-Signature"
)

func timestamped(t testing.TB, o webhook.TimestampedOptions) *webhook.TimestampedVerifier {
	t.Helper()
	o.Source, o.Header, o.Production = "acme", sigHeader, true
	if o.Secrets == nil {
		o.Secrets = []string{newSecret, oldSecret}
	}
	v, err := webhook.NewTimestampedVerifier(o)
	require.NoError(t, err)
	return v
}

func TestSignTimestamped_MatchesTheVectors(t *testing.T) {
	assert.Equal(t, "t=1700000000,v1="+oldSig, webhook.SignTimestamped(oldSecret, time.Unix(tsAt, 0), []byte(tsBody)))
	assert.Equal(t, "t=1700000000,v1="+newSig, webhook.SignTimestamped(newSecret, time.Unix(tsAt, 0), []byte(tsBody)))
}

func TestNewTimestampedVerifier_Refuses(t *testing.T) {
	tests := []struct {
		name string
		o    webhook.TimestampedOptions
		want string
	}{
		{"a short secret in production", webhook.TimestampedOptions{Source: "acme", Header: sigHeader, IDField: "id", Secrets: []string{"short"}, Production: true}, "at least 24 bytes"},
		{"no signature header", webhook.TimestampedOptions{Source: "acme", IDField: "id", Secrets: []string{newSecret}}, "header name"},
		{"no delivery id source", webhook.TimestampedOptions{Source: "acme", Header: sigHeader, Secrets: []string{newSecret}}, "exactly one"},
		{"two delivery id sources", webhook.TimestampedOptions{Source: "acme", Header: sigHeader, IDHeader: "X-Id", IDField: "id", Secrets: []string{newSecret}}, "exactly one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := webhook.NewTimestampedVerifier(tt.o)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestTimestampedVerify(t *testing.T) {
	byField := timestamped(t, webhook.TimestampedOptions{IDField: "id"})
	byHeader := timestamped(t, webhook.TimestampedOptions{IDHeader: "X-Delivery"})
	signed := func(sig string) http.Header { return http.Header{sigHeader: {sig}, "X-Delivery": {"del_9"}} }
	junk := strings.Repeat("v1="+strings.Repeat("ab", 32)+",", 5)
	tests := []struct {
		name   string
		v      *webhook.TimestampedVerifier
		h      http.Header
		body   string
		now    int64
		want   error
		wantID string
	}{
		{"signed with the old secret", byField, signed("t=1700000000,v1=" + oldSig), tsBody, tsAt, nil, "evt_1"},
		{"signed with the new secret", byField, signed("t=1700000000,v1=" + newSig), tsBody, tsAt, nil, "evt_1"},
		{"the id from a header", byHeader, signed("t=1700000000,v1=" + newSig), tsBody, tsAt, nil, "del_9"},
		{"one of several signatures and another scheme", byField, signed("t=1700000000, v0=abc, v1=" + strings.Repeat("00", 32) + ", v1=" + oldSig), tsBody, tsAt, nil, "evt_1"},
		{"within tolerance", byField, signed("t=1700000000,v1=" + newSig), tsBody, tsAt + 299, nil, "evt_1"},
		{"stale", byField, signed("t=1700000000,v1=" + newSig), tsBody, tsAt + 301, webhook.ErrTimestamp, ""},
		{"from the future", byField, signed("t=1700000000,v1=" + newSig), tsBody, tsAt - 301, webhook.ErrTimestamp, ""},
		{"body changed", byField, signed("t=1700000000,v1=" + newSig), `{"id":"evt_2","type":"thing.happened"}`, tsAt, webhook.ErrSignature, ""},
		{"time changed", byField, signed("t=1700000001,v1=" + newSig), tsBody, tsAt, webhook.ErrSignature, ""},
		{"an unknown secret", byField, signed(webhook.SignTimestamped(strings.Repeat("x", 32), time.Unix(tsAt, 0), []byte(tsBody))), tsBody, tsAt, webhook.ErrSignature, ""},
		{"only the first five signatures are compared", byField, signed("t=1700000000," + junk + "v1=" + newSig), tsBody, tsAt, webhook.ErrSignature, ""},
		{"no header", byField, http.Header{}, tsBody, tsAt, webhook.ErrMissingHeaders, ""},
		{"malformed: not key=value", byField, signed("1700000000," + newSig), tsBody, tsAt, webhook.ErrMissingHeaders, ""},
		{"malformed: no time", byField, signed("v1=" + newSig), tsBody, tsAt, webhook.ErrMissingHeaders, ""},
		{"malformed: two times", byField, signed("t=1700000000,t=1700000001,v1=" + newSig), tsBody, tsAt, webhook.ErrMissingHeaders, ""},
		{"malformed: time not a number", byField, signed("t=soon,v1=" + newSig), tsBody, tsAt, webhook.ErrTimestamp, ""},
		{"malformed: signature not hex", byField, signed("t=1700000000,v1=" + strings.Repeat("zz", 32)), tsBody, tsAt, webhook.ErrSignature, ""},
		{"a signed body without the id field", byField, signed(webhook.SignTimestamped(newSecret, time.Unix(tsAt, 0), []byte(`{"type":"x"}`))), `{"type":"x"}`, tsAt, webhook.ErrDeliveryID, ""},
		{"a signed body whose id is a number", byField, signed(webhook.SignTimestamped(newSecret, time.Unix(tsAt, 0), []byte(`{"id":7}`))), `{"id":7}`, tsAt, webhook.ErrDeliveryID, ""},
		{"no id header", byHeader, http.Header{sigHeader: {"t=1700000000,v1=" + newSig}}, tsBody, tsAt, webhook.ErrDeliveryID, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := tt.v.Verify(at(t, tt.now), tt.h, []byte(tt.body))
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
				_, mapped := webhook.Mapper(err)
				assert.True(t, mapped, "every failure is the same 401")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func FuzzTimestampedVerify(f *testing.F) {
	f.Add("t=1700000000,v1="+newSig, tsBody)
	f.Add("t=1700000000,,v1=,=,t", "")
	f.Add("t=-1,v1="+strings.Repeat("0", 2000), "{}")
	v := timestamped(f, webhook.TimestampedOptions{IDField: "id", Secrets: []string{newSecret}})
	f.Fuzz(func(t *testing.T, sig, body string) {
		_, err := v.Verify(at(t, tsAt), http.Header{sigHeader: {sig}}, []byte(body))
		if err == nil && body != tsBody {
			t.Fatalf("accepted a body the secret never signed: %q", body)
		}
	})
}
