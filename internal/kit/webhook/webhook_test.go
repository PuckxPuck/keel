package webhook_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

// The example from the Standard Webhooks specification.
const (
	specSecret    = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" //nolint:gosec // the specification's published test secret
	specID        = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	specTimestamp = 1614265330
	specBody      = `{"test": 2432232314}`
	specSignature = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	otherSecret   = "whsec_dGVzdC1zZWNyZXQtdGhhdC1pcy1sb25nLWVub3VnaA==" //nolint:gosec // a test-only secret
)

func at(t *testing.T, sec int64) context.Context {
	return clock.WithWall(t.Context(), clock.Fixed(time.Unix(sec, 0)))
}

func TestSign_MatchesTheSpecVector(t *testing.T) {
	sig, err := webhook.Sign(specSecret, specID, time.Unix(specTimestamp, 0), []byte(specBody))
	require.NoError(t, err)
	assert.Equal(t, specSignature, sig)
}

func verifier(t testing.TB, source string, secrets ...string) *webhook.Verifier {
	t.Helper()
	v, err := webhook.NewVerifier(webhook.Options{Source: source, Secrets: secrets, Tolerance: 5 * time.Minute, Production: true})
	require.NoError(t, err)
	return v
}

func TestNewVerifier_RefusesWeakSecretsInProduction(t *testing.T) {
	short := "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, webhook.MinSecretBytes-1))
	_, err := webhook.NewVerifier(webhook.Options{Source: "stripe", Secrets: []string{specSecret, short}, Production: true})
	require.ErrorIs(t, err, webhook.ErrWeakSecret)
	_, err = webhook.NewVerifier(webhook.Options{Source: "stripe", Secrets: []string{short}})
	require.NoError(t, err, "outside production a short secret is allowed")
	_, err = webhook.NewVerifier(webhook.Options{Source: "Not A Name", Secrets: []string{specSecret}})
	require.ErrorIs(t, err, webhook.ErrSource)
}

func TestVerify(t *testing.T) {
	v := verifier(t, "spec", otherSecret, specSecret)
	junk := strings.Repeat("v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= ", 5)
	valid := webhook.Headers{ID: specID, Timestamp: "1614265330", Signature: specSignature}
	tests := []struct {
		name string
		h    webhook.Headers
		body string
		now  int64
		want error
	}{
		{"the spec vector with the second secret", valid, specBody, specTimestamp, nil},
		{"one of several signatures matches", webhook.Headers{
			ID: specID, Timestamp: "1614265330",
			Signature: "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= v2,abc " + specSignature,
		}, specBody, specTimestamp, nil},
		{"within tolerance", valid, specBody, specTimestamp + 299, nil},
		{"too old", valid, specBody, specTimestamp + 301, webhook.ErrTimestamp},
		{"from the future", valid, specBody, specTimestamp - 301, webhook.ErrTimestamp},
		{"body changed", valid, `{"test": 2432232315}`, specTimestamp, webhook.ErrSignature},
		{"id changed", webhook.Headers{ID: "msg_other", Timestamp: valid.Timestamp, Signature: specSignature}, specBody, specTimestamp, webhook.ErrSignature},
		{"unsupported version only", webhook.Headers{ID: specID, Timestamp: valid.Timestamp, Signature: "v2,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="}, specBody, specTimestamp, webhook.ErrSignature},
		{"missing id", webhook.Headers{Timestamp: valid.Timestamp, Signature: specSignature}, specBody, specTimestamp, webhook.ErrMissingHeaders},
		{"missing signature", webhook.Headers{ID: specID, Timestamp: valid.Timestamp}, specBody, specTimestamp, webhook.ErrMissingHeaders},
		{"timestamp not a number", webhook.Headers{ID: specID, Timestamp: "soon", Signature: specSignature}, specBody, specTimestamp, webhook.ErrTimestamp},
		{"only the first five signatures are compared", webhook.Headers{ID: specID, Timestamp: valid.Timestamp, Signature: junk + specSignature}, specBody, specTimestamp, webhook.ErrSignature},
		{"an id with a space is refused", webhook.Headers{ID: "msg 1", Timestamp: valid.Timestamp, Signature: specSignature}, specBody, specTimestamp, webhook.ErrMissingHeaders},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Verify(at(t, tt.now), tt.h, []byte(tt.body))
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func FuzzVerify(f *testing.F) {
	f.Add(specID, "1614265330", specSignature, specBody)
	f.Add(specID, "1614265330", "v1, v1,,, v1,====", "")
	f.Add("", "-1", "v1,"+string(make([]byte, 300)), "{}")
	v := verifier(f, "spec", specSecret)
	f.Fuzz(func(t *testing.T, id, ts, sig, body string) {
		h := webhook.Headers{ID: id, Timestamp: ts, Signature: sig}
		err := v.Verify(at(t, specTimestamp), h, []byte(body))
		if err == nil && (id != specID || body != specBody) {
			t.Fatalf("accepted a delivery the spec secret never signed: %q %q", id, body)
		}
	})
}

type recorder interface {
	Seen(ctx context.Context, tx db.Transaction, id string) (bool, error)
}

func TestSeen_RecognisesAReplayFromTheSameSender(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		id := "msg_" + ids.New().String()
		stripe, github := verifier(t, "stripe", specSecret), verifier(t, "github", specSecret)
		acme := timestamped(t, webhook.TimestampedOptions{IDField: "id"})
		seen := func(v recorder) bool {
			var got bool
			require.NoError(t, db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				got, err = v.Seen(ctx, tx, id)
				return err
			}))
			return got
		}

		rolledBack := db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			_, err := stripe.Seen(ctx, tx, id)
			require.NoError(t, err)
			return assert.AnError
		})
		require.ErrorIs(t, rolledBack, assert.AnError)

		assert.False(t, seen(stripe), "a rolled-back delivery can be retried")
		assert.True(t, seen(stripe), "the same id again is a replay")
		assert.False(t, seen(github), "ids are unique only per sender")
		assert.False(t, seen(acme), "a timestamped sender records its own ids")
		assert.True(t, seen(acme), "and recognises its replays")
	})
}
