package password_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/password"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var cheap = password.Params{Memory: 64, Time: 1, Threads: 1}

func hasher(t *testing.T, p password.Params) *password.Hasher {
	t.Helper()
	h, err := password.NewHasher(p, 2)
	require.NoError(t, err)
	return h
}

// A stored hash is outside input: parameters past the bounds for the configured ones (memory at most
// 4x, time at most 2x+1, four lanes) or malformed are refused before any hashing at their cost.
func TestVerify_RefusesHashesOutsideTheBounds(t *testing.T) {
	h := hasher(t, cheap)
	salt, key := "c2FsdHNhbHRzYWx0c2FsdA", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	bcrypt31 := "$2a$31$" + strings.Repeat("a", 53)
	tests := []struct {
		name, encoded string
		want          error
	}{
		{"memory above 4x configured", "$argon2id$v=19$m=257,t=1,p=1$" + salt + "$" + key, password.ErrOutOfBounds},
		{"time above 2x configured plus 1", "$argon2id$v=19$m=64,t=4,p=1$" + salt + "$" + key, password.ErrOutOfBounds},
		{"more than four lanes", "$argon2id$v=19$m=256,t=1,p=5$" + salt + "$" + key, password.ErrOutOfBounds},
		{"memory above 1 GiB", "$argon2id$v=19$m=1048577,t=1,p=1$" + salt + "$" + key, password.ErrMalformedHash},
		{"salt shorter than 8", "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$" + key, password.ErrMalformedHash},
		{"key shorter than 16", "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$a2V5", password.ErrMalformedHash},
		{"other version", "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key, password.ErrMalformedHash},
		{"argon2i, not argon2id", "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key, password.ErrMalformedHash},
		{"bcrypt cost above 15", bcrypt31, password.ErrMalformedHash},
		{"garbage", "plain-text", password.ErrMalformedHash},
	}
	for _, tt := range tests {
		ok, _, err := h.Verify(t.Context(), tt.encoded, "whatever")
		assert.False(t, ok, tt.name)
		require.ErrorIs(t, err, tt.want, tt.name)
	}
}

func TestVerify_MatchesAndAsksForRehash(t *testing.T) {
	ctx := t.Context()
	current := hasher(t, cheap)
	older := hasher(t, password.Params{Memory: 32, Time: 1, Threads: 1})
	sameParams, err := current.Hash(ctx, "correct horse battery")
	require.NoError(t, err)
	oldParams, err := older.Hash(ctx, "correct horse battery")
	require.NoError(t, err)
	legacy, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	require.NoError(t, err)
	const composed, decomposed = "caf\u00e9 au lait daily", "cafe\u0301 au lait daily"
	unicode, err := current.Hash(ctx, composed)
	require.NoError(t, err)
	legacyComposed, err := bcrypt.GenerateFromPassword([]byte(composed), bcrypt.MinCost)
	require.NoError(t, err)

	tests := []struct {
		name, encoded, plain string
		ok, rehash           bool
	}{
		{"current parameters", sameParams, "correct horse battery", true, false},
		{"older parameters", oldParams, "correct horse battery", true, true},
		{"legacy bcrypt", string(legacy), "correct horse battery", true, true},
		{"wrong password", sameParams, "correct horse battery!", false, false},
		{"wrong password on bcrypt", string(legacy), "nope", false, true},
		{"longer than 128 characters", sameParams, strings.Repeat("a", 129), false, false},
		{"decomposed accent against a composed one", unicode, decomposed, true, false},
		{"legacy bcrypt, typed as it was made", string(legacyComposed), composed, true, true},
		{"legacy bcrypt, typed decomposed", string(legacyComposed), decomposed, true, true},
	}
	for _, tt := range tests {
		ok, rehash, err := current.Verify(ctx, tt.encoded, tt.plain)
		require.NoError(t, err, tt.name)
		assert.Equal(t, tt.ok, ok, tt.name)
		if tt.ok {
			assert.Equal(t, tt.rehash, rehash, tt.name)
		}
	}
	assert.False(t, current.NeedsRehash(sameParams))
	assert.True(t, current.NeedsRehash(oldParams))
	assert.True(t, current.NeedsRehash(string(legacy)))
}

func TestPolicy(t *testing.T) {
	single := password.Config{}.Policy(false)
	withMFA := password.Config{}.Policy(true)
	tests := []struct {
		name   string
		policy password.Policy
		plain  string
		want   []string
	}{
		{"15 characters alone", single, "violet-otter-42", nil},
		{"14 characters alone", single, "violet-otter-4", []string{password.ReasonTooShort}},
		{"8 characters with a second factor", withMFA, "vi0let!x", nil},
		{"length counts characters, not bytes", withMFA, "ééééééé", []string{password.ReasonTooShort}},
		{"no composition rules", single, "aaaaaaaaaaaaaaaa", nil},
		{"common, in any case", withMFA, "PassWord123", []string{password.ReasonCommon}},
		{"common, in full-width letters", withMFA, "\uff30\uff41\uff53\uff53word123", []string{password.ReasonCommon}},
		{"128 characters of two bytes", single, strings.Repeat("é", 128), nil},
		{"over 128 characters", single, strings.Repeat("é", 129), []string{password.ReasonTooLong}},
		{"not text", withMFA, "abcdefgh\xff", []string{password.ReasonInvalid}},
	}
	for _, tt := range tests {
		err := tt.policy.Check(tt.plain)
		if tt.want == nil {
			require.NoError(t, err, tt.name)
			continue
		}
		var pe *password.PolicyError
		require.ErrorAs(t, err, &pe, tt.name)
		assert.Equal(t, tt.want, pe.Reasons, tt.name)
	}
}

type allow struct{}

func (allow) CheckStatus(context.Context, db.Transaction, users.Actor, users.ID, users.Status) error {
	return nil
}

// countingVerifier records which hashes were verified, to prove the unknown-account path runs a
// real verification and to count how many attempts reached a real hash.
type countingVerifier struct {
	*password.Hasher
	dummyRuns, realRuns atomic.Int32
}

func (c *countingVerifier) Verify(ctx context.Context, encoded, plain string) (bool, bool, error) {
	if encoded == c.DummyHash() {
		c.dummyRuns.Add(1)
	} else {
		c.realRuns.Add(1)
	}
	return c.Hasher.Verify(ctx, encoded, plain)
}

// fromAddress puts a client address in the context the way httpx.ClientAddress does.
func fromAddress(t *testing.T, remote string) context.Context {
	t.Helper()
	var seen *http.Request
	h := httpx.ClientAddress(config.Proxy{})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r }))
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	h.ServeHTTP(httptest.NewRecorder(), r)
	return seen.Context()
}

type account struct {
	svc    *password.Service
	v      *countingVerifier
	email  string
	userID users.ID
}

// newAccount makes a user whose password is a legacy bcrypt hash of "a long legacy passphrase".
func newAccount(t *testing.T, e *testdb.Engine, perAccount int) account {
	t.Helper()
	rec := audit.New(audit.Options{})
	a := account{v: &countingVerifier{Hasher: hasher(t, cheap)}, email: ids.New().String() + "@example.test"}
	a.svc = password.NewService(a.v, auth.NewFailures(ratelimit.DBStoreOf(e.DB())), password.Throttle{
		PerAccount: ratelimit.Rate{Limit: perAccount, Period: time.Hour},
		PerAddress: ratelimit.Rate{Limit: 100, Period: time.Hour},
	}, rec)
	require.NoError(t, db.InTx(t.Context(), e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
		u, err := users.NewService(rec, allow{}).Create(ctx, tx, users.NewUser{Email: a.email})
		a.userID = u.ID
		if err != nil {
			return err
		}
		legacy, err := bcrypt.GenerateFromPassword([]byte("a long legacy passphrase"), bcrypt.MinCost)
		if err != nil {
			return err
		}
		_, err = tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "INSERT INTO credentials (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)"),
			u.ID, string(legacy), u.CreatedAt, u.CreatedAt)
		return err
	}))
	return a
}

// signIn runs the closing write the way the app does: a statement in the transaction.
func (a account) signIn(ctx context.Context, d *db.DB, email, plain string) error {
	_, err := a.svc.Authenticate(ctx, d, email, plain, func(ctx context.Context, tx db.Transaction, _ users.User) error {
		_, err := tx.Q().ExecContext(ctx, "SELECT 1")
		return err
	})
	return err
}

func TestAuthenticate(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAccount(t, e, 3)
		v, email, userID := a.v, a.email, a.userID
		attacker, owner := fromAddress(t, "198.51.100.7:1000"), fromAddress(t, "203.0.113.9:1000")
		signIn := func(ctx context.Context, email, plain string) error { return a.signIn(ctx, e.DB(), email, plain) }

		before := v.dummyRuns.Load()
		unknown := signIn(attacker, "nobody-"+email, "a long legacy passphrase")
		require.ErrorIs(t, unknown, password.ErrInvalidCredentials)
		assert.Equal(t, before+1, v.dummyRuns.Load(), "an unknown account verifies against the dummy hash")
		require.ErrorIs(t, signIn(attacker, email, "wrong guess one"), password.ErrInvalidCredentials, "same answer as unknown")
		require.ErrorIs(t, signIn(attacker, email, "wrong guess two"), password.ErrInvalidCredentials)
		require.ErrorIs(t, signIn(attacker, email, "wrong guess three"), password.ErrInvalidCredentials)

		var throttled *auth.ThrottledError
		require.ErrorAs(t, signIn(attacker, email, "a long legacy passphrase"), &throttled, "this account from this address waits")
		assert.Positive(t, throttled.RetryAfter)
		require.NoError(t, signIn(owner, email, "a long legacy passphrase"), "the owner elsewhere is not locked out")

		var stored string
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), db.Rebind(e.Dialect(), "SELECT password_hash FROM credentials WHERE user_id = ?"), userID).Scan(&stored))
		assert.True(t, strings.HasPrefix(stored, "$argon2id$"), "the bcrypt hash was upgraded on sign-in")
		assert.False(t, v.NeedsRehash(stored))
		require.NoError(t, signIn(owner, strings.ToUpper(email), "a long legacy passphrase"), "the rehashed password still works")
		require.ErrorIs(t, signIn(owner, email, strings.Repeat("a", 129)), password.ErrInvalidCredentials, "over the maximum")
	})
}

// A burst is counted before any check, so it cannot overrun the limit, and sign-ins above the pool
// size all finish: no connection is held while one waits for the counter or the hash.
func TestAuthenticate_Burst(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAccount(t, e, 3)
		attacker := fromAddress(t, "198.51.100.7:1000")
		const burst = 12
		errs := make([]error, burst)
		var wg sync.WaitGroup
		for i := range burst {
			wg.Go(func() { errs[i] = a.signIn(attacker, e.DB(), a.email, "wrong guess") })
		}
		wg.Wait()
		throttled := 0
		for _, err := range errs {
			var te *auth.ThrottledError
			if errors.As(err, &te) {
				throttled++
				continue
			}
			require.ErrorIs(t, err, password.ErrInvalidCredentials)
		}
		assert.Equal(t, burst-3, throttled)
		assert.Equal(t, int32(3), a.v.realRuns.Load(), "only three attempts reached the hash")

		for i := range burst {
			from := fromAddress(t, fmt.Sprintf("203.0.113.%d:1000", i+1))
			wg.Go(func() { errs[i] = a.signIn(from, e.DB(), a.email, "a long legacy passphrase") })
		}
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
	})
}
