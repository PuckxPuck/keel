package webhooks_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/netguard"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/seal"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
	"github.com/PuckxPuck/keel/internal/kit/webhooks"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var loopback = netip.MustParsePrefix("127.0.0.1/32")

var laneSeq atomic.Int64

type fixture struct {
	d   *db.DB
	q   *jobs.Queue
	svc *webhooks.Service
}

func newFixture(t *testing.T, d *db.DB, opts webhooks.Options) fixture {
	t.Helper()
	cfg := jobs.Defaults()
	cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: fmt.Sprintf("w%d", laneSeq.Add(1)), Workers: 1})
	cfg.Lease, cfg.Poll, cfg.ShutdownGrace = 2*time.Second, 20*time.Millisecond, 0
	q, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d)})
	require.NoError(t, err)
	if opts.Keys == nil {
		opts.Keys = keyring(t, testKey)
	}
	opts.Queue, opts.Tx = q, jobs.PlainTx(d)
	opts.Config = webhooks.Config{Timeout: 5 * time.Second, AllowHTTP: true, DisableAfter: 2, Retain: 720 * time.Hour, SecretOverlap: time.Hour}
	opts.Client = netguard.NewDialer(5*time.Second, netguard.Permit(loopback)).Client(5 * time.Second)
	svc, err := webhooks.New(opts)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = d.SQL().ExecContext(context.Background(), "DELETE FROM webhook_endpoints") // endpoints are global without tenancy
	})
	return fixture{d: d, q: q, svc: svc}
}

const testKey = "webhooks-test-key-0123456789abcdef"

func keyring(t *testing.T, keys ...config.Secret) *seal.Keyring {
	t.Helper()
	k, err := seal.NewKeyring(keys, "webhooks")
	require.NoError(t, err)
	return k
}

func (f fixture) tx(t *testing.T, fn func(ctx context.Context, tx db.Transaction) error) {
	t.Helper()
	require.NoError(t, db.InTx(t.Context(), f.d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) }))
}

func (f fixture) runUntil(t *testing.T, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.q.Run(ctx) }()
	require.Eventually(t, cond, 10*time.Second, 20*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func (f fixture) deliveries(t *testing.T) []webhooks.Delivery {
	var list []webhooks.Delivery
	f.tx(t, func(ctx context.Context, tx db.Transaction) error {
		var err error
		list, err = f.svc.Deliveries(ctx, tx, 10)
		return err
	})
	return list
}

func TestDelivery_IsSignedForStandardWebhooksReceivers(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB(), webhooks.Options{})
		var mu sync.Mutex
		var verified []string
		var secret string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			defer mu.Unlock()
			v, err := webhook.NewVerifier(webhook.Options{Source: "test", Secrets: []string{secret}})
			if err == nil {
				err = v.Verify(r.Context(), webhook.HeadersOf(r.Header), body)
			}
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			verified = append(verified, string(body))
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		quiet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unsubscribed endpoint was called") }))
		defer quiet.Close()

		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			mu.Lock()
			defer mu.Unlock()
			var err error
			if _, secret, err = f.svc.CreateEndpoint(ctx, tx, webhooks.NewEndpoint{URL: srv.URL, Events: []string{"order.paid"}}); err != nil {
				return err
			}
			if _, _, err = f.svc.CreateEndpoint(ctx, tx, webhooks.NewEndpoint{URL: quiet.URL, Events: []string{"order.cancelled"}}); err != nil {
				return err
			}
			_, err = f.svc.Emit(ctx, tx, "order.paid", map[string]string{"id": "o-1"})
			return err
		})
		f.runUntil(t, func() bool {
			list := f.deliveries(t)
			return len(list) == 1 && list[0].Status == webhooks.Succeeded
		})
		mu.Lock()
		defer mu.Unlock()
		require.Len(t, verified, 1)
		assert.Contains(t, verified[0], `"type":"order.paid"`)
		assert.Contains(t, verified[0], `"data":{"id":"o-1"}`)
	})
}

// After a rotation the old secret signs beside the new one, so a receiver can switch at its own pace.
func TestDelivery_IsSignedWithBothSecretsDuringTheOverlap(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB(), webhooks.Options{})
		var mu sync.Mutex
		var secrets []string
		verifiedBy := map[int]bool{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			defer mu.Unlock()
			for i, secret := range secrets {
				v, err := webhook.NewVerifier(webhook.Options{Source: "test", Secrets: []string{secret}})
				verifiedBy[i] = err == nil && v.Verify(r.Context(), webhook.HeadersOf(r.Header), body) == nil
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			mu.Lock()
			defer mu.Unlock()
			ep, old, err := f.svc.CreateEndpoint(ctx, tx, webhooks.NewEndpoint{URL: srv.URL, Events: []string{"*"}})
			if err != nil {
				return err
			}
			current, err := f.svc.RotateSecret(ctx, tx, ep.ID, ep.Version)
			if err != nil {
				return err
			}
			secrets = []string{old, current}
			_, err = f.svc.Emit(ctx, tx, "order.paid", map[string]string{"id": "o-1"})
			return err
		})
		f.runUntil(t, func() bool {
			list := f.deliveries(t)
			return len(list) == 1 && list[0].Status == webhooks.Succeeded
		})
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, map[int]bool{0: true, 1: true}, verifiedBy)
	})
}

func TestDelivery_DisablesEndpointAfterRepeatedFailures(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		var disabled []webhooks.Endpoint
		var mu sync.Mutex
		f := newFixture(t, e.DB(), webhooks.Options{
			Retries: []time.Duration{0, 0},
			OnDisabled: func(_ context.Context, _ db.Transaction, ep webhooks.Endpoint) error {
				mu.Lock()
				defer mu.Unlock()
				disabled = append(disabled, ep)
				return nil
			},
		})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
		defer srv.Close()
		var ep webhooks.Endpoint
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			var err error
			if ep, _, err = f.svc.CreateEndpoint(ctx, tx, webhooks.NewEndpoint{URL: srv.URL, Events: []string{"*"}}); err != nil {
				return err
			}
			_, err = f.svc.Emit(ctx, tx, "stock.changed", map[string]int{"qty": 3})
			return err
		})
		f.runUntil(t, func() bool {
			list := f.deliveries(t)
			return len(list) == 1 && list[0].Status == webhooks.Failed
		})
		d := f.deliveries(t)[0]
		assert.Equal(t, 3, d.Attempts)
		require.NotNil(t, d.LastStatusCode)
		assert.Equal(t, http.StatusBadGateway, *d.LastStatusCode)
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			got, err := f.svc.Endpoint(ctx, tx, ep.ID)
			require.NoError(t, err)
			assert.Equal(t, webhooks.Disabled, got.Status)
			return nil
		})
		mu.Lock()
		defer mu.Unlock()
		require.Len(t, disabled, 1)
		assert.Equal(t, ep.ID, disabled[0].ID)
	})
}

func (f fixture) endpointWithDelivery(t *testing.T, url string) (webhooks.Endpoint, webhooks.DeliveryID) {
	t.Helper()
	var ep webhooks.Endpoint
	f.tx(t, func(ctx context.Context, tx db.Transaction) error {
		var err error
		if ep, _, err = f.svc.CreateEndpoint(ctx, tx, webhooks.NewEndpoint{URL: url, Events: []string{"*"}}); err != nil {
			return err
		}
		_, err = f.svc.Emit(ctx, tx, "thing.changed", map[string]int{"id": 1})
		return err
	})
	list := f.deliveries(t)
	require.Len(t, list, 1)
	return ep, list[0].ID
}

func (f fixture) endpoint(t *testing.T, id webhooks.EndpointID) webhooks.Endpoint {
	t.Helper()
	var ep webhooks.Endpoint
	f.tx(t, func(ctx context.Context, tx db.Transaction) error {
		var err error
		ep, err = f.svc.Endpoint(ctx, tx, id)
		return err
	})
	return ep
}

// A worker that lost its lease finishes after the run that replaced it: its outcome must not win.
func TestDelivery_OnlyANewerAttemptRecordsItsOutcome(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB(), webhooks.Options{})
		ep, id := f.endpointWithDelivery(t, "https://receiver.example.test/")
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			return f.svc.RecordAttempt(ctx, tx, id, ep.ID, 2, true, false)
		})
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			return f.svc.RecordAttempt(ctx, tx, id, ep.ID, 1, false, true)
		})
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			return f.svc.RecordAttempt(ctx, tx, id, ep.ID, 2, false, true)
		})

		d := f.deliveries(t)[0]
		assert.Equal(t, webhooks.Succeeded, d.Status)
		assert.Equal(t, 1, d.Attempts)
		got := f.endpoint(t, ep.ID)
		assert.Equal(t, webhooks.Active, got.Status)
		assert.Equal(t, 0, got.FailureCount)
	})
}

func TestDelivery_ShutdownDuringThePostIsNotAFailedAttempt(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB(), webhooks.Options{})
		posted := make(chan struct{})
		var once sync.Once
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body) // the server notices the client leaving only once the body is read
			once.Do(func() { close(posted) })
			<-r.Context().Done()
		}))
		defer srv.Close()
		ep, _ := f.endpointWithDelivery(t, srv.URL)

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- f.q.Run(ctx) }()
		<-posted
		cancel()
		require.NoError(t, <-done)

		d := f.deliveries(t)[0]
		assert.Equal(t, webhooks.Pending, d.Status)
		assert.Equal(t, 0, d.Attempts)
		assert.Equal(t, 0, f.endpoint(t, ep.ID).FailureCount)
	})
}

func TestDelivery_UnreadableSecretFailsTheDelivery(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB(), webhooks.Options{})
		ep, _ := f.endpointWithDelivery(t, "https://receiver.example.test/")
		_, err := f.d.SQL().ExecContext(t.Context(), db.Rebind(f.d.Dialect(), "UPDATE webhook_endpoints SET secret = ? WHERE id = ?"), []byte{1, 2, 3}, ep.ID)
		require.NoError(t, err)

		f.runUntil(t, func() bool { return f.deliveries(t)[0].Status == webhooks.Failed })
		d := f.deliveries(t)[0]
		require.NotNil(t, d.LastErrorCode)
		assert.Equal(t, "secret", *d.LastErrorCode)
	})
}

func TestEndpoint_ChangesAtAStaleVersionConflict(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB(), webhooks.Options{})
		ep, _ := f.endpointWithDelivery(t, "https://receiver.example.test/")
		changes := map[string]func(ctx context.Context, tx db.Transaction, version int) error{
			"rotate": func(ctx context.Context, tx db.Transaction, v int) error {
				_, err := f.svc.RotateSecret(ctx, tx, ep.ID, v)
				return err
			},
			"enable": func(ctx context.Context, tx db.Transaction, v int) error {
				return f.svc.EnableEndpoint(ctx, tx, ep.ID, v)
			},
			"disable": func(ctx context.Context, tx db.Transaction, v int) error {
				return f.svc.DisableEndpoint(ctx, tx, ep.ID, v)
			},
			"delete": func(ctx context.Context, tx db.Transaction, v int) error {
				return f.svc.DeleteEndpoint(ctx, tx, ep.ID, v)
			},
		}
		for name, change := range changes {
			err := db.InTx(t.Context(), f.d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return change(ctx, tx, ep.Version+5) })
			var stale *occ.StaleError
			require.ErrorAs(t, err, &stale, name)
			assert.Equal(t, ep.Version, stale.Current.Version, name)
		}
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			return f.svc.DisableEndpoint(ctx, tx, ep.ID, ep.Version)
		})
		assert.Equal(t, webhooks.Disabled, f.endpoint(t, ep.ID).Status)
	})
}

// After Rekey every secret opens with the newest key alone, so the old one can be removed; a rotated-out
// secret past its overlap is dropped rather than resealed.
func TestRekey_ResealsSecretsWithTheNewestKey(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.Isolated(t)
		f := newFixture(t, d, webhooks.Options{})
		ep, _ := f.endpointWithDelivery(t, "https://receiver.example.test/")
		f.tx(t, func(ctx context.Context, tx db.Transaction) error {
			_, err := f.svc.RotateSecret(ctx, tx, ep.ID, ep.Version)
			return err
		})
		const newKey = "webhooks-newer-key-0123456789abcdef"
		rotated := newFixture(t, d, webhooks.Options{Keys: keyring(t, newKey, testKey)})
		pastOverlap := clock.WithWall(t.Context(), clock.Fixed(clock.Wall(t.Context()).Now().Add(2*time.Hour)))
		res, err := rotated.svc.Rekey(pastOverlap)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, res.Rewrapped, 1)

		var sealed, previous []byte
		require.NoError(t, d.SQL().QueryRowContext(t.Context(), db.Rebind(d.Dialect(), "SELECT secret, previous_secret FROM webhook_endpoints WHERE id = ?"), ep.ID).Scan(&sealed, &previous))
		_, stale, err := keyring(t, newKey).Open(sealed, ep.ID[:])
		require.NoError(t, err)
		assert.False(t, stale)
		assert.Nil(t, previous, "the rotated-out secret's overlap has ended")
	})
}
