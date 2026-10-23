package mail_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/mail"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var laneSeq atomic.Int64

type fixture struct {
	d    *db.DB
	q    *jobs.Queue
	svc  *mail.Service
	rec  *mail.Recorder
	lane string
}

func newFixture(t *testing.T, d *db.DB) fixture {
	t.Helper()
	lane := fmt.Sprintf("m%d", laneSeq.Add(1))
	cfg := jobs.Defaults()
	cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: lane, Workers: 1})
	cfg.Lease, cfg.Poll = 2*time.Second, 20*time.Millisecond
	q, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d)})
	require.NoError(t, err)
	r, err := mail.NewRenderer(nil)
	require.NoError(t, err)
	rec := &mail.Recorder{}
	svc, err := mail.New(mail.Options{
		Queue: q, Tx: jobs.PlainTx(d), Mailer: rec, Renderer: r,
		Config: mail.Config{From: "App <no-reply@example.test>", RetainBody: time.Hour, RetainLog: time.Hour},
	})
	require.NoError(t, err)
	return fixture{d: d, q: q, svc: svc, rec: rec, lane: lane}
}

func (f fixture) enqueue(t *testing.T, e mail.Email) (jobs.ID, string) {
	t.Helper()
	var id jobs.ID
	require.NoError(t, db.InTx(t.Context(), f.d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		id, err = f.svc.Enqueue(ctx, tx, e)
		return err
	}))
	var messageID string
	require.NoError(t, f.d.SQL().QueryRowContext(t.Context(), db.Rebind(f.d.Dialect(), "SELECT message_id FROM mail_outbox WHERE job_id = ?"), id).Scan(&messageID))
	return id, messageID
}

func (f fixture) runUntil(t *testing.T, id jobs.ID, status string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.q.Run(ctx) }()
	require.Eventually(t, func() bool { return f.jobStatus(t, id) == status }, 10*time.Second, 20*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func (f fixture) jobStatus(t *testing.T, id jobs.ID) string {
	var s string
	require.NoError(t, f.d.SQL().QueryRowContext(t.Context(), db.Rebind(f.d.Dialect(), "SELECT status FROM jobs WHERE id = ?"), id).Scan(&s))
	return s
}

func (f fixture) outbox(t *testing.T, messageID string) []string {
	t.Helper()
	rows, err := f.d.SQL().QueryContext(t.Context(), db.Rebind(f.d.Dialect(), "SELECT status FROM mail_outbox WHERE message_id = ? ORDER BY seq"), messageID)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestNotifier_SendsOnceWithItsMessageIDAndClearsTheLink(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB())
		n := f.svc.Notifier(mail.DefaultLinks("https://app.example.test/"))
		var uid users.ID
		require.NoError(t, uid.UnmarshalText([]byte(ids.New().String())))
		require.NoError(t, db.InTx(t.Context(), f.d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return n.SendReset(ctx, tx, users.User{ID: uid, Email: "ana@example.test", Name: "Ana"}, "tok-123")
		}))
		var id jobs.ID
		require.NoError(t, f.d.SQL().QueryRowContext(t.Context(), db.Rebind(f.d.Dialect(), "SELECT id FROM jobs WHERE lane = ? AND kind = ?"),
			f.lane, mail.KindSend).Scan(&id))
		f.runUntil(t, id, "done")

		sent := f.rec.Messages()
		require.Len(t, sent, 1)
		m := sent[0]
		assert.Equal(t, []string{"<ana@example.test>"}, m.To)
		assert.Equal(t, "Reset your password", m.Subject)
		assert.Contains(t, m.Text, "https://app.example.test/reset-password#token=tok-123")
		assert.Equal(t, []string{"queued", "sending", "sent"}, f.outbox(t, m.MessageID))
		assert.NotContains(t, f.payload(t, id), "tok-123")
	})
}

func (f fixture) payload(t *testing.T, id jobs.ID) string {
	t.Helper()
	var payload string
	require.NoError(t, f.d.SQL().QueryRowContext(t.Context(), db.Rebind(f.d.Dialect(), "SELECT payload FROM jobs WHERE id = ?"), id).Scan(&payload))
	return payload
}

// A message that may have been handed over is never sent again, and its token-bearing body goes at once.
func TestSend_RerunAfterCrashBetweenSendingAndSentMarksUncertain(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB())
		id, messageID := f.enqueue(t, mail.Email{To: []string{"bo@example.test"}, Template: "verify", Data: map[string]string{"Name": "Bo", "Link": "https://x.test/v#token=tok-9"}, Sensitive: true})
		_, err := f.d.SQL().ExecContext(t.Context(), db.Rebind(f.d.Dialect(),
			"INSERT INTO mail_outbox (id, message_id, seq, job_id, status, created_at) VALUES (?, ?, 2, ?, 'sending', ?)"),
			ids.New(), messageID, id, clock.Wall(t.Context()).Now().UTC())
		require.NoError(t, err)

		f.runUntil(t, id, "failed")
		assert.Empty(t, f.rec.Messages())
		assert.Equal(t, []string{"queued", "sending", "uncertain"}, f.outbox(t, messageID))
		assert.NotContains(t, f.payload(t, id), "tok-9")
	})
}

func TestSend_AmbiguousFailureIsNotRetried(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		f := newFixture(t, e.DB())
		var calls atomic.Int64
		f.rec.Fail = func(mail.Message) error {
			calls.Add(1)
			return errors.New("connection reset after DATA")
		}
		id, messageID := f.enqueue(t, mail.Email{To: []string{"cy@example.test"}, Template: "verify", Data: map[string]string{"Name": "Cy", "Link": "https://x.test/v#token=tok-7"}, Sensitive: true})
		f.runUntil(t, id, "failed")
		assert.Equal(t, int64(1), calls.Load())
		assert.Equal(t, []string{"queued", "sending", "uncertain"}, f.outbox(t, messageID))
		assert.NotContains(t, f.payload(t, id), "tok-7")
	})
}

func TestConfig_TLSNoneOnlyToLoopback(t *testing.T) {
	base := mail.Config{
		Driver: mail.DriverSMTP, From: "a@example.test", RetainBody: time.Hour, RetainLog: time.Hour,
		SMTP: mail.SMTPConfig{Port: 1025, Timeout: time.Second},
	}
	cases := []struct {
		host string
		tls  mail.TLSMode
		ok   bool
	}{
		{"127.0.0.1", mail.TLSNone, true},
		{"localhost", mail.TLSNone, true},
		{"::1", mail.TLSNone, true},
		{"smtp.example.test", mail.TLSNone, false},
		{"10.0.0.5", mail.TLSNone, false},
		{"smtp.example.test", mail.TLSStartTLS, true},
		{"smtp.example.test", "", false},
	}
	for _, c := range cases {
		cfg := base
		cfg.SMTP.Host, cfg.SMTP.TLS = c.host, c.tls
		err := cfg.Validate(false)
		assert.Equal(t, c.ok, err == nil, "%s %s: %v", c.host, c.tls, err)
	}
}

func TestRenderer_EscapesHTMLAndPrefersAppTemplates(t *testing.T) {
	app := fstest.MapFS{"layout.html": {Data: []byte(`<main>{{template "content" .}}</main>`)}}
	r, err := mail.NewRenderer(app)
	require.NoError(t, err)
	out, err := r.Render("reset", map[string]string{"Name": "<b>Eve</b>", "Link": "https://x.test/r#token=abc"})
	require.NoError(t, err)
	assert.Equal(t, "Reset your password", out.Subject)
	assert.True(t, strings.HasPrefix(out.HTML, "<main>"))
	assert.Contains(t, out.HTML, "&lt;b&gt;Eve&lt;/b&gt;")
	assert.Contains(t, out.Text, "https://x.test/r#token=abc")
}

// Two runs of one message at once (an operator retry while a cancelled worker still runs, or clock skew
// around a lease) hand the message over once.
func TestSend_ConcurrentRunsSendOnce(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		f := newFixture(t, d)
		slow, err := mail.New(mail.Options{
			Queue: mustQueue(t, d), Mailer: f.rec, Renderer: mustRenderer(t),
			Tx: func(ctx context.Context, fn func(context.Context, db.Transaction) error) error {
				return jobs.PlainTx(d)(ctx, func(ctx context.Context, tx db.Transaction) error {
					if err := fn(ctx, tx); err != nil {
						return err
					}
					time.Sleep(150 * time.Millisecond) // hold the transaction open so the other run overlaps it
					return nil
				})
			},
			Config: mail.Config{From: "App <no-reply@example.test>", RetainBody: time.Hour, RetainLog: time.Hour},
		})
		require.NoError(t, err)
		id, _ := f.enqueue(t, mail.Email{To: []string{"di@example.test"}, Template: "verify", Data: map[string]string{"Name": "Di", "Link": "https://x.test/v"}})
		var payload []byte
		require.NoError(t, d.SQL().QueryRowContext(t.Context(), db.Rebind(d.Dialect(), "SELECT payload FROM jobs WHERE id = ?"), id).Scan(&payload))
		job := jobs.Job{ID: id, Kind: mail.KindSend, Payload: payload, Attempt: 1, MaxAttempts: 8}

		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { _ = slow.RunSend(t.Context(), job) })
		}
		wg.Wait()
		assert.Len(t, f.rec.Messages(), 1)
	})
}

func mustQueue(t *testing.T, d *db.DB) *jobs.Queue {
	t.Helper()
	cfg := jobs.Defaults()
	cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: fmt.Sprintf("m%d", laneSeq.Add(1)), Workers: 1})
	q, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d)})
	require.NoError(t, err)
	return q
}

func mustRenderer(t *testing.T) *mail.Renderer {
	t.Helper()
	r, err := mail.NewRenderer(nil)
	require.NoError(t, err)
	return r
}
