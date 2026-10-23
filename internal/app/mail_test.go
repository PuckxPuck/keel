//go:build !nomail

package app_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/mail"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

// productionEnv passes the production profile; the database comes from the test, so its URLs only need
// to look right.
var productionEnv = []string{
	"APP_ENV=production", "APP_PUBLIC_URL=https://app.example.test", signingKeys,
	"APP_DATABASE_URL=postgres://app@db.example.test/app?sslmode=verify-full",
	"APP_DATABASE_MIGRATE_URL=postgres://owner@db.example.test/app?sslmode=verify-full",
	"APP_MAIL_DRIVER=smtp", "APP_MAIL_FROM=App <no-reply@example.test>", "APP_MAIL_SMTP_HOST=smtp.example.test",
	"APP_JOBS_POLL=50ms", "APP_JOBS_SHUTDOWN_GRACE=0s",
}

// serve in the production profile builds with mail as the notifier: an invite reaches the mailer through
// the queue serve runs, with the token in the link's fragment. user:create can still print it instead.
func TestServe_ProductionProfileSendsLinksByMail(t *testing.T) {
	d := testdb.Get(t)
	cfg, err := app.LoadConfig(slices.Concat(productionEnv, operatorEnv))
	require.NoError(t, err)
	sent := &mail.Recorder{}
	deps := app.Deps{DB: d, Mailer: sent}
	built, err := app.Build(t.Context(), cfg, deps)
	require.NoError(t, err)
	require.NotNil(t, built.Queue)

	email := ids.New().String() + "@example.test"
	_, printed, err := app.CreateUser(t.Context(), cfg, deps, email, "Ann", false)
	require.NoError(t, err)
	assert.Empty(t, printed, "a sent invite is not printed")
	_, printed, err = app.CreateUser(t.Context(), cfg, deps, ids.New().String()+"@example.test", "", true)
	require.NoError(t, err)
	assert.NotEmpty(t, printed)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- built.Queue.Run(ctx) }()
	var invite mail.Message
	require.Eventually(t, func() bool {
		for _, m := range sent.Messages() {
			if len(m.To) == 1 && strings.Contains(m.To[0], email) {
				invite = m
				return true
			}
		}
		return false
	}, 10*time.Second, 20*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	assert.Contains(t, invite.Text, "https://app.example.test/accept-invite#token=")
}

func TestDoctor_FailsAnUnreachableMailServer(t *testing.T) {
	failed := failedChecks(t, "APP_MAIL_DRIVER=smtp", "APP_MAIL_FROM=no-reply@example.test", "APP_MAIL_SMTP_HOST=127.0.0.1",
		"APP_MAIL_SMTP_PORT=1", "APP_MAIL_SMTP_TLS=none")
	require.Len(t, failed, 1, failed)
	assert.Contains(t, failed[0], "mail: ")
}
