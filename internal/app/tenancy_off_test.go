//go:build notenancy

package app_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/config"
)

// operatorEnv is empty: without the tenancy part there is no operator pool.
var operatorEnv []string //nolint:unused // read by mail_test.go, which a build without mail leaves out

// Without the tenancy part nothing may open the pool that bypasses row-level security: the setting is
// refused, and OpenDatabase refuses it before connecting even when handed an unvalidated configuration.
func TestNoTenancy_RefusesTheOperatorPool(t *testing.T) {
	operator := "APP_DATABASE_OPERATOR_URL=postgres://keel_operator@db.example/keel"
	_, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys, "APP_DATABASE_URL=postgres://keel_app@db.example/keel", operator})
	require.ErrorContains(t, err, "APP_DATABASE_OPERATOR_URL needs the tenancy part")

	var cfg app.Config
	cfg.Database.URL = "postgres://keel_app@127.0.0.1:1/keel"
	cfg.Database.OperatorURL = config.Secret("postgres://keel_operator@127.0.0.1:1/keel")
	_, err = app.OpenDatabase(t.Context(), cfg)
	require.ErrorContains(t, err, "APP_DATABASE_OPERATOR_URL needs the tenancy part")
}
