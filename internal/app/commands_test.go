package app_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/config"
)

func runCommand(t *testing.T, environ []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = cli.App{Name: app.Name, Commands: app.Commands(environ)}.Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestConfigCheck_PrintsRedactedConfig(t *testing.T) {
	environ := []string{"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080", signingKeys}

	code, stdout, _ := runCommand(t, environ, "config:check")

	assert.Equal(t, cli.ExitOK, code)
	assert.Contains(t, stdout, "APP_HTTP_ADDR")
	assert.Contains(t, stdout, "127.0.0.1:8080")
	assert.Contains(t, stdout, "http://localhost:8080")
}

func TestConfigCheck_FailsOnInvalidProductionConfig(t *testing.T) {
	environ := []string{"APP_ENV=production", "APP_PUBLIC_URL=http://example.com", "APP_HTTP_DOCS=true"}

	code, stdout, stderr := runCommand(t, environ, "config:check")

	assert.Equal(t, cli.ExitError, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "public URL must be https in production")
	assert.Contains(t, stderr, "docs routes must be disabled in production")
}

func TestAbout_JSON(t *testing.T) {
	code, stdout, _ := runCommand(t, []string{"APP_ENV=test", signingKeys}, "about", "--json")

	assert.Equal(t, cli.ExitOK, code)
	assert.Contains(t, stdout, `"key": "env", "value": "test"`)
	assert.Contains(t, stdout, `"key": "go_version"`)
}

func TestAbout_SurvivesInvalidConfig(t *testing.T) {
	code, stdout, _ := runCommand(t, []string{"APP_ENV=nonsense"}, "about")

	assert.Equal(t, cli.ExitOK, code)
	assert.Contains(t, stdout, "invalid (run config:check)")
}

func TestConfigCheck_RequiresAppEnv(t *testing.T) {
	code, _, stderr := runCommand(t, nil, "config:check")

	assert.Equal(t, cli.ExitError, code)
	assert.Contains(t, stderr, "APP_ENV")
}

// Deploys hand migrate the owner's URL and nothing else, so migrate validates only database settings.
func TestMigrate_NeedsOnlyDatabaseSettings(t *testing.T) {
	tests := []struct {
		name, url, want string
	}{
		{"owner URL alone gets as far as connecting", "postgres://owner@127.0.0.1:1/app?sslmode=verify-full", "connect"},
		{"production still needs verified TLS", "postgres://owner@127.0.0.1:1/app", "sslmode=verify-full"},
		{"production migrates as the owner, never through the app's URL", "", "migrate URL is required in production"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environ := []string{"APP_ENV=production", "APP_DATABASE_MIGRATE_URL=" + tt.url}
			if tt.url == "" {
				environ = []string{"APP_ENV=production", "APP_DATABASE_URL=postgres://app@127.0.0.1:1/app?sslmode=verify-full"}
			}

			code, _, stderr := runCommand(t, environ, "migrate:status")

			assert.Equal(t, cli.ExitError, code)
			assert.Contains(t, stderr, tt.want)
			assert.NotContains(t, stderr, "APP_SESSION_KEYS")
		})
	}
}

// Every secret can arrive as a file (<NAME>_FILE): config reads the file variable of each one, which
// is why naming both is refused for every secret.
func TestConfig_EverySecretReadsAFile(t *testing.T) {
	cfg, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys})
	require.NoError(t, err)
	var secrets []string
	listed := map[string]bool{}
	for _, e := range config.Describe(app.EnvPrefix, cfg) {
		listed[e.Key] = true
		if e.Value == "[redacted]" {
			secrets = append(secrets, e.Key)
		}
	}
	require.Contains(t, secrets, "APP_DATABASE_URL")
	// Key lists render redacted only when set; the optional parts' are listed only when the part is kept.
	for _, key := range []string{"APP_MFA_KEYS", "APP_CONNECTION_KEYS", "APP_WEBHOOKS_OUT_KEYS", "APP_APIKEY_LEAK_SECRETS"} {
		if listed[key] {
			secrets = append(secrets, key)
		}
	}

	for _, key := range secrets {
		_, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys, key + "=x", key + "_FILE=/nonexistent"})
		assert.ErrorContains(t, err, "set one of "+key+" or "+key+"_FILE", key)
	}
}
