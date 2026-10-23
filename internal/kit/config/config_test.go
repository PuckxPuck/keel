package config_test

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

type testConfig struct {
	Env    config.Env `env:"ENV,required,notEmpty"`
	App    config.App
	HTTP   config.HTTP   `envPrefix:"HTTP_"`
	Log    config.Log    `envPrefix:"LOG_"`
	Proxy  config.Proxy  `envPrefix:"PROXY_"`
	DBURL  config.Secret `env:"DATABASE_URL"`
	CAFile string        `env:"DATABASE_CA_FILE"`
}

func load(t *testing.T, vars ...string) (testConfig, error) {
	t.Helper()
	return config.LoadFrom[testConfig]("APP_", append([]string{"APP_ENV=local"}, vars...))
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := load(t)

	require.NoError(t, err)
	assert.Equal(t, config.EnvLocal, cfg.Env)
	assert.Equal(t, "127.0.0.1:8080", cfg.HTTP.Addr)
	assert.Equal(t, 5*time.Second, cfg.HTTP.ReadHeaderTimeout)
	assert.Equal(t, 30*time.Second, cfg.HTTP.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.HTTP.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.HTTP.IdleTimeout)
	assert.Equal(t, config.ByteSize(1<<20), cfg.HTTP.MaxBodyBytes)
	assert.Equal(t, 5*time.Second, cfg.HTTP.ShutdownDrain)
	assert.Equal(t, 30*time.Second, cfg.HTTP.ShutdownTimeout)
	assert.False(t, cfg.HTTP.Docs)
	assert.Empty(t, cfg.HTTP.CORSOrigins)
	assert.Equal(t, slog.LevelInfo, cfg.Log.Level)
	assert.Equal(t, config.LogJSON, cfg.Log.Format)
	assert.Equal(t, config.EdgeNone, cfg.Proxy.Edge)
}

func TestLoad_ParsesValues(t *testing.T) {
	cfg, err := load(t,
		"APP_ENV=test",
		"APP_PUBLIC_URL=http://localhost:8080",
		"APP_HTTP_MAX_BODY_BYTES=20MiB",
		"APP_HTTP_CORS_ORIGINS=https://a.example.com,https://b.example.com",
		"APP_LOG_LEVEL=debug",
		"APP_LOG_FORMAT=text",
		"APP_PROXY_TRUSTED=127.0.0.1/32, unix,10.0.0.0/8",
	)

	require.NoError(t, err)
	assert.Equal(t, config.EnvTest, cfg.Env)
	assert.Equal(t, config.ByteSize(20<<20), cfg.HTTP.MaxBodyBytes)
	assert.Equal(t, []string{"https://a.example.com", "https://b.example.com"}, cfg.HTTP.CORSOrigins)
	assert.Equal(t, slog.LevelDebug, cfg.Log.Level)
	assert.Equal(t, config.LogText, cfg.Log.Format)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}, cfg.Proxy.Trusted.Prefixes)
	assert.True(t, cfg.Proxy.Trusted.Unix)
}

func TestLoad_ProductionProfile(t *testing.T) {
	valid := []string{
		"APP_ENV=production",
		"APP_PUBLIC_URL=https://app.example.com",
		"APP_PROXY_TRUSTED=127.0.0.1/32",
	}

	tests := []struct {
		name    string
		extra   []string
		wantErr []string
	}{
		{name: "valid production config", extra: nil},
		{name: "staging uses the same profile", extra: []string{"APP_ENV=staging", "APP_HTTP_DOCS=true"}, wantErr: []string{"docs routes must be disabled in production"}},
		{name: "public url must be https", extra: []string{"APP_PUBLIC_URL=http://app.example.com"}, wantErr: []string{"public URL must be https in production"}},
		{name: "public url is required", extra: []string{"APP_PUBLIC_URL="}, wantErr: []string{"public URL is required"}},
		{name: "http cors origin refused", extra: []string{"APP_HTTP_CORS_ORIGINS=http://a.example.com"}, wantErr: []string{"must be https in production"}},
		{name: "docs refused", extra: []string{"APP_HTTP_DOCS=true"}, wantErr: []string{"docs routes must be disabled in production"}},
		{name: "cloudflare edge needs trusted proxies", extra: []string{"APP_PROXY_TRUSTED=", "APP_PROXY_EDGE=cloudflare"}, wantErr: []string{"edge cloudflare needs trusted proxies"}},
		{name: "tunnel edge needs tunnel addr", extra: []string{"APP_PROXY_EDGE=cloudflare-tunnel"}, wantErr: []string{"edge cloudflare-tunnel needs a tunnel addr"}},
		{name: "tunnel edge with tunnel addr", extra: []string{"APP_PROXY_EDGE=cloudflare-tunnel", "APP_PROXY_TUNNEL_ADDR=127.0.0.1"}},
		{name: "unix peer counts as a trusted proxy", extra: []string{"APP_PROXY_TRUSTED=unix", "APP_PROXY_EDGE=cloudflare"}},
		{name: "trust-everything prefix refused", extra: []string{"APP_PROXY_TRUSTED=0.0.0.0/0"}, wantErr: []string{"would trust every address"}},
		{
			name:  "every problem is reported at once",
			extra: []string{"APP_PUBLIC_URL=http://x.example.com", "APP_HTTP_DOCS=true", "APP_PROXY_EDGE=cloudflare", "APP_PROXY_TRUSTED=", "APP_LOG_FORMAT=yaml"},
			wantErr: []string{
				"App: public URL must be https in production",
				"HTTP: docs routes must be disabled in production",
				"Proxy: edge cloudflare needs trusted proxies in production",
				"Log: format must be json or text",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, append(append([]string{}, valid...), tt.extra...)...)

			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, want := range tt.wantErr {
				assert.ErrorContains(t, err, want)
			}
		})
	}
}

func TestLoad_NonProductionIsLenient(t *testing.T) {
	_, err := load(t, "APP_ENV=local", "APP_HTTP_DOCS=true", "APP_PUBLIC_URL=http://localhost:8080")

	require.NoError(t, err)
}

func TestLoad_RejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		vars    []string
		wantErr string
	}{
		{name: "unknown env", vars: []string{"APP_ENV=prod"}, wantErr: `must be local, test, staging or production, got "prod"`},
		{name: "bad addr", vars: []string{"APP_HTTP_ADDR=nonsense"}, wantErr: "must be host:port"},
		{name: "bad port", vars: []string{"APP_HTTP_ADDR=:99999"}, wantErr: "invalid port"},
		{name: "relative unix socket", vars: []string{"APP_HTTP_ADDR=unix:app.sock"}, wantErr: "absolute path"},
		{name: "zero header limit", vars: []string{"APP_HTTP_MAX_HEADER_BYTES=0"}, wantErr: "max header bytes"},
		{name: "zero timeout", vars: []string{"APP_HTTP_READ_TIMEOUT=0s"}, wantErr: "read timeout must be positive"},
		{name: "drain longer than timeout", vars: []string{"APP_HTTP_SHUTDOWN_DRAIN=30s"}, wantErr: "shorter than the shutdown timeout"},
		{name: "stop shorter than a request", vars: []string{"APP_HTTP_WRITE_TIMEOUT=60s"}, wantErr: "at least the write timeout"},
		{name: "wildcard cors origin", vars: []string{"APP_HTTP_CORS_ORIGINS=*"}, wantErr: "exact origin"},
		{name: "cors origin with path", vars: []string{"APP_HTTP_CORS_ORIGINS=https://a.example.com/x"}, wantErr: "exact origin"},
		{name: "tunnel addr without tunnel edge", vars: []string{"APP_PROXY_TUNNEL_ADDR=127.0.0.1"}, wantErr: "only used with edge cloudflare-tunnel"},
		{name: "unknown edge", vars: []string{"APP_PROXY_EDGE=fastly"}, wantErr: "edge must be none"},
		{name: "relative public url", vars: []string{"APP_PUBLIC_URL=example.com"}, wantErr: "absolute http(s) URL"},
		{name: "public url with credentials", vars: []string{"APP_PUBLIC_URL=https://user:pw@example.com"}, wantErr: "must not carry credentials"},
		{name: "bad byte size", vars: []string{"APP_HTTP_MAX_BODY_BYTES=lots"}, wantErr: "invalid byte size"},
		{name: "bad duration", vars: []string{"APP_HTTP_IDLE_TIMEOUT=soon"}, wantErr: "IdleTimeout"},
		{name: "bad prefix", vars: []string{"APP_PROXY_TRUSTED=10.0.0.0/99"}, wantErr: "prefix length out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.vars...)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLoad_FileVariables(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	t.Run("reads the file and trims one trailing newline", func(t *testing.T) {
		cfg, err := load(t, "APP_DATABASE_URL_FILE="+write("db", "postgres://secret\n\n"))

		require.NoError(t, err)
		assert.Equal(t, "postgres://secret\n", cfg.DBURL.Reveal())
	})
	t.Run("applies to every field, not just secrets", func(t *testing.T) {
		cfg, err := load(t, "APP_HTTP_ADDR_FILE="+write("addr", "127.0.0.1:9000\n"))

		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1:9000", cfg.HTTP.Addr)
	})
	t.Run("both the variable and its file is an error", func(t *testing.T) {
		_, err := load(t, "APP_DATABASE_URL=plain", "APP_DATABASE_URL_FILE="+write("both", "from-file"))

		require.Error(t, err)
		assert.ErrorContains(t, err, "set one of APP_DATABASE_URL or APP_DATABASE_URL_FILE")
	})
	t.Run("a file over 64 KiB is refused", func(t *testing.T) {
		_, err := load(t, "APP_DATABASE_URL_FILE="+write("big", strings.Repeat("x", 64<<10+1)))

		require.Error(t, err)
		assert.ErrorContains(t, err, "larger than")
	})
	t.Run("a file of exactly 64 KiB is read", func(t *testing.T) {
		_, err := load(t, "APP_DATABASE_URL_FILE="+write("limit", strings.Repeat("x", 64<<10)))

		require.NoError(t, err)
	})
	t.Run("a directory is refused", func(t *testing.T) {
		_, err := load(t, "APP_DATABASE_URL_FILE="+dir)

		require.Error(t, err)
		assert.ErrorContains(t, err, "not a regular file")
	})
	t.Run("a field that itself ends in _FILE still works", func(t *testing.T) {
		cfg, err := load(t, "APP_DATABASE_CA_FILE=/etc/ca.pem")

		require.NoError(t, err)
		assert.Equal(t, "/etc/ca.pem", cfg.CAFile)
	})
	t.Run("a missing file is reported", func(t *testing.T) {
		_, err := load(t, "APP_DATABASE_URL_FILE="+filepath.Join(dir, "missing"))

		require.Error(t, err)
		assert.ErrorContains(t, err, "APP_DATABASE_URL_FILE")
	})
	t.Run("an unrelated _FILE variable is ignored", func(t *testing.T) {
		_, err := load(t, "APP_SOMETHING_ELSE_FILE=/does/not/exist")

		require.NoError(t, err)
	})
}

func TestLoad_EnvIsRequired(t *testing.T) {
	tests := []struct {
		name    string
		vars    []string
		wantErr string
	}{
		{name: "missing", vars: nil, wantErr: "APP_ENV"},
		{name: "empty", vars: []string{"APP_ENV="}, wantErr: "APP_ENV"},
		{name: "unknown", vars: []string{"APP_ENV=prod"}, wantErr: "must be local, test, staging or production"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.LoadFrom[testConfig]("APP_", tt.vars)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLoad_RequiresEnvField(t *testing.T) {
	type noEnv struct {
		HTTP config.HTTP `envPrefix:"HTTP_"`
	}

	_, err := config.LoadFrom[noEnv]("APP_", nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "config.Env")
}

func TestDescribe_RedactsSecretsAndKeepsOrder(t *testing.T) {
	cfg, err := load(t, "APP_DATABASE_URL=postgres://user:hunter2@db/x", "APP_PROXY_TRUSTED=10.0.0.0/8,127.0.0.1/32")
	require.NoError(t, err)

	entries := config.Describe("APP_", cfg)

	got := map[string]string{}
	var keys []string
	for _, e := range entries {
		got[e.Key] = e.Value
		keys = append(keys, e.Key)
	}
	assert.Equal(t, "[redacted]", got["APP_DATABASE_URL"])
	assert.Equal(t, "10.0.0.0/8,127.0.0.1/32", got["APP_PROXY_TRUSTED"])
	assert.Equal(t, "1MiB", got["APP_HTTP_MAX_BODY_BYTES"])
	assert.Equal(t, "5s", got["APP_HTTP_READ_HEADER_TIMEOUT"])
	assert.Equal(t, "local", got["APP_ENV"])
	assert.Equal(t, "APP_ENV", keys[0])
	for _, e := range entries {
		assert.NotContains(t, e.Value, "hunter2")
	}
}
