package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

func record(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	return out
}

func newLogger(buf *bytes.Buffer) *slog.Logger {
	return logx.New(config.Log{Level: slog.LevelInfo, Format: config.LogJSON}, buf)
}

func TestContextAttributes_AppearOnEveryRecord(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf)
	ctx := logx.With(context.Background(),
		slog.String(logx.KeyRequestID, "req-1"),
		slog.String(logx.KeyTenantID, "tenant-1"),
	)
	ctx = logx.With(ctx, slog.String(logx.KeyUserID, "user-1"), slog.String(logx.KeyTenantID, "tenant-2"))

	logger.InfoContext(ctx, "hello")

	got := record(t, &buf)
	assert.Equal(t, "req-1", got[logx.KeyRequestID])
	assert.Equal(t, "user-1", got[logx.KeyUserID])
	assert.Equal(t, "tenant-2", got[logx.KeyTenantID], "a later value replaces the earlier one")
}

func TestFrom_BindsContextForPlainCalls(t *testing.T) {
	var buf bytes.Buffer
	ctx := logx.WithLogger(context.Background(), newLogger(&buf))
	ctx = logx.With(ctx, slog.String(logx.KeyClientIP, "203.0.113.9"))

	logx.From(ctx).Info("hello")

	assert.Equal(t, "203.0.113.9", record(t, &buf)[logx.KeyClientIP])
}

func TestContextAttributes_StayTopLevelInsideGroups(t *testing.T) {
	var buf bytes.Buffer
	ctx := logx.With(context.Background(), slog.String(logx.KeyRequestID, "req-1"))

	newLogger(&buf).With("component", "auth").WithGroup("http").InfoContext(ctx, "hello", "path", "/x")

	got := record(t, &buf)
	assert.Equal(t, "auth", got["component"])
	assert.Equal(t, "req-1", got[logx.KeyRequestID])
	assert.Equal(t, map[string]any{"path": "/x"}, got["http"])
}

func TestRedaction(t *testing.T) {
	sensitive := []string{
		"password", "Password", "PASSWORD", "new_password", "passwd", "pwd", "pass",
		"client_secret", "access_token", "accessToken", "AccessTOKEN", "refresh-token", "tokens",
		"Authorization", "auth", "bearer", "cookie", "set_cookie", "session_id",
		"api_key", "x-api-key", "X-Api-Key", "APIKey", "apikey", "api.key",
		"otp", "OTPCode", "otp_code", "recovery_code", "code",
		"pin", "jwt", "dsn", "database_url", "credentials", "private_key", "signing_key",
		"signature", "email", "user_email", "phone", "mobile",
	}
	plain := []string{
		"status_code", "exit_code", "tokenizer", "encode", "barcode", "passenger",
		"path", "request_id", "pinned", "address",
	}
	for _, key := range sensitive {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			newLogger(&buf).Info("event", key, "value-123")

			assert.Equal(t, "[redacted]", record(t, &buf)[key])
		})
	}
	for _, key := range plain {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			newLogger(&buf).Info("event", key, "value-123")

			assert.Equal(t, "value-123", record(t, &buf)[key])
		})
	}
}

func TestRedaction_NestedInGroups(t *testing.T) {
	var buf bytes.Buffer

	newLogger(&buf).Info("event",
		slog.Group("request", slog.String("path", "/login"), slog.String("password", "hunter2")),
		slog.Group("authorization", slog.String("scheme", "Bearer"), slog.String("value", "abc")),
	)

	got := record(t, &buf)
	assert.Equal(t, map[string]any{"path": "/login", "password": "[redacted]"}, got["request"])
	assert.Equal(t, map[string]any{"scheme": "[redacted]", "value": "[redacted]"}, got["authorization"])
	assert.NotContains(t, buf.String(), "hunter2")
}

func TestRedaction_AppliesToContextAttributes(t *testing.T) {
	var buf bytes.Buffer
	ctx := logx.With(context.Background(), slog.String("token", "abc123"))

	newLogger(&buf).InfoContext(ctx, "event")

	assert.NotContains(t, buf.String(), "abc123")
}

func TestNew_TextFormatRedacts(t *testing.T) {
	var buf bytes.Buffer
	logger := logx.New(config.Log{Level: slog.LevelInfo, Format: config.LogText}, &buf)

	logger.Warn("kept", "password", "hunter2")

	assert.Contains(t, buf.String(), "password=[redacted]")
	assert.NotContains(t, buf.String(), "hunter2")
}
