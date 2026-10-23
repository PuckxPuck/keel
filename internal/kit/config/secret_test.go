package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

func TestSecret_NeverPrintsTheValue(t *testing.T) {
	s := config.Secret("hunter2")
	type holder struct{ Token config.Secret }

	tests := []struct {
		name string
		got  string
	}{
		{"%v", fmt.Sprintf("%v", s)},
		{"%+v", fmt.Sprintf("%+v", s)},
		{"%#v", fmt.Sprintf("%#v", s)},
		{"%q", fmt.Sprintf("%q", s)},
		{"pointer", fmt.Sprintf("%v", &s)},
		{"embedded in a struct", fmt.Sprintf("%+v", holder{Token: s})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotContains(t, tt.got, "hunter2")
			assert.Contains(t, tt.got, "[redacted]")
		})
	}
}

func TestSecret_JSON(t *testing.T) {
	raw, err := json.Marshal(map[string]config.Secret{"password": "hunter2"})

	require.NoError(t, err)
	assert.JSONEq(t, `{"password":"[redacted]"}`, string(raw))
}

func TestSecret_SlogRedacts(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	logger.Info("config", "db", config.Secret("hunter2"))

	assert.NotContains(t, buf.String(), "hunter2")
	assert.Contains(t, buf.String(), "[redacted]")
}

func TestRequireStrong(t *testing.T) {
	strong := config.Secret(strings.Repeat("k", 32))

	tests := []struct {
		name    string
		secret  config.Secret
		prod    bool
		wantErr string
	}{
		{"32 bytes in production", strong, true, ""},
		{"31 bytes in production", strong[:31], true, "at least 32 bytes"},
		{"empty in production", "", true, "at least 32 bytes"},
		{"example value in production", "keel-app-local", true, "example value"},
		{"example value ignores case", "ChangeMe", true, "example value"},
		{"anything outside production", "x", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.RequireStrong("APP_KEY", tt.secret, tt.prod)

			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, "APP_KEY")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
