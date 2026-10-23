package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gen follows the dialect folders the app keeps: an app with only MySQL needs MySQL, not Postgres, and a
// folder whose database is missing is an error that names the variable to set.
func TestRunGen_NeedsTheDatabaseOfEachDialectFolder(t *testing.T) {
	t.Setenv("APP_TEST_DATABASE_URL", "")
	t.Setenv("APP_TEST_MYSQL_URL", "")
	t.Setenv("KEEL_PG_PORT", "1")
	t.Setenv("KEEL_MYSQL_PORT", "1")
	tests := []struct {
		dialect string
		want    string
		other   string
	}{
		{dialect: "mysql", want: "APP_TEST_MYSQL_URL", other: "APP_TEST_DATABASE_URL"},
		{dialect: "postgres", want: "APP_TEST_DATABASE_URL", other: "APP_TEST_MYSQL_URL"},
	}
	for _, tt := range tests {
		t.Run(tt.dialect, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, migrationsDir, tt.dialect), 0o750))

			err := runGenIn(t.Context(), io.Discard, &tree{root: root}, false)

			require.ErrorContains(t, err, tt.want)
			assert.NotContains(t, err.Error(), tt.other)
		})
	}
}

func TestRemoveStaleSpecs_KeepsOnlyExistingRealms(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"api.openapi.yaml", "retired.openapi.yaml", "notes.md"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
	}

	require.NoError(t, removeStaleSpecs(dir, []string{"api"}))

	assert.FileExists(t, filepath.Join(dir, "api.openapi.yaml"))
	assert.FileExists(t, filepath.Join(dir, "notes.md"))
	assert.NoFileExists(t, filepath.Join(dir, "retired.openapi.yaml"))
}
