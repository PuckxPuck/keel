//go:build !nofiles

package app_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doctor writes, reads and removes a probe object, and fails a storage it cannot use.
func TestDoctor_ProbesFileStorage(t *testing.T) {
	root := t.TempDir()
	assert.Empty(t, failedChecks(t, "APP_FILES_DRIVER=local", "APP_FILES_ROOT="+root))
	left, err := os.ReadDir(filepath.Join(root, "doctor"))
	if err == nil {
		assert.Empty(t, left, "the probe object is removed")
	}
	failed := failedChecks(t, "APP_FILES_DRIVER=local", "APP_FILES_ROOT="+filepath.Join(root, "missing"))
	require.Len(t, failed, 1, failed)
	assert.Contains(t, failed[0], "files: ")
}
