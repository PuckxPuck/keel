//go:build !nopdf

package app_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctor_FailsAnUnreachableRenderer(t *testing.T) {
	failed := failedChecks(t, "APP_PDF_URL=http://127.0.0.1:1")
	require.Len(t, failed, 1, failed)
	assert.Contains(t, failed[0], "pdf: ")
}
