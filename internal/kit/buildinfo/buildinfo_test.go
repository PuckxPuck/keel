package buildinfo

import (
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve(t *testing.T) {
	vcs := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.3.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-10-22T10:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	tests := []struct {
		name                           string
		version, commit, buildTime     string
		bi                             *debug.BuildInfo
		wantVersion, wantCommit, wantT string
		wantModified                   bool
	}{
		{
			name: "ldflags win", version: "v1.2.3", commit: "def456", buildTime: "2026-01-01T00:00:00Z", bi: vcs,
			wantVersion: "v1.2.3", wantCommit: "def456", wantT: "2026-01-01T00:00:00Z", wantModified: true,
		},
		{
			name: "falls back to vcs settings", bi: vcs,
			wantVersion: "v0.3.0", wantCommit: "abc123", wantT: "2026-10-22T10:00:00Z", wantModified: true,
		},
		{
			name: "devel main version is not a version", bi: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			wantVersion: "dev",
		},
		{name: "no build info at all", wantVersion: "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolve(tt.version, tt.commit, tt.buildTime, tt.bi)

			assert.Equal(t, tt.wantVersion, got.Version)
			assert.Equal(t, tt.wantCommit, got.Commit)
			assert.Equal(t, tt.wantT, got.BuildTime)
			assert.Equal(t, tt.wantModified, got.Modified)
			assert.Equal(t, runtime.Version(), got.GoVersion)
		})
	}
}
