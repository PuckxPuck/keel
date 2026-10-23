package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...) //nolint:gosec // test setup with fixed arguments
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

// The compatibility check says why it has nothing to compare, and only compares against a v* tag.
func TestLatestReleaseTag_SaysWhyThereIsNothingToCompare(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, v := range []string{"AUTHOR", "COMMITTER"} {
		t.Setenv("GIT_"+v+"_NAME", "keel")
		t.Setenv("GIT_"+v+"_EMAIL", "keel@example.com")
	}
	repo := func(t *testing.T) string {
		dir := t.TempDir()
		git(t, dir, "init", "-q")
		return dir
	}
	committed := func(t *testing.T) string {
		dir := repo(t)
		git(t, dir, "commit", "-q", "--allow-empty", "-m", "first")
		return dir
	}
	// made is an app keel init made from keel's v0.1.0, with a commit of its own.
	made := func(t *testing.T) string {
		dir := committed(t)
		git(t, dir, "tag", "v0.1.0")
		require.NoError(t, os.WriteFile(filepath.Join(dir, keelVersionFile), []byte("v0.1.0\n"), 0o600))
		git(t, dir, "add", "-A")
		git(t, dir, "commit", "-q", "-m", "keel init")
		return dir
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		tag     string
		skip    string
		failure string
	}{
		{name: "not a repository", setup: func(t *testing.T) string { return t.TempDir() }, skip: "not a git repository"},
		{name: "no commits", setup: repo, skip: "no commits"},
		{name: "no tag", setup: committed, skip: "no release tag"},
		{name: "deploy tags do not count", setup: func(t *testing.T) string {
			dir := committed(t)
			git(t, dir, "tag", "deploy-20261023")
			return dir
		}, skip: "no release tag"},
		{name: "release tag", setup: func(t *testing.T) string {
			dir := committed(t)
			git(t, dir, "tag", "v0.1.0")
			git(t, dir, "tag", "deploy-20261023")
			return dir
		}, tag: "v0.1.0"},
		{name: "an app does not count keel's tags", setup: made, skip: "keel's own tags do not count"},
		{name: "an app's own release tag", setup: func(t *testing.T) string {
			dir := made(t)
			git(t, dir, "tag", "v1.0.0")
			return dir
		}, tag: "v1.0.0"},
		{name: "an app clone without keel's tags", setup: func(t *testing.T) string {
			dir := made(t)
			git(t, dir, "tag", "-d", "v0.1.0")
			return dir
		}, skip: "no release tag"},
		{name: "an app clone without keel's tags, with its own", setup: func(t *testing.T) string {
			dir := made(t)
			git(t, dir, "tag", "-d", "v0.1.0")
			git(t, dir, "tag", "v1.0.0")
			return dir
		}, tag: "v1.0.0"},
		{name: "shallow clone without the tags", setup: func(t *testing.T) string {
			source := committed(t)
			git(t, source, "commit", "-q", "--allow-empty", "-m", "second")
			dir := t.TempDir()
			git(t, dir, "clone", "-q", "--depth", "1", "--no-tags", "file://"+source, dir)
			return dir
		}, failure: "shallow"},
		{name: "shallow app clone without keel's tags", setup: func(t *testing.T) string {
			source := made(t)
			dir := t.TempDir()
			git(t, dir, "clone", "-q", "--depth", "1", "--no-tags", "file://"+source, dir)
			return dir
		}, failure: "shallow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, skip, err := latestReleaseTag(t.Context(), tt.setup(t))

			if tt.failure != "" {
				require.ErrorContains(t, err, tt.failure)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.tag, tag)
			assert.Contains(t, skip, tt.skip)
		})
	}
}
