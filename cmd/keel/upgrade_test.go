package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upgrade:diff leaves out the kit directories an app removed at init, so git apply does not fail on
// them, and keeps directories keel added after the app's version.
func TestUpgradePathspec_SkipsRemovedParts(t *testing.T) {
	gitEnv(t)
	keel, app := t.TempDir(), t.TempDir()
	write := func(root, rel string) {
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("package x\n"), 0o600))
	}
	for _, rel := range []string{"internal/kit/db/db.go", "internal/kit/auth/auth.go", "internal/kit/auth/oidc/oidc.go", "internal/kit/mail/mail.go", "internal/kit/mail/templates/t.go"} {
		write(keel, rel)
	}
	git(t, keel, "init", "-q")
	git(t, keel, "add", "-A")
	git(t, keel, "commit", "-q", "-m", "v1")
	git(t, keel, "tag", "v0.1.0")
	write(app, "internal/kit/db/db.go")
	write(app, "internal/kit/auth/auth.go")

	paths, err := upgradePathspec(t.Context(), keel, "v0.1.0", app)

	require.NoError(t, err)
	assert.Equal(t, []string{"internal/kit", "cmd/keel", ":(exclude)internal/kit/auth/oidc", ":(exclude)internal/kit/mail"}, paths)
}

// The diff names the app's module path, so it applies to an app whose imports init rewrote.
func TestUpgradeDiff_AppliesAfterModuleRewrite(t *testing.T) {
	gitEnv(t)
	keel, app := t.TempDir(), t.TempDir()
	kit := func(mod, body string) string {
		return "package audit\n\nimport \"" + mod + "/internal/kit/ids\"\n\n" + body
	}
	write := func(root, rel, content string) {
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte(content), 0o600))
	}
	write(keel, "go.mod", "module example.org/keel\n")
	write(keel, "internal/kit/audit/audit.go", kit("example.org/keel", "var a ids.ID\n"))
	git(t, keel, "init", "-q")
	git(t, keel, "add", "-A")
	git(t, keel, "commit", "-q", "-m", "v1")
	git(t, keel, "tag", "v0.1.0")
	write(keel, "internal/kit/audit/audit.go", kit("example.org/keel", "var b ids.ID\n"))
	git(t, keel, "commit", "-q", "-am", "v2")
	git(t, keel, "tag", "v0.2.0")
	write(app, "go.mod", "module example.com/acme/shop\n")
	write(app, keelVersionFile, "v0.1.0\n")
	write(app, "internal/kit/audit/audit.go", kit("example.com/acme/shop", "var a ids.ID\n"))
	git(t, app, "init", "-q")
	t.Chdir(app)

	fs := flag.NewFlagSet("upgrade:diff", flag.ContinueOnError)
	upgradeFlags(fs)
	var patch bytes.Buffer
	fs.SetOutput(&patch)
	require.NoError(t, fs.Parse([]string{"--keel", keel}))
	require.NoError(t, runUpgradeDiff(t.Context(), fs, []string{"v0.2.0"}))

	apply := exec.CommandContext(t.Context(), "git", "apply", "--check", "-")
	apply.Stdin = &patch
	out, err := apply.CombinedOutput()
	require.NoError(t, err, "%s", out)
}
