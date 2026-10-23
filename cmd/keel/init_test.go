package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const repoRoot = "../.."

// keelOnlyTest skips in an app: the manifest and the init plan describe keel's own tree.
func keelOnlyTest(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(repoRoot, keelVersionFile)); err == nil {
		t.Skip("an app made by keel init; these tests describe keel itself")
	}
}

// The plan over keel's own tree leaves no part build tags, no markers and no keel module path, and every
// manifest path and replacement it uses matches (buildInitPlan fails otherwise).
func TestInitPlan_LeavesNoTraceOfKeel(t *testing.T) {
	keelOnlyTest(t)
	tests := []struct {
		name string
		opts initOptions
		gone []string
		kept []string
	}{
		{
			name: "postgres with every part",
			opts: initOptions{module: "example.com/acme/shop", name: "shop", db: "postgres", envPrefix: "SHOP_"},
			gone: []string{"internal/modules/notes", "db/migrations/mysql", "internal/app/tenancy_off.go", "docs/plans"},
			kept: []string{"internal/kit/tenancy", "deploy/systemd/shop@.service"},
		},
		{
			name: "postgres with notes",
			opts: initOptions{module: "example.com/acme/shop", name: "shop", db: "postgres", envPrefix: "APP_", with: []string{"notes"}},
			kept: []string{"internal/modules/notes"},
		},
		{
			name: "mysql without tenancy",
			opts: initOptions{module: "example.com/acme/shop", name: "shop", db: "mysql", envPrefix: "APP_", without: []string{"tenancy"}},
			gone: []string{"internal/kit/tenancy", "db/migrations/postgres", "docs/tenancy.md", "spec/operator.openapi.yaml"},
			kept: []string{"internal/app/tenancy_off.go"},
		},
		{
			name: "postgres without every part",
			opts: initOptions{module: "example.com/acme/shop", name: "shop", db: "postgres", envPrefix: "APP_", without: []string{"all"}},
			gone: []string{"internal/kit/apikeys", "internal/kit/auth/oidc", "internal/app/mail", "spec/api.openapi.yaml", "internal/kit/otelx"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl, err := buildInitPlan(t.Context(), &tree{root: repoRoot}, tt.opts, "v0.1.0")
			require.NoError(t, err)

			for _, p := range tt.gone {
				assert.Empty(t, pl.under(p), "%s should be removed", p)
			}
			for _, p := range tt.kept {
				assert.NotEmpty(t, pl.under(p), "%s should stay", p)
			}
			gomod, err := pl.read("go.mod")
			require.NoError(t, err)
			assert.Contains(t, string(gomod), "module "+tt.opts.module+"\n")
		})
	}
}

// The self-check catches a keel name or APP_ setting in a file the rewrites do not cover, and leaves
// alone what is meant to stay.
func TestInitPlan_StaleNames(t *testing.T) {
	tests := []struct {
		name, file, src, appName, prefix string
		stale                            bool
	}{
		{name: "deploy path in an uncovered file", file: "deploy/extra.conf", src: "root /srv/app/x\n", appName: "shop", prefix: "APP_", stale: true},
		{name: "role name in an uncovered file", file: "deploy/db/extra.sql", src: "GRANT x TO keel_app;\n", appName: "shop", prefix: "APP_", stale: true},
		{name: "setting under another prefix", file: "deploy/extra.env", src: "APP_HTTP_ADDR=:8080\n", appName: "shop", prefix: "SHOP_", stale: true},
		{name: "the name init would write anyway", file: "deploy/extra.conf", src: "root /srv/app/x\n", appName: "app", prefix: "APP_"},
		{name: "docs use app as the placeholder", file: "docs/extra.md", src: "root /srv/app/x\n", appName: "shop", prefix: "APP_"},
		{name: "test tooling keeps its prefix", file: "deploy/extra.env", src: "APP_TEST_DATABASE_URL=x\n", appName: "shop", prefix: "SHOP_"},
		{name: "kit keeps APP_ in comments", file: "internal/kit/x/x.go", src: "// APP_HTTP_ADDR\n", appName: "shop", prefix: "SHOP_"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := &initPlan{opts: initOptions{name: tt.appName, db: "postgres", envPrefix: tt.prefix}}

			errs := pl.staleNames(tt.file, []byte(tt.src), pl.nameTable())

			assert.Equal(t, tt.stale, len(errs) > 0, "%v", errs)
		})
	}
}

// keel init refuses what would make a broken app, before it plans anything.
func TestInitOptions_Refusals(t *testing.T) {
	valid := initOptions{module: "example.com/acme/shop", name: "shop", db: "postgres", envPrefix: "APP_"}
	tests := []struct {
		name string
		edit func(o *initOptions)
		want string
	}{
		{"unknown part", func(o *initOptions) { o.without = []string{"billing"} }, `unknown part "billing"`},
		{"tenancy on mysql", func(o *initOptions) { o.db = "mysql" }, "--without tenancy"},
		{"notes without its parts", func(o *initOptions) { o.with, o.without = []string{"notes"}, []string{"files"} }, "notes needs files"},
		{"unknown module", func(o *initOptions) { o.with = []string{"invoices"} }, `unknown module "invoices"`},
		{"bad name", func(o *initOptions) { o.name = "My-App" }, "--name"},
		{"keel's own prefix", func(o *initOptions) { o.envPrefix = "KEEL_" }, "--env-prefix"},
		{"bad module path", func(o *initOptions) { o.module = "Example.com//x/" }, "--module"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := valid
			tt.edit(&o)
			_, err := o.removedParts()
			require.ErrorContains(t, err, tt.want)
		})
	}
	_, err := valid.removedParts()
	require.NoError(t, err)
}

// A second run and a dirty tree are refused before anything is planned, since a failed init resets the
// tree to HEAD.
func TestInitPreflight_Refusals(t *testing.T) {
	gitEnv(t)
	opts := initOptions{module: "example.com/acme/shop", name: "shop", db: "postgres", envPrefix: "APP_"}
	committed := func(t *testing.T) string {
		dir := t.TempDir()
		git(t, dir, "init", "-q")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("keel\n"), 0o600))
		git(t, dir, "add", "-A")
		git(t, dir, "commit", "-q", "-m", "keel")
		return dir
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"second run", func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, keelVersionFile), []byte("v0.1.0\n"), 0o600))
			git(t, dir, "add", "-A")
			git(t, dir, "commit", "-q", "-m", "init")
		}, "already run"},
		{"untracked file", func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "scratch.txt"), nil, 0o600))
		}, "untracked"},
		{"changed file", func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("changed\n"), 0o600))
		}, "untracked"},
		{"unreachable database from the environment", func(t *testing.T, _ string) {
			t.Setenv("APP_TEST_DATABASE_URL", "postgres://user:secret@127.0.0.1:1/none?sslmode=disable")
		}, "can reach"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := committed(t)
			tt.setup(t, dir)
			_, err := initPreflight(t.Context(), &strings.Builder{}, &tree{root: dir}, opts)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func gitEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, v := range []string{"AUTHOR", "COMMITTER"} {
		t.Setenv("GIT_"+v+"_NAME", "keel")
		t.Setenv("GIT_"+v+"_EMAIL", "keel@example.com")
	}
}

// keel init on a copy of keel writes an app that builds and vets; what the plan removes and rewrites is
// TestInitPlan's, and gen and the full check run in init-matrix.yml.
func TestInit_EndToEnd(t *testing.T) {
	keelOnlyTest(t)
	if testing.Short() {
		t.Skip("builds a copy of the repository")
	}
	if _, ok := engineNamed("postgres").url(t.Context()); !ok {
		t.Skip("no Postgres: keel init needs the database keel gen uses")
	}
	gitEnv(t)
	dir := t.TempDir()
	listed, err := exec.CommandContext(t.Context(), "git", "-C", repoRoot, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	require.NoError(t, err)
	for _, rel := range strings.Split(string(listed), "\x00") {
		src, err := os.ReadFile(filepath.Join(repoRoot, rel)) //nolint:gosec // files git listed in this repository
		if rel == "" || os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(rel)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), src, 0o600)) //nolint:gosec // rel was listed by git under the repository
	}
	git(t, dir, "init", "-q")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "keel")
	git(t, dir, "tag", "v0.1.0")
	t.Chdir(dir)

	var out strings.Builder
	opts := initOptions{module: "example.com/acme/shop", name: "shop", db: "postgres", envPrefix: "SHOP_"}
	err = runInitIn(t.Context(), &out, &tree{root: "."}, opts, initRun{steps: initBuildSteps})
	require.NoError(t, err, out.String())

	version, err := os.ReadFile(keelVersionFile)
	require.NoError(t, err)
	assert.Equal(t, "v0.1.0\n", string(version))
}

// rollbackRepo is a committed checkout with an executable, a directory, an ignored .env and the tools
// module runSteps looks for; the plan changes, creates and deletes files in it.
func rollbackRepo(t *testing.T) *initPlan {
	t.Helper()
	gitEnv(t)
	dir := t.TempDir()
	files := map[string]string{
		"tools/go.mod": "module x/tools\n", ".gitignore": ".env\n", "README.md": "keel\n",
		"run.sh": "#!/bin/sh\n", "gone/a.txt": "a\n", "gone/b.txt": "b\n",
	}
	for rel, content := range files {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(rel)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o600))
	}
	require.NoError(t, os.Chmod(filepath.Join(dir, "run.sh"), 0o755)) //nolint:gosec // an executable fixture
	git(t, dir, "init", "-q")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "keel")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1\n"), 0o600))
	t.Chdir(dir)

	pt, err := newPlanTree(t.Context(), &tree{root: "."})
	require.NoError(t, err)
	require.NoError(t, pt.replace("README.md", []byte("shop\n")))
	require.NoError(t, pt.create(keelVersionFile, []byte("v0.1.0\n")))
	require.NoError(t, pt.remove("run.sh"))
	require.NoError(t, pt.remove("gone"))
	return &initPlan{planTree: pt, opts: initOptions{db: "postgres", name: "shop"}}
}

// A failure after the first write and an interrupt both put the checkout back at HEAD, modes included,
// and keep ignored files; an interrupt does so even with --keep-on-failure.
func TestApplyInit_RollsBack(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, pl *initPlan) error
		want string
	}{
		{name: "a delete fails midway through the commit", run: func(t *testing.T, pl *initPlan) error {
			pl.unlink = func(p string) error {
				if filepath.Base(p) == "b.txt" {
					return errors.New("injected")
				}
				return os.Remove(p)
			}
			return applyInit(t.Context(), io.Discard, pl, initState{head: "HEAD"}, initRun{steps: func() []step { return nil }})
		}, want: "injected"},
		{name: "interrupted during a step", run: func(t *testing.T, pl *initPlan) error {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			interrupt := step{name: "go build", run: func(ctx context.Context, _ io.Writer) error {
				cancel()
				<-ctx.Done()
				return ctx.Err()
			}}
			return applyInit(ctx, io.Discard, pl, initState{head: "HEAD"}, initRun{keep: true, steps: func() []step { return []step{interrupt} }})
		}, want: "reset to HEAD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := rollbackRepo(t)

			err := tt.run(t, pl)

			require.ErrorContains(t, err, tt.want)
			status, err := exec.CommandContext(t.Context(), "git", "status", "--porcelain", "--untracked-files=all").Output()
			require.NoError(t, err)
			assert.Empty(t, string(status))
			info, err := os.Stat("run.sh")
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
			env, err := os.ReadFile(".env")
			require.NoError(t, err)
			assert.Equal(t, "SECRET=1\n", string(env))
		})
	}
}

// A failed commit's own undo restores deleted files with their mode before git is asked to.
func TestCommitAll_UndoKeepsModes(t *testing.T) {
	pl := rollbackRepo(t)
	pl.unlink = func(p string) error {
		if filepath.Base(p) == "b.txt" {
			return errors.New("injected")
		}
		return os.Remove(p)
	}

	require.ErrorContains(t, pl.commitAll(), "injected")

	info, err := os.Stat("run.sh")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	assert.Equal(t, "keel\n", string(readme))
	assert.NoFileExists(t, keelVersionFile)
}

// The plan never writes through or deletes a symlink, which could point outside the repository.
func TestPlanTree_RefusesSymlinks(t *testing.T) {
	gitEnv(t)
	outside := filepath.Join(t.TempDir(), "outside.md")
	require.NoError(t, os.WriteFile(outside, []byte("outside\n"), 0o600))
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "docs"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docs", "a.md"), []byte("a\n"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "docs", "link.md")))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "top.md")))
	require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(dir, "linked")))
	git(t, dir, "init", "-q")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "keel")
	pt, err := newPlanTree(t.Context(), &tree{root: dir})
	require.NoError(t, err)

	require.ErrorContains(t, pt.replace("top.md", []byte("x\n")), "symlink")
	require.ErrorContains(t, pt.remove("docs"), "symlink")
	require.ErrorContains(t, pt.create("top.md", []byte("x\n")), "already exists")
	require.NoError(t, pt.create("linked/new.md", []byte("x\n")))
	require.ErrorContains(t, pt.commitAll(), "symlink")
	src, err := os.ReadFile(outside) //nolint:gosec // the test's own file
	require.NoError(t, err)
	assert.Equal(t, "outside\n", string(src))
	assert.NoFileExists(t, filepath.Join(filepath.Dir(outside), "new.md"))
}
