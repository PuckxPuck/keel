package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

// Every generator, run into a copy of the repository, leaves code that builds, passes go vet and passes
// its own generated tests, and make:module refuses a module that exists or a name that is not a
// lower-case identifier. Under tenancy each module table is a tenant table from its one migration, so a
// child table's composite foreign key to it applies and the schema passes the tenancy catalogue.
func TestGenerators_OutputBuildsVetsAndPasses(t *testing.T) {
	keelOnlyTest(t) // it asserts keel's own mode, Postgres with tenancy (D36)
	pg := os.Getenv("APP_TEST_DATABASE_URL")
	if pg == "" {
		t.Skip("the Jet types for the new tables need Postgres: set APP_TEST_DATABASE_URL (keel test does)")
	}
	root := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum", "cmd", "internal", "db"} {
		copyInto(t, filepath.Join("..", "..", name), filepath.Join(root, name))
	}
	ctx := t.Context()
	runs := []struct {
		gen  generator
		args []string
	}{
		{makeModule, []string{"gadgets"}},
		{makeMigrationCmd, []string{"gadgets", "create_gadget_parts"}},
		{makeJob, []string{"gadgets", "refresh"}},
		{makeAppCommand, []string{"gadgets:refresh"}},
		{makePermission, []string{"gadgets.archive"}},
	}
	for _, r := range runs {
		require.NoError(t, runGenerator(ctx, os.Stderr, &tree{root: root}, r.gen, r.args, false), "%v", r.args)
	}
	refused := []struct {
		why  string
		gen  generator
		args []string
	}{
		{"an existing module", makeModule, []string{"gadgets"}},
		{"not a lower-case identifier", makeModule, []string{"Gadget_s"}},
		{"a permission already there", makePermission, []string{"gadgets.archive"}},
	}
	for _, r := range refused {
		require.Error(t, runGenerator(ctx, os.Stderr, &tree{root: root}, r.gen, r.args, false), r.why)
	}

	pgDir := filepath.Join(root, migrationsDir, "postgres")
	split, err := filepath.Glob(filepath.Join(pgDir, "*_tenancy_gadget*.sql"))
	require.NoError(t, err)
	assert.Empty(t, split, "no create-then-alter split for module tables")
	child, err := filepath.Glob(filepath.Join(pgDir, "*_gadgets_create_gadget_parts.sql"))
	require.NoError(t, err)
	require.Len(t, child, 1)
	src, err := os.ReadFile(child[0]) //nolint:gosec // inside the test directory
	require.NoError(t, err)
	parent := ",\n    gadget_id uuid not null,\n    foreign key (tenant_id, gadget_id) references gadgets (tenant_id, id) on delete cascade\n);"
	withParent := strings.Replace(string(src), "\n);", parent, 1)
	require.NotEqual(t, string(src), withParent)
	require.NoError(t, os.WriteFile(child[0], []byte(withParent), 0o600)) //nolint:gosec // inside the test directory

	fsys := os.DirFS(pgDir)
	require.NoError(t, genDialect(ctx, db.Postgres, pg, fsys, filepath.Join(root, dbgenDir, "postgres")))
	env, flags := goBuildFlags()
	for _, args := range [][]string{
		append(append([]string{"build"}, flags...), "./..."),
		append(append([]string{"vet"}, flags...), "./internal/app/...", "./internal/modules/...", "./cmd/app"),
		append(append([]string{"test", "-count=1"}, flags...), "./internal/modules/gadgets/..."),
		append(append([]string{"test", "-count=1", "-run", "^(TestCheckCatalogue|TestMigrations_AreValid)$"}, flags...), "./internal/kit/tenancy/"),
	} {
		cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // go build, vet and test with fixed arguments
		cmd.Dir, cmd.Env = root, append(os.Environ(), env, "APP_TEST_DATABASE_URL="+pg, "APP_TEST_MYSQL_URL=")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "go %v:\n%s", args, out)
	}
}

// miniTree is a repository with only what planning a module reads: go.mod, a Postgres migration folder and
// internal/app, whose package-level names and modules.go registration the generators check.
func miniTree(t *testing.T, modulesGo string) *tree {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte(content), 0o600)) //nolint:gosec // inside the test directory
	}
	write("go.mod", "module example.com/app\n\ngo 1.27\n")
	write("db/migrations/postgres/.keep", "")
	write("internal/app/names.go", "package app\n\nvar codes = 1\n\nfunc operations() {}\n")
	if modulesGo == "" {
		src, err := os.ReadFile(filepath.Join("..", "..", "internal", "app", "modules.go"))
		require.NoError(t, err)
		modulesGo = string(src)
	}
	write(modulesFile, modulesGo)
	return &tree{root: root}
}

// A name that would break the build or a migration is refused while planning, before anything is written.
func TestMakeModule_RefusesNamesThatCollide(t *testing.T) {
	tests := []struct {
		name    string
		module  string
		refused string
	}{
		{name: "free name", module: "invoices"},
		{name: "not an identifier", module: "Gadget_s", refused: "lower-case identifier"},
		{name: "go keyword", module: "func", refused: "keyword"},
		{name: "predeclared name", module: "len", refused: "predeclared"},
		{name: "package-level name in internal/app", module: "codes", refused: "codes"},
		{name: "import the module's tests use", module: "strings", refused: "strings"},
		{name: "kit package the module's tests import", module: "users", refused: "users"},
		{name: "type the module declares", module: "services", refused: "Service"},
		{name: "mysql reserved word", module: "groups", refused: "reserved word"},
		{name: "postgres reserved word", module: "user", refused: "reserved word"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := miniTree(t, "")

			err := makeModule(t.Context(), tr, []string{tt.module})
			if err == nil {
				err = tr.validate()
			}

			if tt.refused == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.refused)
		})
	}
}

func TestMakeMigration_RefusesAReservedTableName(t *testing.T) {
	tr := miniTree(t, "")
	require.NoError(t, os.MkdirAll(filepath.Join(tr.root, "internal/modules/billing"), 0o750))

	require.ErrorContains(t, makeMigrationCmd(t.Context(), tr, []string{"billing", "create_order"}), "reserved word")
	require.ErrorContains(t, makeMigrationCmd(t.Context(), tr, []string{"nothere", "create_invoices"}), "not found")
	require.NoError(t, makeMigrationCmd(t.Context(), tr, []string{"billing", "create_invoices"}))
}

// A generator that cannot register itself writes nothing, so the same command works once the file is fixed;
// a write that fails half way puts the tree back.
func TestGenerators_AreAtomic(t *testing.T) {
	t.Run("registration cannot be found", func(t *testing.T) {
		tr := miniTree(t, "package app\n\ntype Module interface{}\n\nvar list = []Module{}\n\nfunc modules(_ *wiring) []Module { return list }\n")

		err := runGenerator(t.Context(), os.Stderr, tr, makeModule, []string{"orders"}, false)

		require.ErrorContains(t, err, "register by hand")
		assert.NoDirExists(t, filepath.Join(tr.root, "internal/modules/orders"))
		entries, readErr := os.ReadDir(filepath.Join(tr.root, "db/migrations/postgres"))
		require.NoError(t, readErr)
		assert.Len(t, entries, 1, "only .keep")
	})
	t.Run("a write fails", func(t *testing.T) {
		root := t.TempDir()
		for name, content := range map[string]string{"edited.txt": "before", "blocked.txt": "kept"} {
			require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o600))
		}
		require.NoError(t, os.Chmod(filepath.Join(root, "blocked.txt"), 0o400))
		tr := &tree{root: root}
		require.NoError(t, tr.create("new/dir/file.txt", []byte("x")))
		require.NoError(t, tr.edit("edited.txt", func([]byte) ([]byte, error) { return []byte("after"), nil }))
		require.NoError(t, tr.edit("blocked.txt", func([]byte) ([]byte, error) { return []byte("changed"), nil }))

		require.Error(t, tr.commit())

		assert.NoDirExists(t, filepath.Join(root, "new"))
		got, err := os.ReadFile(filepath.Join(root, "edited.txt")) //nolint:gosec // inside the test directory
		require.NoError(t, err)
		assert.Equal(t, "before", string(got))
	})
}

// A list written on one line, or without a trailing comma, still gets a valid new element.
func TestInsertListItem_AddsTheMissingComma(t *testing.T) {
	src := []byte("package app\n\nfunc appCommands(_ []string) []int {\n\treturn []int{1}\n}\n")

	out, err := insertListItem(src, listReturnedBy("appCommands"), "2,")

	require.NoError(t, err)
	assert.Contains(t, string(out), "1,\n\t\t2,\n")
}

func copyInto(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Stat(src)
	require.NoError(t, err)
	if info.IsDir() {
		require.NoError(t, os.CopyFS(dst, os.DirFS(src)))
		return
	}
	content, err := os.ReadFile(src) //nolint:gosec // a fixed repository file
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, content, 0o600)) //nolint:gosec // into the test's temporary directory
}

// goBuildFlags match how this test binary was built, so the builds reuse the compiled packages it left
// in the cache (the race detector needs cgo on Linux).
func goBuildFlags() (env string, flags []string) {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "-race" && s.Value == "true" {
				return "CGO_ENABLED=1", []string{"-race"}
			}
		}
	}
	return "CGO_ENABLED=0", nil
}
