package main

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The manifest accounts for everything optional in keel, so a new kit package, migration, tagged file or
// marker cannot slip past keel init.
func TestPartsManifest_AccountsForTheTree(t *testing.T) {
	keelOnlyTest(t)
	pl, err := newPlanTree(t.Context(), &tree{root: repoRoot})
	require.NoError(t, err)
	files := pl.files()

	t.Run("kit directories", func(t *testing.T) {
		owners := slices.Clone(coreKit)
		for _, p := range parts {
			owners = append(owners, p.kit...)
		}
		for _, f := range files {
			if !strings.HasPrefix(f, "internal/kit/") {
				continue
			}
			dir := path.Dir(f)
			assert.True(t, slices.ContainsFunc(owners, func(o string) bool { return dir == o || strings.HasPrefix(dir, o+"/") }),
				"%s belongs to no part and is not core: add it to parts.go", dir)
		}
	})

	t.Run("migration stems", func(t *testing.T) {
		owned := slices.Clone(coreMigrations)
		for _, p := range parts {
			owned = append(owned, p.migrations...)
		}
		var found []string
		for _, f := range files {
			if stem, ok := migrationStem(f); ok && strings.HasPrefix(f, migrationsDir+"/") {
				found = append(found, stem)
				assert.Contains(t, owned, stem, "%s belongs to no part and is not core: add it to parts.go", f)
			}
		}
		for _, stem := range owned {
			assert.Contains(t, found, stem, "parts.go names migration %s, which does not exist", stem)
		}
	})

	t.Run("tagged files", func(t *testing.T) {
		for _, f := range files {
			if !strings.HasSuffix(f, ".go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(repoRoot, f)) //nolint:gosec // files git listed in this repository
			require.NoError(t, err)
			_, expr, ok, err := buildLine(src)
			require.NoError(t, err, f)
			if !ok {
				continue
			}
			walkTags(expr, func(tag string) {
				p, _ := partNamed(strings.TrimPrefix(tag, "no"))
				assert.True(t, slices.Contains(ownedFiles(p), f) || slices.ContainsFunc(allPaths(), func(o string) bool { return strings.HasPrefix(f, o+"/") || f == o }),
					"%s is built by %s but parts.go does not list it under %s", f, tag, p.name)
			})
		}
	})

	t.Run("markers", func(t *testing.T) {
		for _, f := range files {
			if strings.HasSuffix(f, ".go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(repoRoot, f)) //nolint:gosec // files git listed in this repository
			require.NoError(t, err)
			_, err = stripMarkers(src, func(string) bool { return true })
			assert.NoError(t, err, f)
		}
	})

	t.Run("manifest paths exist", func(t *testing.T) {
		var missing []string
		check := func(rel string) {
			if !slices.ContainsFunc(files, func(f string) bool { return f == rel || strings.HasPrefix(f, rel+"/") }) {
				missing = append(missing, rel)
			}
		}
		for _, p := range parts {
			for _, rel := range slices.Concat(p.kit, p.paths, ownedFiles(p)) {
				check(rel)
			}
			for _, table := range p.tables {
				if !slices.ContainsFunc(dialectNames, func(d string) bool { return slices.Contains(files, path.Join(dbgenDir, d, "table", table+".go")) }) {
					missing = append(missing, "table "+table)
				}
			}
		}
		for _, rel := range slices.Concat(coreKit, keelOnly[:2], []string{unitFile, embedFile}) {
			check(rel)
		}
		assert.Empty(t, missing)
	})
}

func allPaths() []string {
	var out []string
	for _, p := range parts {
		out = append(out, p.paths...)
	}
	return out
}

// keel never holds .keel-version: init refuses to run where one exists.
func TestKeelHasNoVersionFile(t *testing.T) {
	keelOnlyTest(t)
	_, err := os.Stat(filepath.Join(repoRoot, keelVersionFile))
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// Marker blocks are whole lines; a removed block takes its blank line with it, and a stray or crossed
// closing marker is refused.
func TestStripMarkers(t *testing.T) {
	keep := func(name string) bool { return name != "mail" && name != "mysql" }
	tests := []struct {
		name, in, want, err string
	}{
		{name: "removed block and its blank line", in: "a\n\n<!-- part:mail -->\nmail\n<!-- /part:mail -->\n\nb\n", want: "a\n\nb\n"},
		{name: "kept block loses its markers", in: "a\n# part:files\nfiles\n# /part:files\nb\n", want: "a\nfiles\nb\n"},
		{name: "sql block", in: "a\n-- part:mail\nmail\n-- /part:mail\nb\n", want: "a\nb\n"},
		{name: "nested in a removed block", in: "  # part:mysql\n  # part:files\n  x\n  # /part:files\n  # /part:mysql\ny\n", want: "y\n"},
		{name: "crossed blocks", in: "# part:files\n# part:pdf\n# /part:files\n# /part:pdf\n", err: "does not close"},
		{name: "never closed", in: "# part:files\n", err: "never closed"},
		{name: "unknown part", in: "<!-- part:billing -->\n<!-- /part:billing -->\n", err: "unknown marker"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := stripMarkers([]byte(tt.in), keep)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(out))
		})
	}
}
