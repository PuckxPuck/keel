package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/cli"
)

func checkModuleName(name string) error {
	if !moduleNameRE.MatchString(name) {
		return cli.Usagef("module name %q must be a lower-case identifier of 2 to 30 letters and digits, starting with a letter", name)
	}
	if token.IsKeyword(name) || types.Universe.Lookup(name) != nil || name == "main" || name == "init" {
		return cli.Usagef("module name %q is a Go keyword, a predeclared name or reserved for the toolchain", name)
	}
	return checkTableName(name)
}

// checkTableName refuses a name either database needs quoted.
func checkTableName(table string) error {
	if sqlReserved[table] {
		return cli.Usagef("%q is a reserved word in MySQL or PostgreSQL and cannot name a table unquoted", table)
	}
	return nil
}

// validate parses every Go file the plan touches together with the other files of its directory, and
// refuses a plan that would not compile for a naming reason: a package-level name declared twice, or an
// import name that clashes with a declaration in the same package.
func (t *tree) validate() error {
	dirs := map[string]bool{}
	for rel := range t.pending {
		if strings.HasSuffix(rel, ".go") {
			dirs[filepath.Dir(rel)] = true
		}
	}
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		if err := t.checkScope(dir); err != nil {
			return err
		}
	}
	return nil
}

type scopedFile struct {
	rel     string
	imports map[string]string
}

type packageScope struct {
	declared map[string]string
	files    []scopedFile
}

func (t *tree) checkScope(dir string) error {
	sources, err := t.dirSources(dir)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	pkgs := map[string]*packageScope{}
	for _, rel := range slices.Sorted(maps.Keys(sources)) {
		f, err := parser.ParseFile(fset, rel, sources[rel], parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("%s does not parse: %w", rel, err)
		}
		scope := pkgs[f.Name.Name]
		if scope == nil {
			scope = &packageScope{declared: map[string]string{}}
			pkgs[f.Name.Name] = scope
		}
		for _, name := range declaredNames(f) {
			if other, dup := scope.declared[name]; dup {
				return fmt.Errorf("%s declares %s, which %s already declares in package %s", rel, name, other, f.Name.Name)
			}
			scope.declared[name] = rel
		}
		imports, err := importNames(rel, f)
		if err != nil {
			return err
		}
		scope.files = append(scope.files, scopedFile{rel: rel, imports: imports})
	}
	for pkg, scope := range pkgs {
		for _, file := range scope.files {
			for name, importPath := range file.imports {
				if other, clash := scope.declared[name]; clash {
					return fmt.Errorf("%s imports %q as %s, which package %s also declares in %s; pick another name", file.rel, importPath, name, pkg, other)
				}
			}
		}
	}
	return nil
}

// dirSources is the Go files in dir (not below it) that the default build includes, as the plan would
// leave them.
func (t *tree) dirSources(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	entries, err := os.ReadDir(t.path(dir))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if ok, _ := build.Default.MatchFile(t.path(dir), e.Name()); !ok {
			continue
		}
		rel := filepath.Join(dir, e.Name())
		if out[rel], err = t.read(rel); err != nil {
			return nil, err
		}
	}
	for rel, src := range t.pending {
		if filepath.Dir(rel) == dir && strings.HasSuffix(rel, ".go") {
			out[rel] = src
		}
	}
	return out, nil
}

func declaredNames(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.Name != "init" {
				out = append(out, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					out = append(out, spec.Name.Name)
				case *ast.ValueSpec:
					for _, n := range spec.Names {
						out = append(out, n.Name)
					}
				}
			}
		}
	}
	return slices.DeleteFunc(out, func(n string) bool { return n == "_" })
}

var majorVersionRE = regexp.MustCompile(`^v[0-9]+$`)

// importNames maps the name each import binds in the file to its path; blank and dot imports bind none.
func importNames(rel string, f *ast.File) (map[string]string, error) {
	out := map[string]string{}
	for _, spec := range f.Imports {
		p := strings.Trim(spec.Path.Value, `"`)
		name := path.Base(p)
		if majorVersionRE.MatchString(name) {
			name = path.Base(path.Dir(p))
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		if other, dup := out[name]; dup {
			return nil, fmt.Errorf("%s imports both %q and %q as %s; pick another name", rel, other, p, name)
		}
		out[name] = p
	}
	return out, nil
}
