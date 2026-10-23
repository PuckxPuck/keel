package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"
)

//go:embed templates
var templates embed.FS

// tree is the repository a generator plans its changes in. Nothing reaches the disk until commit, and a
// failed commit puts everything back.
type tree struct {
	root string
	// pending holds the content of every file this run creates or replaces.
	pending  map[string][]byte
	original map[string][]byte
	created  []string
	changed  []string
	written  []string
	madeDirs []string
}

func repoTree() (*tree, error) {
	if _, err := os.Stat("tools/go.mod"); err != nil {
		return nil, errors.New("run keel from the repository root (tools/go.mod not found)")
	}
	return &tree{root: "."}, nil
}

func (t *tree) path(rel string) string { return filepath.Join(t.root, rel) }

func (t *tree) exists(rel string) bool {
	if _, ok := t.pending[rel]; ok {
		return true
	}
	_, err := os.Lstat(t.path(rel))
	return err == nil
}

// regularFile returns p's permissions and refuses a symlink or anything else that is not a plain file,
// so keel never writes through a link to a file outside the repository.
func regularFile(p string) (fs.FileMode, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is a symlink or not a regular file; keel only changes regular files", p)
	}
	return info.Mode().Perm(), nil
}

func (t *tree) read(rel string) ([]byte, error) {
	if src, ok := t.pending[rel]; ok {
		return src, nil
	}
	return os.ReadFile(t.path(rel)) //nolint:gosec // rel is built from validated names under the repository
}

func (t *tree) plan(rel string, content []byte) {
	if t.pending == nil {
		t.pending = map[string][]byte{}
	}
	t.pending[rel] = content
}

// create plans a new file and refuses to overwrite one.
func (t *tree) create(rel string, content []byte) error {
	if t.exists(rel) {
		return fmt.Errorf("%s already exists; generators never overwrite files", rel)
	}
	t.plan(rel, content)
	t.created = append(t.created, rel)
	return nil
}

// replace plans new content for a file that exists.
func (t *tree) replace(rel string, content []byte) error {
	if !slices.Contains(t.created, rel) && !slices.Contains(t.changed, rel) {
		if _, err := regularFile(t.path(rel)); err != nil {
			return err
		}
		src, err := t.read(rel)
		if err != nil {
			return err
		}
		if t.original == nil {
			t.original = map[string][]byte{}
		}
		t.original[rel] = src
		t.changed = append(t.changed, rel)
	}
	t.plan(rel, content)
	return nil
}

// edit applies fn to rel's content and plans the result.
func (t *tree) edit(rel string, fn func([]byte) ([]byte, error)) error {
	src, err := t.read(rel)
	if err != nil {
		return err
	}
	out, err := fn(src)
	if err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return t.replace(rel, out)
}

// commit writes the plan: new files first, then edits. When anything fails it undoes what it wrote.
func (t *tree) commit() error {
	for _, rel := range slices.Concat(t.created, t.changed) {
		if err := t.writeFile(rel, slices.Contains(t.created, rel)); err != nil {
			return errors.Join(fmt.Errorf("write %s: %w", rel, err), t.undo())
		}
	}
	return nil
}

func (t *tree) writeFile(rel string, isNew bool) error {
	if err := t.throughLink(rel); err != nil {
		return err
	}
	p := t.path(rel)
	if err := t.makeDirs(filepath.Dir(p)); err != nil {
		return err
	}
	if !isNew {
		if _, err := regularFile(p); err != nil {
			return err
		}
		return os.WriteFile(p, t.pending[rel], 0o600)
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // p is a validated path under the repository
	if err != nil {
		return err
	}
	t.written = append(t.written, rel)
	_, err = f.Write(t.pending[rel])
	return errors.Join(err, f.Close())
}

// throughLink refuses rel when a directory on its way from the root is a symlink, so a write cannot land
// outside the repository.
func (t *tree) throughLink(rel string) error {
	for d := filepath.Dir(filepath.Clean(rel)); d != "." && d != string(filepath.Separator); d = filepath.Dir(d) {
		if info, err := os.Lstat(t.path(d)); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; keel never writes through one", d)
		}
	}
	return nil
}

// makeDirs creates dir and records the directories it had to make, so undo can remove them.
func (t *tree) makeDirs(dir string) error {
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil || d == filepath.Dir(d) {
			break
		}
		missing = append(missing, d)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	t.madeDirs = append(t.madeDirs, missing...)
	return nil
}

// undo removes the files and directories a commit made and restores the files it edited.
func (t *tree) undo() error {
	var errs []error
	for _, rel := range t.written {
		if err := os.Remove(t.path(rel)); err != nil {
			errs = append(errs, err)
		}
	}
	for _, rel := range t.changed {
		if err := os.WriteFile(t.path(rel), t.original[rel], 0o600); err != nil {
			errs = append(errs, err)
		}
	}
	for _, d := range t.madeDirs {
		_ = os.Remove(d) // only empty directories go
	}
	return errors.Join(errs...)
}

func (t *tree) report(w interface{ Write([]byte) (int, error) }) {
	for _, f := range t.created {
		_, _ = fmt.Fprintf(w, "created %s\n", f)
	}
	for _, f := range t.changed {
		_, _ = fmt.Fprintf(w, "changed %s\n", f)
	}
}

var modulePathRE = regexp.MustCompile(`(?m)^module\s+(\S+)\s*$`)

func (t *tree) modulePath() (string, error) {
	src, err := t.read("go.mod")
	if err != nil {
		return "", err
	}
	m := modulePathRE.FindSubmatch(src)
	if m == nil {
		return "", errors.New("go.mod has no module line")
	}
	return string(m[1]), nil
}

const migrationsDir = "db/migrations"

// dialects are the migration folders the app keeps, Postgres first.
func (t *tree) dialects() []string {
	var out []string
	for _, d := range []string{"postgres", "mysql"} {
		if t.exists(filepath.Join(migrationsDir, d)) {
			out = append(out, d)
		}
	}
	return out
}

// tenancy is true when the app keeps the tenancy part.
func (t *tree) tenancy() bool { return t.exists("internal/kit/tenancy") }

func render(name string, data any) ([]byte, error) {
	tpl, err := template.New(filepath.Base(name)).Delims("{%", "%}").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).ParseFS(templates, "templates/"+name)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func renderGo(name string, data any) ([]byte, error) {
	src, err := render(name, data)
	if err != nil {
		return nil, err
	}
	out, err := format.Source(src)
	if err != nil {
		return nil, fmt.Errorf("format %s: %w", name, err)
	}
	return out, nil
}

// locator finds the position a Go edit inserts before.
type locator func(f *ast.File) (token.Pos, bool)

// insertGo inserts text on its own line before the position at finds, then formats the file.
func insertGo(src []byte, at locator, text string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	pos, ok := at(f)
	if !ok {
		return nil, errors.New("cannot find where to add the registration")
	}
	off := fset.Position(pos).Offset
	line := off
	for line > 0 && (src[line-1] == ' ' || src[line-1] == '\t') {
		line--
	}
	if line > 0 && src[line-1] == '\n' {
		return format.Source(slices.Concat(src[:line], []byte(text+"\n"), src[line:]))
	}
	return format.Source(slices.Concat(src[:off], []byte("\n"+text+"\n"), src[off:]))
}

// litFinder finds the composite literal a registration is added to.
type litFinder func(f *ast.File) (*ast.CompositeLit, bool)

// listReturnedBy finds the composite literal function fn returns.
func listReturnedBy(fn string) litFinder {
	return func(f *ast.File) (*ast.CompositeLit, bool) {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Body == nil {
				continue
			}
			for _, s := range fd.Body.List {
				if ret, ok := s.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
					if lit, ok := ret.Results[0].(*ast.CompositeLit); ok {
						return lit, true
					}
				}
			}
		}
		return nil, false
	}
}

// insertListItem adds item as the last element of the literal at find, on its own line, with the
// commas a single-line or comma-less list is missing.
func insertListItem(src []byte, find litFinder, item string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	lit, ok := find(f)
	if !ok {
		return nil, errors.New("cannot find the list to add to")
	}
	if n := len(lit.Elts); n > 0 {
		end := fset.Position(lit.Elts[n-1].End()).Offset
		if !bytes.Contains(src[end:fset.Position(lit.Rbrace).Offset], []byte(",")) {
			src = slices.Concat(src[:end], []byte(","), src[end:])
		}
	}
	return insertGo(src, func(f *ast.File) (token.Pos, bool) {
		lit, ok := find(f)
		if !ok {
			return token.NoPos, false
		}
		return lit.Rbrace, true
	}, item)
}

// methodEnd is the closing brace of the body of method name.
func methodEnd(name string) locator {
	return func(f *ast.File) (token.Pos, bool) {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && fd.Name.Name == name && fd.Body != nil {
				return fd.Body.Rbrace, true
			}
		}
		return token.NoPos, false
	}
}

// varList finds the composite literal assigned to the package variable name.
func varList(name string) litFinder {
	return func(f *ast.File) (*ast.CompositeLit, bool) {
		for _, spec := range specs(f, token.VAR) {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != name || len(vs.Values) != 1 {
				continue
			}
			if lit, ok := vs.Values[0].(*ast.CompositeLit); ok {
				return lit, true
			}
		}
		return nil, false
	}
}

// constBlockOf is the closing parenthesis of the const block declaring constants of type pkg.name.
func constBlockOf(pkg, name string) locator {
	return func(f *ast.File) (token.Pos, bool) {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST || !gd.Rparen.IsValid() {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if sel, ok := vs.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
						return gd.Rparen, true
					}
				}
			}
		}
		return token.NoPos, false
	}
}

func importBlockEnd(f *ast.File) (token.Pos, bool) {
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT && gd.Rparen.IsValid() {
			return gd.Rparen, true
		}
	}
	return token.NoPos, false
}

func specs(f *ast.File, tok token.Token) []ast.Spec {
	var out []ast.Spec
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == tok {
			out = append(out, gd.Specs...)
		}
	}
	return out
}

// addImport adds path to the file's import block, in its last (local) group.
func addImport(src []byte, path string) ([]byte, error) {
	if bytes.Contains(src, []byte(`"`+path+`"`)) {
		return src, nil
	}
	return insertGo(src, importBlockEnd, `"`+path+`"`)
}

// useParam names the first parameter of function or method fn when it is blank (`_ T` or just `T`) so a
// registration can use it, and returns the name to use.
func useParam(src []byte, fn string, method bool, want string) ([]byte, string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, "", err
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || (fd.Recv != nil) != method || fd.Name.Name != fn || fd.Type.Params == nil || len(fd.Type.Params.List) == 0 {
			continue
		}
		param := fd.Type.Params.List[0]
		switch {
		case len(param.Names) == 0:
			at := fset.Position(param.Type.Pos()).Offset
			return slices.Concat(src[:at], []byte(want+" "), src[at:]), want, nil
		case param.Names[0].Name == "_":
			at := fset.Position(param.Names[0].Pos()).Offset
			return slices.Concat(src[:at], []byte(want), src[at+1:]), want, nil
		}
		return src, param.Names[0].Name, nil
	}
	return nil, "", fmt.Errorf("cannot find %s", fn)
}

// goFiles lists the Go files under dir (relative to the tree), for checks that read every one.
func (t *tree) goFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(filepath.Join(t.root, dir), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		rel, err := filepath.Rel(t.root, p)
		out = append(out, rel)
		return err
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return out, err
}
