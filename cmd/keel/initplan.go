package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// planTree adds deletes to the generators' tree. A deleted file's content and mode are read at plan time
// so a failed commit can put it back.
type planTree struct {
	*tree
	listed []string
	// irregular are the listed paths that are symlinks or not files; the plan never changes or deletes them.
	irregular []string
	deleted   map[string][]byte
	modes     map[string]fs.FileMode
	order     []string
	gone      []string
	// unlink deletes a file during commitAll; tests replace it to fail midway.
	unlink func(string) error
}

// newPlanTree lists the repository's files as git sees them (tracked plus untracked, never ignored), so
// .env and build output are left alone.
func newPlanTree(ctx context.Context, t *tree) (*planTree, error) {
	out, err := gitOutput(ctx, t.root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	p := &planTree{tree: t, deleted: map[string][]byte{}, modes: map[string]fs.FileMode{}, unlink: os.Remove}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		info, err := os.Lstat(t.path(rel))
		switch {
		case err != nil:
		case info.Mode().IsRegular():
			p.listed = append(p.listed, rel)
		default:
			p.irregular = append(p.irregular, rel)
		}
	}
	slices.Sort(p.listed)
	return p, nil
}

func (p *planTree) isDeleted(rel string) bool {
	_, ok := p.deleted[rel]
	return ok
}

// under lists the live files at rel or below it.
func (p *planTree) under(rel string) []string {
	var out []string
	for _, f := range p.files() {
		if f == rel || strings.HasPrefix(f, rel+"/") {
			out = append(out, f)
		}
	}
	return out
}

// files are the live files: listed and not deleted, plus those the plan creates.
func (p *planTree) files() []string {
	var out []string
	for _, f := range p.listed {
		if !p.isDeleted(f) {
			out = append(out, f)
		}
	}
	for _, f := range p.created {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// remove plans the deletion of rel, a file or a directory and everything in it. It fails when rel has
// no live file, so a manifest entry that matches nothing is caught.
func (p *planTree) remove(rel string) error {
	files := p.under(rel)
	if len(files) == 0 {
		return fmt.Errorf("%s does not exist", rel)
	}
	if i := slices.IndexFunc(p.irregular, func(f string) bool { return f == rel || strings.HasPrefix(f, rel+"/") }); i >= 0 {
		return fmt.Errorf("%s is a symlink or not a regular file; keel only deletes regular files", p.irregular[i])
	}
	for _, f := range files {
		if slices.Contains(p.created, f) || slices.Contains(p.changed, f) {
			return fmt.Errorf("%s is both changed and deleted by the plan", f)
		}
		mode, err := regularFile(p.path(f))
		if err != nil {
			return err
		}
		src, err := os.ReadFile(p.path(f)) //nolint:gosec // f was listed by git under the repository
		if err != nil {
			return err
		}
		p.deleted[f] = src
		p.modes[f] = mode
		p.order = append(p.order, f)
	}
	return nil
}

// removeIfPresent deletes rel when it has live files, and says whether it did.
func (p *planTree) removeIfPresent(rel string) (bool, error) {
	if len(p.under(rel)) == 0 {
		return false, nil
	}
	return true, p.remove(rel)
}

// commitAll writes the plan, then deletes. When anything fails it undoes what it did.
func (p *planTree) commitAll() error {
	if err := p.commit(); err != nil {
		return err
	}
	for _, f := range p.order {
		if _, err := regularFile(p.path(f)); err != nil {
			return errors.Join(err, p.undoAll())
		}
		if err := p.unlink(p.path(f)); err != nil {
			return errors.Join(fmt.Errorf("delete %s: %w", f, err), p.undoAll())
		}
		p.gone = append(p.gone, f)
	}
	for _, f := range p.order {
		for d := filepath.Dir(p.path(f)); d != filepath.Clean(p.root); d = filepath.Dir(d) {
			if os.Remove(d) != nil {
				break // not empty
			}
		}
	}
	return nil
}

func (p *planTree) undoAll() error {
	var errs []error
	for _, f := range p.gone {
		if err := os.MkdirAll(filepath.Dir(p.path(f)), 0o750); err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, os.WriteFile(p.path(f), p.deleted[f], 0o600), os.Chmod(p.path(f), p.modes[f]))
	}
	return errors.Join(append(errs, p.undo())...)
}

// initOptions are keel init's flags.
type initOptions struct {
	module, name, db, envPrefix string
	without                     []string
	with                        []string
}

var (
	appNameRE   = regexp.MustCompile(`^[a-z][a-z0-9]{1,29}$`)
	envPrefixRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*_$`)
	appModuleRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9](/[A-Za-z0-9._~-]+)*$`)
)

// removedParts validates the options and returns the parts init removes.
func (o initOptions) removedParts() ([]part, error) {
	var errs []error
	if !appModuleRE.MatchString(o.module) || strings.Contains(o.module, "..") || strings.HasSuffix(o.module, "/") {
		errs = append(errs, fmt.Errorf("--module %q is not a module path (example.com/me/app)", o.module))
	}
	if !appNameRE.MatchString(o.name) {
		errs = append(errs, fmt.Errorf("--name %q must match %s", o.name, appNameRE))
	}
	if !slices.Contains(dialectNames, o.db) {
		errs = append(errs, fmt.Errorf("--db must be postgres or mysql, got %q", o.db))
	}
	if !envPrefixRE.MatchString(o.envPrefix) || o.envPrefix == "KEEL_" {
		errs = append(errs, fmt.Errorf("--env-prefix %q must match %s and not be KEEL_", o.envPrefix, envPrefixRE))
	}
	removed := map[string]bool{}
	for _, name := range o.without {
		switch {
		case name == "all":
			for _, n := range optionalParts() {
				removed[n] = true
			}
		case slices.Contains(optionalParts(), name):
			removed[name] = true
		default:
			errs = append(errs, fmt.Errorf("--without: unknown part %q (parts: %s)", name, strings.Join(optionalParts(), ", ")))
		}
	}
	for _, p := range parts {
		if p.module && !slices.Contains(o.with, p.name) {
			removed[p.name] = true
		}
	}
	for _, name := range o.with {
		if p, ok := partNamed(name); !ok || !p.module {
			errs = append(errs, fmt.Errorf("--with: unknown module %q", name))
		}
	}
	var out []part
	for _, p := range parts {
		if removed[p.name] {
			out = append(out, p)
			continue
		}
		if p.postgresOnly && o.db == "mysql" {
			errs = append(errs, fmt.Errorf("%s needs Postgres: add --without %s for MySQL", p.name, p.name))
		}
		for _, r := range p.requires {
			if removed[r] {
				errs = append(errs, fmt.Errorf("%s needs %s, which --without removes", p.name, r))
			}
		}
	}
	return out, errors.Join(errs...)
}

// initPlan is everything keel init changes, planned in memory.
type initPlan struct {
	*planTree
	opts    initOptions
	removed []part
	oldMod  string
	// requested are the paths the plan removes, as named (for the report).
	requested []string
}

func (pl *initPlan) removedNames() []string {
	var out []string
	for _, p := range pl.removed {
		out = append(out, p.name)
	}
	return out
}

func (pl *initPlan) isRemoved(name string) bool { return slices.Contains(pl.removedNames(), name) }

// buildInitPlan plans keel init in memory and checks the result; nothing is written.
func buildInitPlan(ctx context.Context, t *tree, opts initOptions, version string) (*initPlan, error) {
	removed, err := opts.removedParts()
	if err != nil {
		return nil, err
	}
	pt, err := newPlanTree(ctx, t)
	if err != nil {
		return nil, err
	}
	oldMod, err := t.modulePath()
	if err != nil {
		return nil, err
	}
	pl := &initPlan{planTree: pt, opts: opts, removed: removed, oldMod: oldMod}
	steps := []func() error{
		pl.removeParts, pl.removeDialect, pl.removeKeelOnly, pl.applyConstraints,
		pl.pruneUseSchema, pl.renameUnit, pl.stripAllMarkers, pl.rewrite,
		func() error { return pl.create(keelVersionFile, []byte(version+"\n")) },
		pl.check,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return pl, nil
}

func (pl *initPlan) removePath(rel string) error {
	if err := pl.remove(rel); err != nil {
		return err
	}
	pl.requested = append(pl.requested, rel)
	return nil
}

func (pl *initPlan) removeParts() error {
	var errs []error
	for _, p := range pl.removed {
		for _, rel := range slices.Concat(p.kit, p.paths) {
			if err := pl.removeOnce(rel); err != nil {
				errs = append(errs, fmt.Errorf("part %s: %w", p.name, err))
			}
		}
		for _, stem := range p.migrations {
			if err := pl.removeMigration(stem); err != nil {
				errs = append(errs, fmt.Errorf("part %s: %w", p.name, err))
			}
		}
		for _, table := range p.tables {
			if err := pl.removeTable(table); err != nil {
				errs = append(errs, fmt.Errorf("part %s: %w", p.name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// removeOnce removes rel unless an earlier part already removed it or a directory holding it.
func (pl *initPlan) removeOnce(rel string) error {
	if slices.ContainsFunc(pl.requested, func(r string) bool { return rel == r || strings.HasPrefix(rel, r+"/") }) {
		return nil
	}
	return pl.removePath(rel)
}

var migrationRE = regexp.MustCompile(`^\d{14}_([a-z0-9_]+)\.sql$`)

// migrationStem is a migration file's name without its timestamp and extension.
func migrationStem(file string) (string, bool) {
	m := migrationRE.FindStringSubmatch(path.Base(file))
	if m == nil {
		return "", false
	}
	return m[1], true
}

func (pl *initPlan) removeMigration(stem string) error {
	found := false
	for _, f := range pl.listed {
		if s, ok := migrationStem(f); ok && s == stem && strings.HasPrefix(f, migrationsDir+"/") {
			found = true
			if !pl.isDeleted(f) {
				if err := pl.remove(f); err != nil {
					return err
				}
			}
		}
	}
	if !found {
		return fmt.Errorf("no migration %s in %s", stem, migrationsDir)
	}
	return nil
}

func (pl *initPlan) removeTable(table string) error {
	found := false
	for _, d := range dialectNames {
		for _, kind := range []string{"table", "model"} {
			f := path.Join(dbgenDir, d, kind, table+".go")
			if !slices.Contains(pl.listed, f) {
				continue
			}
			found = true
			if !pl.isDeleted(f) {
				if err := pl.remove(f); err != nil {
					return err
				}
			}
		}
	}
	if !found {
		return fmt.Errorf("no generated table %s in %s", table, dbgenDir)
	}
	return nil
}

func (pl *initPlan) otherDialect() string {
	if pl.opts.db == "postgres" {
		return "mysql"
	}
	return "postgres"
}

func (pl *initPlan) removeDialect() error {
	other := pl.otherDialect()
	for _, dir := range []string{path.Join(migrationsDir, other), path.Join(dbgenDir, other)} {
		if err := pl.removeRequested(dir); err != nil {
			return err
		}
	}
	return pl.applyReplacements(dialectReplacements(pl.opts.db))
}

func (pl *initPlan) removeKeelOnly() error {
	for _, rel := range keelOnly {
		if err := pl.removeRequested(rel); err != nil {
			return err
		}
	}
	return nil
}

func (pl *initPlan) removeRequested(rel string) error {
	removed, err := pl.removeIfPresent(rel)
	if removed {
		pl.requested = append(pl.requested, rel)
	}
	return err
}

func (pl *initPlan) goFiles() []string {
	var out []string
	for _, f := range pl.files() {
		if strings.HasSuffix(f, ".go") {
			out = append(out, f)
		}
	}
	return out
}

// partTags are the build tags of every part, no<name>.
func partTags() map[string]string {
	out := map[string]string{}
	for _, p := range parts {
		out[p.tag()] = p.name
	}
	return out
}

// buildLine finds a Go file's //go:build line and the part tags it names. ok is false when the file has
// no constraint naming a part; a constraint that mixes part tags with others is an error.
func buildLine(src []byte) (line int, expr constraint.Expr, ok bool, err error) {
	for i, l := range strings.Split(string(src), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "package ") {
			break
		}
		if !constraint.IsGoBuild(l) {
			continue
		}
		expr, err := constraint.Parse(l)
		if err != nil {
			return 0, nil, false, err
		}
		var mine, other []string
		tags := partTags()
		walkTags(expr, func(tag string) {
			if _, isPart := tags[tag]; isPart {
				mine = append(mine, tag)
			} else {
				other = append(other, tag)
			}
		})
		if len(mine) == 0 {
			return 0, nil, false, nil
		}
		if len(other) > 0 {
			return 0, nil, false, fmt.Errorf("constraint %q mixes part tags with %s", l, strings.Join(other, ", "))
		}
		return i, expr, true, nil
	}
	return 0, nil, false, nil
}

func walkTags(e constraint.Expr, fn func(string)) {
	switch x := e.(type) {
	case *constraint.TagExpr:
		fn(x.Tag)
	case *constraint.NotExpr:
		walkTags(x.X, fn)
	case *constraint.AndExpr:
		walkTags(x.X, fn)
		walkTags(x.Y, fn)
	case *constraint.OrExpr:
		walkTags(x.X, fn)
		walkTags(x.Y, fn)
	}
}

// applyConstraints keeps each Go file the app's parts build and drops its constraint line, so the app
// builds without tags; files only another set of parts builds are deleted.
func (pl *initPlan) applyConstraints() error {
	set := map[string]bool{}
	for _, p := range pl.removed {
		set[p.tag()] = true
	}
	for _, f := range pl.goFiles() {
		src, err := pl.read(f)
		if err != nil {
			return err
		}
		line, expr, ok, err := buildLine(src)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if !ok {
			continue
		}
		if !expr.Eval(func(tag string) bool { return set[tag] }) {
			if err := pl.remove(f); err != nil {
				return err
			}
			continue
		}
		lines := strings.Split(string(src), "\n")
		end := line + 1
		if end < len(lines) && strings.TrimSpace(lines[end]) == "" {
			end++
		}
		if err := pl.replace(f, []byte(strings.Join(slices.Delete(lines, line, end), "\n"))); err != nil {
			return err
		}
	}
	return nil
}

var useSchemaLineRE = regexp.MustCompile(`^\t(\w+) = \w+\.FromSchema\(schema\)$`)

// pruneUseSchema drops the generated UseSchema lines of deleted tables, so the app builds before keel gen
// regenerates internal/dbgen.
func (pl *initPlan) pruneUseSchema() error {
	for _, d := range dialectNames {
		dir := path.Join(dbgenDir, d, "table")
		file := path.Join(dir, "table_use_schema.go")
		if pl.isDeleted(file) || !slices.Contains(pl.listed, file) {
			continue
		}
		declared := map[string]bool{}
		for _, f := range pl.under(dir) {
			src, err := pl.read(f)
			if err != nil {
				return err
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
			if err != nil {
				return err
			}
			for _, spec := range specs(parsed, token.VAR) {
				for _, n := range spec.(*ast.ValueSpec).Names {
					declared[n.Name] = true
				}
			}
		}
		if err := pl.edit(file, func(src []byte) ([]byte, error) {
			var keep []string
			for l := range strings.SplitSeq(string(src), "\n") {
				if m := useSchemaLineRE.FindStringSubmatch(l); m != nil && !declared[m[1]] {
					continue
				}
				keep = append(keep, l)
			}
			return []byte(strings.Join(keep, "\n")), nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// renameUnit names the systemd unit after the app; release.sh starts <name>@<slot>.
func (pl *initPlan) renameUnit() error {
	if pl.opts.name == "app" {
		return nil
	}
	src, err := pl.read(unitFile)
	if err != nil {
		return err
	}
	if err := pl.remove(unitFile); err != nil {
		return err
	}
	return pl.create(unitFileFor(pl.opts.name), src)
}

var markerRE = regexp.MustCompile(`^\s*(?:<!-- (/?)part:([a-z0-9]+) -->|(?:#|--) (/?)part:([a-z0-9]+))\s*$`)

// marker parses a marker line: its name and whether it closes a block.
func marker(line string) (name string, closing, ok bool) {
	m := markerRE.FindStringSubmatch(line)
	if m == nil {
		return "", false, false
	}
	if m[2] != "" {
		return m[2], m[1] == "/", true
	}
	return m[4], m[3] == "/", true
}

// stripMarkers removes the blocks of markers keep refuses and the marker lines of those it keeps. A
// removed block between two blank lines takes one of them with it.
func stripMarkers(src []byte, keep func(name string) bool) ([]byte, error) {
	known := markerNames()
	var out []string
	var open []string
	dropping := 0
	dropBlank := false
	for i, line := range strings.Split(string(src), "\n") {
		name, closing, ok := marker(line)
		if !ok {
			if dropping > 0 {
				continue
			}
			if dropBlank && strings.TrimSpace(line) == "" {
				dropBlank = false
				continue
			}
			dropBlank = false
			out = append(out, line)
			continue
		}
		if !slices.Contains(known, name) {
			return nil, fmt.Errorf("line %d: unknown marker part:%s", i+1, name)
		}
		if !closing {
			open = append(open, name)
			if dropping > 0 || !keep(name) {
				dropping++
			}
			continue
		}
		if len(open) == 0 || open[len(open)-1] != name {
			return nil, fmt.Errorf("line %d: /part:%s does not close the open block", i+1, name)
		}
		open = open[:len(open)-1]
		if dropping > 0 {
			dropping--
			if dropping == 0 {
				dropBlank = len(out) == 0 || strings.TrimSpace(out[len(out)-1]) == ""
			}
		}
	}
	if len(open) > 0 {
		return nil, fmt.Errorf("part:%s is never closed", open[len(open)-1])
	}
	return []byte(strings.Join(out, "\n")), nil
}

// textFiles are the live non-Go files that are text.
func (pl *initPlan) textFiles() ([]string, error) {
	var out []string
	for _, f := range pl.files() {
		if strings.HasSuffix(f, ".go") || strings.HasSuffix(f, ".sum") {
			continue
		}
		src, err := pl.read(f)
		if err != nil {
			return nil, err
		}
		if !bytes.ContainsRune(src, 0) {
			out = append(out, f)
		}
	}
	return out, nil
}

func (pl *initPlan) stripAllMarkers() error {
	keep := func(name string) bool {
		switch {
		case name == keelMarker:
			return false
		case slices.Contains(dialectNames, name):
			return name == pl.opts.db
		}
		return !pl.isRemoved(name)
	}
	files, err := pl.textFiles()
	if err != nil {
		return err
	}
	for _, f := range files {
		src, err := pl.read(f)
		if err != nil {
			return err
		}
		if !hasMarker(src) {
			continue
		}
		out, err := stripMarkers(src, keep)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := pl.replace(f, out); err != nil {
			return err
		}
	}
	return nil
}

func hasMarker(src []byte) bool {
	for l := range strings.SplitSeq(string(src), "\n") {
		if _, _, ok := marker(l); ok {
			return true
		}
	}
	return false
}

// rewrite moves the app onto its module path, name and environment prefix.
func (pl *initPlan) rewrite() error {
	if pl.opts.module != pl.oldMod {
		for _, f := range pl.goFiles() {
			src, err := pl.read(f)
			if err != nil {
				return err
			}
			out, err := rewriteModuleGo(src, pl.oldMod, pl.opts.module)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			if !bytes.Equal(out, src) {
				if err := pl.replace(f, out); err != nil {
					return err
				}
			}
		}
		if err := pl.applyReplacements(moduleReplacements(pl.oldMod, pl.opts.module)); err != nil {
			return err
		}
	}
	if err := pl.applyReplacements(nameReplacements(pl.opts.name)); err != nil {
		return err
	}
	if pl.opts.envPrefix == "APP_" {
		return nil
	}
	for _, f := range pl.files() {
		// kit names no prefix of its own, and keel's Go code names APP_ only to recognise it
		if strings.HasPrefix(f, "internal/kit/") || strings.HasSuffix(f, ".sum") || (strings.HasPrefix(f, "cmd/keel/") && strings.HasSuffix(f, ".go")) {
			continue
		}
		src, err := pl.read(f)
		if err != nil {
			return err
		}
		if out, n := rewriteEnvPrefix(src, pl.opts.envPrefix); n > 0 {
			if err := pl.replace(f, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyReplacements applies each entry to the live files it covers; an entry that matches nothing is an
// error, so keel and its table cannot drift apart.
func (pl *initPlan) applyReplacements(table []replacement) error {
	var errs []error
	for _, r := range table {
		if r.dialect != "" && r.dialect != pl.opts.db {
			continue
		}
		matched := false
		for _, f := range pl.files() {
			key := f
			if f == unitFileFor(pl.opts.name) {
				key = unitFile
			}
			if !r.covers(key) {
				continue
			}
			src, err := pl.read(f)
			if err != nil {
				return err
			}
			if !r.re.Match(src) {
				continue
			}
			matched = true
			if err := pl.replace(f, r.re.ReplaceAll(src, []byte(r.to))); err != nil {
				return err
			}
		}
		if !matched {
			errs = append(errs, fmt.Errorf("replacement %q matched nothing in %s", r.re, strings.Join(r.paths, ", ")))
		}
	}
	return errors.Join(errs...)
}

// rewriteModuleGo moves import paths, string literals and comments from the module path from to to.
func rewriteModuleGo(src []byte, from, to string) ([]byte, error) {
	if !bytes.Contains(src, []byte(from)) {
		return src, nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	pathRE := regexp.MustCompile(regexp.QuoteMeta(from) + "(/|\"|`|$|\\s|\\.)")
	type edit struct {
		from, to int
		text     []byte
	}
	var edits []edit
	visit := func(pos, end token.Pos) {
		a, b := fset.Position(pos).Offset, fset.Position(end).Offset
		seg := src[a:b]
		if out := pathRE.ReplaceAll(seg, []byte(to+"$1")); !bytes.Equal(out, seg) {
			edits = append(edits, edit{a, b, out})
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			visit(lit.Pos(), lit.End())
		}
		return true
	})
	for _, cg := range f.Comments {
		visit(cg.Pos(), cg.End())
	}
	slices.SortFunc(edits, func(a, b edit) int { return b.from - a.from })
	for _, e := range edits {
		src = slices.Concat(src[:e.from], e.text, src[e.to:])
	}
	return format.Source(src)
}

// check is the plan's own test: no part build tags, no markers, no old module path and no keel name or
// APP_ setting the rewrites should have moved are left.
func (pl *initPlan) check() error {
	var errs []error
	for _, f := range pl.goFiles() {
		src, err := pl.read(f)
		if err != nil {
			return err
		}
		if _, _, ok, err := buildLine(src); ok || err != nil {
			errs = append(errs, fmt.Errorf("%s still has a part build constraint", f))
		}
		if pl.opts.module != pl.oldMod && moduleMention(src, pl.oldMod) {
			errs = append(errs, fmt.Errorf("%s still names %s", f, pl.oldMod))
		}
		errs = append(errs, pl.staleNames(f, src, nil)...)
	}
	files, err := pl.textFiles()
	if err != nil {
		return err
	}
	names := pl.nameTable()
	for _, f := range files {
		src, err := pl.read(f)
		if err != nil {
			return err
		}
		if hasMarker(src) {
			errs = append(errs, fmt.Errorf("%s still has part markers", f))
		}
		if pl.opts.module != pl.oldMod && moduleMention(src, pl.oldMod) {
			errs = append(errs, fmt.Errorf("%s still names %s", f, pl.oldMod))
		}
		errs = append(errs, pl.staleNames(f, src, names)...)
	}
	return errors.Join(errs...)
}

// nameTable is the name replacements for the app's engine.
func (pl *initPlan) nameTable() []replacement {
	var out []replacement
	for _, r := range nameReplacements(pl.opts.name) {
		if r.dialect == "" || r.dialect == pl.opts.db {
			out = append(out, r)
		}
	}
	return out
}

// staleAllowed are the text files the stale name check skips: kit code never changes, the docs use app
// as the placeholder deploy name, and .gitignore's /keel is the keel tool's binary. Go code is checked
// for the prefix only: it names keel's deploy forms in the few literals the table must match.
func staleAllowed(f string) bool {
	return strings.HasPrefix(f, "internal/kit/") || strings.HasPrefix(f, "docs/") || f == ".gitignore"
}

// staleNames finds what the name and prefix rewrites missed in f: text a name replacement would still
// change (keel added a reference in a file the table does not cover), and APP_ settings under another
// prefix. Outside internal/kit and keel's own test fixtures only APP_TEST_* and the bare prefix (keel's
// flag default) may stay.
func (pl *initPlan) staleNames(f string, src []byte, names []replacement) []error {
	var errs []error
	if !staleAllowed(f) {
		for _, r := range names {
			if prefix, _ := r.re.LiteralPrefix(); !bytes.Contains(src, []byte(prefix)) {
				continue
			}
			for _, m := range r.re.FindAll(src, -1) {
				if !bytes.Equal(r.re.ReplaceAll(m, []byte(r.to)), m) {
					errs = append(errs, fmt.Errorf("%s still has keel's %q: add the file to that replacement in parts.go", f, m))
					break
				}
			}
		}
	}
	if pl.opts.envPrefix == "APP_" || strings.HasPrefix(f, "internal/kit/") || (strings.HasPrefix(f, "cmd/keel/") && strings.HasSuffix(f, "_test.go")) {
		return errs
	}
	for _, tok := range envTokenRE.FindAll(src, -1) {
		if s := string(tok); s != "APP_" && !strings.HasPrefix(s, "APP_TEST_") {
			errs = append(errs, fmt.Errorf("%s still names %s under --env-prefix %s", f, s, pl.opts.envPrefix))
			break
		}
	}
	return errs
}

// moduleMention reports whether src names the module path itself, plain or regex-escaped, and not a
// longer path that starts with it.
func moduleMention(src []byte, mod string) bool {
	for _, form := range []string{mod, regexp.QuoteMeta(mod)} {
		re := regexp.MustCompile(regexp.QuoteMeta(form) + `($|[^A-Za-z0-9_-])`)
		if re.Match(src) {
			return true
		}
	}
	return false
}

// report prints what the plan does.
func (pl *initPlan) report(w io.Writer) {
	if len(pl.removed) > 0 {
		_, _ = fmt.Fprintf(w, "parts removed: %s\n", strings.Join(pl.removedNames(), ", "))
	}
	for _, rel := range pl.requested {
		_, _ = fmt.Fprintf(w, "remove %s\n", rel)
	}
	var others []string
	for _, f := range pl.order {
		if !slices.ContainsFunc(pl.requested, func(r string) bool { return f == r || strings.HasPrefix(f, r+"/") }) {
			others = append(others, f)
		}
	}
	for _, f := range others {
		_, _ = fmt.Fprintf(w, "remove %s\n", f)
	}
	pl.tree.report(w)
}
