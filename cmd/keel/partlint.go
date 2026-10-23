package main

import (
	"context"
	"errors"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

// The rules that keep each optional part removable (docs/architecture.md section 12):
//  1. A constraint is //go:build !no<p> (an on file; a test may need several: !no<a> && !no<b>) or
//     //go:build no<p> (its off twin); deploytest is the only other tag.
//  2. In internal/app and cmd/app, a file without a part constraint and an off twin import no optional kit
//     package; an on file imports only its own parts' packages and those of the parts they require.
//  3. A kit package imports only core kit packages, its own part's, and those of the parts its part requires.
func checkPartRules(_ context.Context, out io.Writer) error {
	found, err := partRuleBreaks(os.DirFS("."))
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return fmt.Errorf("part rules:\n  %s", strings.Join(found, "\n  "))
	}
	_, err = fmt.Fprintln(out, "part files keep to their constraints and imports")
	return err
}

// partFile is what a Go file's constraint says about the parts.
type partFile struct {
	parts []string // the parts an on file needs
	off   bool     // an off twin, built only without its part
}

func partRuleBreaks(fsys fs.FS) ([]string, error) {
	mod, err := modulePathOf(fsys)
	if err != nil {
		return nil, err
	}
	var found []string
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); p != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "tools") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		pf, problem := readConstraint(p, src)
		if problem != "" {
			found = append(found, p+": "+problem)
			return nil
		}
		if len(pf.parts) == 0 {
			pf.parts = partsOwning(p)
		}
		for _, imp := range importsOf(p, src) {
			if why := importBreak(p, mod, imp, pf); why != "" {
				found = append(found, fmt.Sprintf("%s: imports %s, %s", p, imp, why))
			}
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return found, err
}

func modulePathOf(fsys fs.FS) (string, error) {
	raw, err := fs.ReadFile(fsys, "go.mod")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", errors.New("go.mod names no module")
}

// readConstraint checks rule 1 and reads which parts the file belongs to.
func readConstraint(p string, src []byte) (partFile, string) {
	for line := range strings.SplitSeq(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return partFile{}, err.Error()
		}
		if tag, ok := expr.(*constraint.TagExpr); ok {
			if tag.Tag == "deploytest" {
				return partFile{}, ""
			}
			if name, ok := partOfTag(tag.Tag); ok {
				return partFile{parts: []string{name}, off: true}, ""
			}
		}
		var names []string
		if !onParts(expr, &names) {
			return partFile{}, "constraint " + strconv.Quote(line) + " is not !no<part>, no<part> or deploytest"
		}
		if len(names) > 1 && !strings.HasSuffix(p, "_test.go") {
			return partFile{}, "only a test may need several parts"
		}
		return partFile{parts: names}, ""
	}
	return partFile{}, ""
}

// onParts reads !no<a> && !no<b> ... into names.
func onParts(e constraint.Expr, names *[]string) bool {
	switch x := e.(type) {
	case *constraint.AndExpr:
		return onParts(x.X, names) && onParts(x.Y, names)
	case *constraint.NotExpr:
		tag, ok := x.X.(*constraint.TagExpr)
		if !ok {
			return false
		}
		name, ok := partOfTag(tag.Tag)
		*names = append(*names, name)
		return ok
	}
	return false
}

func partOfTag(tag string) (string, bool) {
	name, ok := strings.CutPrefix(tag, "no")
	if !ok {
		return "", false
	}
	_, known := partNamed(name)
	return name, known
}

func importsOf(p string, src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		if v, err := strconv.Unquote(imp.Path.Value); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// importBreak says why a file at p may not import imp (rules 2 and 3), or "" when it may.
func importBreak(p, mod, imp string, pf partFile) string {
	rel, ok := strings.CutPrefix(imp, mod+"/")
	if !ok {
		return ""
	}
	owner, optional := kitOwner(rel)
	if !optional {
		return ""
	}
	switch {
	case strings.HasPrefix(p, "internal/kit/"):
		self, selfOptional := kitOwner(path.Dir(p))
		if selfOptional && allowed(self, owner) {
			return ""
		}
		return "which belongs to part " + owner
	case strings.HasPrefix(p, "internal/app/"), strings.HasPrefix(p, "cmd/app/"):
		if pf.off || len(pf.parts) == 0 {
			return "an optional part's package, which only that part's on file may import"
		}
		for _, name := range pf.parts {
			if allowed(name, owner) {
				return ""
			}
		}
		return "which belongs to part " + owner + ", one this file neither is nor requires"
	}
	return ""
}

// kitOwner is the part owning the kit directory rel, if an optional one does.
func kitOwner(rel string) (string, bool) {
	best, owner := "", ""
	for _, p := range parts {
		for _, dir := range p.kit {
			if (rel == dir || strings.HasPrefix(rel, dir+"/")) && len(dir) > len(best) {
				best, owner = dir, p.name
			}
		}
	}
	return owner, owner != ""
}

// allowed reports whether part name may use part other's packages: its own, or a part it requires.
func allowed(name, other string) bool {
	return name == other || slices.Contains(requiredParts(name), other)
}

// requiredParts are the parts name requires, directly or through another.
func requiredParts(name string) []string {
	var out []string
	queue := []string{name}
	for len(queue) > 0 {
		p, ok := partNamed(queue[0])
		queue = queue[1:]
		if !ok {
			continue
		}
		for _, r := range p.requires {
			if !slices.Contains(out, r) {
				out = append(out, r)
				queue = append(queue, r)
			}
		}
	}
	return out
}

// partTagSets are the tag sets keel check vets internal/app and cmd/app with: each part tag found in the
// tree alone, joined by the tags of the parts that require it (an app cannot keep those without it), and
// then every tag together. An app, which has no tags, gets none.
func partTagSets(fsys fs.FS) ([][]string, error) {
	var found []string
	for _, dir := range []string{"internal/app", "cmd/app"} {
		entries, err := fs.ReadDir(fsys, dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			src, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
			if pf, _ := readConstraint(e.Name(), src); pf.off && !slices.Contains(found, pf.parts[0]) {
				found = append(found, pf.parts[0])
			}
		}
	}
	slices.Sort(found)
	var sets [][]string
	for _, name := range found {
		set := []string{"no" + name}
		for _, other := range found {
			if slices.Contains(requiredParts(other), name) {
				set = append(set, "no"+other)
			}
		}
		sets = append(sets, set)
	}
	if len(found) > 1 {
		all := make([]string, len(found))
		for i, name := range found {
			all[i] = "no" + name
		}
		sets = append(sets, all)
	}
	return sets, nil
}

// partVetSteps vet each set partTagSets finds, so every off twin and every hook compiles.
func partVetSteps() []step {
	sets, err := partTagSets(os.DirFS("."))
	if err != nil {
		return []step{{name: "vet without parts", run: func(context.Context, io.Writer) error { return err }}}
	}
	steps := make([]step, len(sets))
	for i, set := range sets {
		steps[i] = step{name: "vet -tags " + strings.Join(set, ","), args: []string{"vet", "-tags", strings.Join(set, ","), "./internal/app/...", "./cmd/app/..."}}
	}
	return steps
}
