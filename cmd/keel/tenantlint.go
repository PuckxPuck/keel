package main

import (
	"context"
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Only kit/db and kit/tenancy may write the tenant setting (D30): anything else that mentions it could
// move a transaction into another tenant. Code may read it the one way the schema rules use, which
// migrate's policy check compares against. Each
// file is read whole as one stream: a Go file's string literals (raw ones included, with those joined
// by + read as one), a SQL file's text without comments. Concatenation, quotes, escapes, line breaks
// and the spaces around a dot are taken out, so SET "app"."tenant_id", SET app . tenant_id, a dotted name
// split over lines and 'app.' || 'tenant_id' all name the setting.
var (
	settingWrites = regexp.MustCompile(`(?i)set_config|pg_settings|\bset\s+local\b`)
	settingName   = regexp.MustCompile(`(?i)\bapp\.tenant_id\b`)
	settingRead   = regexp.MustCompile(`(?i)current_setting\('app\.tenant_id',\s*true\)`)
	concatenation = regexp.MustCompile(`["'\x60]\s*(\+|\|\|)\s*["'\x60]`)
	quoteChars    = regexp.MustCompile(`["\x60\\]`)
	dottedSpace   = regexp.MustCompile(`\s*\.\s*`)
	spaces        = regexp.MustCompile(`\s+`)
	sqlComment    = regexp.MustCompile(`(?s)--[^\n]*|/\*.*?\*/`)
	settingOwners = []string{"internal/kit/db/", "internal/kit/tenancy/"}
)

// tenantSettingSteps also check the part rules and vet the builds without each optional part, which
// keel init produces.
func tenantSettingSteps() []step {
	return append([]step{
		{name: "tenant setting (D30)", run: checkTenantSetting},
		{name: "part rules", run: checkPartRules},
	}, partVetSteps()...)
}

// stream is text with the source line of each byte, so a match found after normalising still names the
// line it came from.
type stream struct {
	text  []byte
	lines []int
}

func (s *stream) add(text string, line int) {
	s.text = append(s.text, text...)
	for i := range len(text) {
		s.lines = append(s.lines, line)
		if text[i] == '\n' {
			line++
		}
	}
}

// replace substitutes every match of re with repl, which takes the line of the match's start.
func (s stream) replace(re *regexp.Regexp, repl string) stream {
	out := stream{text: make([]byte, 0, len(s.text)), lines: make([]int, 0, len(s.lines))}
	last := 0
	for _, m := range re.FindAllIndex(s.text, -1) {
		out.text = append(append(out.text, s.text[last:m[0]]...), repl...)
		out.lines = append(out.lines, s.lines[last:m[0]]...)
		for range len(repl) {
			out.lines = append(out.lines, s.lines[m[0]])
		}
		last = m[1]
	}
	out.text = append(out.text, s.text[last:]...)
	out.lines = append(out.lines, s.lines[last:]...)
	return out
}

// settingLines are the lines where the stream, read as the setting rules read it, writes or names the
// setting.
func settingLines(s stream, sql bool) []int {
	if sql {
		s = s.replace(sqlComment, " ")
	}
	s = s.replace(spaces, " ").replace(settingRead, "")
	s = s.replace(concatenation, "").replace(quoteChars, "").replace(dottedSpace, ".")
	var out []int
	for _, re := range []*regexp.Regexp{settingWrites, settingName} {
		for _, m := range re.FindAllIndex(s.text, -1) {
			if line := s.lines[m[0]]; !slices.Contains(out, line) {
				out = append(out, line)
			}
		}
	}
	slices.Sort(out)
	return out
}

// goStrings is a Go file's string literals as one stream: literals joined by + run on, others are
// separated by a line break.
func goStrings(src []byte) stream {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var sc scanner.Scanner
	sc.Init(file, src, nil, 0)
	var s stream
	joined := false
	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF {
			return s
		}
		if tok != token.STRING {
			joined = tok == token.ADD && len(s.text) > 0
			continue
		}
		value, err := strconv.Unquote(lit)
		if err != nil {
			value = lit
		}
		line := fset.Position(pos).Line
		if !joined && len(s.text) > 0 {
			s.add("\n", line)
		}
		s.add(value, line)
		joined = false
	}
}

func checkTenantSetting(_ context.Context, out io.Writer) error {
	found, err := tenantSettingMentions(os.DirFS("."))
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return fmt.Errorf("only internal/kit/db and internal/kit/tenancy may write app.tenant_id:\n  %s", strings.Join(found, "\n  "))
	}
	_, err = fmt.Fprintln(out, "the tenant setting is written only by kit/db and kit/tenancy")
	return err
}

// tenantSettingMentions lists file:line for every place in a Go or SQL file outside the owners that
// writes the setting or names it other than in a migration's read.
func tenantSettingMentions(fsys fs.FS) ([]string, error) {
	var found []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != "." && (strings.HasPrefix(name, ".") || name == "tools" || name == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if (ext != ".go" && ext != ".sql") || owned(path) || path == "cmd/keel/tenantlint.go" || path == "cmd/keel/tenantlint_test.go" {
			return nil
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		s := goStrings(raw)
		if ext == ".sql" {
			s = stream{}
			s.add(string(raw), 1)
		}
		for _, line := range settingLines(s, ext == ".sql") {
			found = append(found, fmt.Sprintf("%s:%d", path, line))
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return found, err
}

func owned(path string) bool {
	for _, p := range settingOwners {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
