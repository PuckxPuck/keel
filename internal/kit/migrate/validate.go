package migrate

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

// ContractMarker is a comment line before -- +goose Up that allows a migration to remove or lock what the
// running release uses (D32).
const ContractMarker = "-- keel:contract"

// GlobalMarker, followed by a reason, is a comment line before -- +goose Up for a Postgres migration whose
// tables every tenant shares (no row-level security, docs/tenancy.md section 4).
const GlobalMarker = "-- keel:global"

// ProceduralMarker, followed by a reason, is a comment line before -- +goose Up for a Postgres migration
// that, under tenancy, runs a DO block or creates a function the validator cannot read; the allowlist must
// name it with the same reason.
const ProceduralMarker = "-- keel:procedural"

var nameRE = regexp.MustCompile(`^(\d{14})_([a-z][a-z0-9]*)_([a-z0-9][a-z0-9_]*)\.sql$`)

type fileName struct {
	version int64
	module  string
}

func parseName(name string) (fileName, error) {
	m := nameRE.FindStringSubmatch(name)
	if m == nil {
		return fileName{}, fmt.Errorf("%s: name must be <YYYYMMDDHHMMSS>_<module>_<what>.sql in lower case", name)
	}
	if _, err := time.Parse("20060102150405", m[1]); err != nil {
		return fileName{}, fmt.Errorf("%s: %s is not a valid UTC timestamp", name, m[1])
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return fileName{}, fmt.Errorf("%s: %w", name, err)
	}
	return fileName{version: v, module: m[2]}, nil
}

// Policy allows one row-level security policy other than the tenant policy, by table and name; Reason is
// what a reviewer reads.
type Policy struct{ Table, Name, Reason string }

// Procedural allows, under tenancy, the DO blocks of one migration File (Function empty) or one function
// it creates (Function, schema-qualified, public when the file leaves the schema out) that runs dynamic
// SQL or changes tables, policies or row-level security. The file must carry ProceduralMarker with the
// same Reason.
type Procedural struct{ File, Function, Reason string }

// Allowed is what Validate lets through that its rules would otherwise refuse, each with a reason.
type Allowed struct {
	Policies   []Policy
	Procedural []Procedural
}

// Validate checks every migration in fsys (one dialect's directory) and reports every problem at once.
// On Postgres every policy a migration creates or alters must be the tenant policy or allowed; under
// tenancy procedural SQL must be allowed too.
func Validate(fsys fs.FS, dialect db.Dialect, allowed Allowed) error {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	var errs []error
	for _, p := range allowed.Policies {
		if p.Table == "" || p.Name == "" || p.Reason == "" {
			errs = append(errs, fmt.Errorf("the allowed policy %q on %q needs a table, a name and a reason", p.Name, p.Table))
		}
	}
	for _, p := range allowed.Procedural {
		if p.File == "" || p.Reason == "" {
			errs = append(errs, fmt.Errorf("the allowed procedural SQL %q in %q needs a file and a reason", p.Function, p.File))
		}
	}
	seen := map[int64]string{}
	files := map[string]parsed{}
	for _, name := range names {
		f, err := parseName(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, ok := seen[f.version]; ok {
			errs = append(errs, fmt.Errorf("%s: version already used by %s", name, prev))
		}
		seen[f.version] = name
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		p, problems := checkFile(string(raw), dialect)
		for _, problem := range problems {
			errs = append(errs, fmt.Errorf("%s: %s", name, problem))
		}
		files[name] = p
	}
	if dialect == db.Postgres {
		errs = append(errs, tenantDDL(names, files, allowed.Policies)...)
	}
	if dialect == db.Postgres && hasTenancy(names) {
		for _, name := range names {
			errs = append(errs, procedural(name, files[name], allowed.Procedural)...)
		}
		for _, f := range tableFates(names, files) {
			if !f.global && !f.tenant {
				errs = append(errs, fmt.Errorf("%s: table %s has no tenant_id: give it one under row-level security, or mark the file %q followed by why every tenant shares it",
					f.createdIn, f.name, GlobalMarker))
			}
		}
	}
	return errors.Join(errs...)
}

// GlobalTables names each table that a Postgres migration in fsys marks global, with the marker's reason,
// for the check that every one is also on the tenancy allowlist.
func GlobalTables(fsys fs.FS) (map[string]string, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	files := map[string]parsed{}
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if files[name], err = parse(string(raw), db.Postgres); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	out := map[string]string{}
	for _, f := range tableFates(names, files) {
		if f.global {
			out[f.name] = f.reason
		}
	}
	return out, nil
}

// kitModule names the kit's migrations. Its tables run with and without tenancy: the tenancy part's own
// migrations convert them, so converting a kit table does not tie the kit to tenancy.
const kitModule = "kit"

// TenantModules names the modules (the <module> in <timestamp>_<module>_<what>.sql) with a migration that
// gives a table tenant_id, and the module that created each such table: they need the tenancy part, so
// a database without it leaves them out (D36). A table stays with the module that created it, so a later
// conversion in another module's file takes the creator out too, unless the creator is the kit.
func TenantModules(fsys fs.FS, dialect db.Dialect) ([]string, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	var out []string
	add := func(module string) {
		if !slices.Contains(out, module) {
			out = append(out, module)
		}
	}
	creators := map[string]string{}
	for _, name := range names {
		f, err := parseName(name)
		if err != nil {
			continue
		}
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		p, err := parse(string(raw), dialect)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, stmt := range p.up {
			if m := createTableRE.FindStringSubmatch(stmt.text); m != nil && creators[tableName(m[1])] == "" {
				creators[tableName(m[1])] = f.module
			}
			table, ok := givesTenantID(stmt)
			if !ok {
				continue
			}
			add(f.module)
			if c := creators[table]; c != "" && c != kitModule {
				add(c)
			}
		}
	}
	return out, nil
}

// givesTenantID names the table stmt creates with, or alters to add, a tenant_id column.
func givesTenantID(stmt statement) (string, bool) {
	if m := createTableRE.FindStringSubmatch(stmt.text); m != nil {
		return tableName(m[1]), tenantColumnRE.MatchString(stmt.text)
	}
	m := alterTableRE.FindStringSubmatch(stmt.text)
	if m == nil || !addTenantRE.MatchString(m[2]) {
		return "", false
	}
	return tableName(m[1]), true
}

// hasTenancy reports whether the migrations include the tenancy part (<ts>_tenancy_<what>.sql).
func hasTenancy(names []string) bool {
	for _, name := range names {
		if f, err := parseName(name); err == nil && f.module == "tenancy" {
			return true
		}
	}
	return false
}

type tableFate struct {
	name, createdIn, reason string
	global, tenant          bool
}

var dropTableRE = regexp.MustCompile(`^drop table (?:if exists )?([^\s;]+)`)

// tableFates follows each table through the migrations in order: global when a file that creates it or
// gives it tenant_id is marked global, a tenant table when an unmarked file gives it tenant_id.
func tableFates(names []string, files map[string]parsed) []*tableFate {
	tables := map[string]*tableFate{}
	var order []string
	for _, name := range names {
		p := files[name]
		for _, stmt := range p.up {
			if m := dropTableRE.FindStringSubmatch(stmt.text); m != nil {
				delete(tables, tableName(m[1]))
				continue
			}
			table, withTenant := "", false
			if m := createTableRE.FindStringSubmatch(stmt.text); m != nil {
				table, withTenant = tableName(m[1]), tenantColumnRE.MatchString(stmt.text)
				if tables[table] == nil {
					tables[table] = &tableFate{name: table, createdIn: name}
					order = append(order, table)
				}
			} else if m := alterTableRE.FindStringSubmatch(stmt.text); m != nil && addTenantRE.MatchString(m[2]) {
				table, withTenant = tableName(m[1]), true
			}
			f := tables[table]
			if f == nil {
				continue
			}
			if p.global {
				f.global, f.reason = true, p.globalReason
			} else if withTenant {
				f.tenant = true
			}
		}
	}
	out := make([]*tableFate, 0, len(order))
	for _, name := range slices.Compact(slices.Sorted(slices.Values(order))) {
		if f := tables[name]; f != nil {
			out = append(out, f)
		}
	}
	return out
}

type parsed struct {
	up, down []statement
	noTx     bool
	contract bool
	global   bool
	// globalReason is what follows the global marker.
	globalReason string
	procedural   bool
	// proceduralReason is what follows the procedural marker.
	proceduralReason string
}

func checkFile(content string, dialect db.Dialect) (parsed, []string) {
	p, err := parse(content, dialect)
	if err != nil {
		return parsed{}, []string{"goose cannot run it: " + err.Error()}
	}
	var problems []string
	if p.global && p.globalReason == "" {
		problems = append(problems, fmt.Sprintf("%s needs a reason on the same line: why every tenant shares the table", GlobalMarker))
	}
	if p.procedural && p.proceduralReason == "" {
		problems = append(problems, fmt.Sprintf("%s needs a reason on the same line: why the migration needs procedural SQL", ProceduralMarker))
	}
	if dialect == db.MySQL {
		if len(p.up) != 1 {
			problems = append(problems, fmt.Sprintf("MySQL migrations hold exactly one statement in Up, found %d", len(p.up)))
		}
		if len(p.down) != 1 {
			problems = append(problems, fmt.Sprintf("MySQL migrations hold exactly one statement in Down, found %d", len(p.down)))
		}
	}
	// A failure part way through a file outside a transaction leaves what ran in place; one statement
	// leaves at most one thing to clean up (an invalid index) before the rerun.
	if p.noTx && len(p.up) != 1 {
		problems = append(problems, fmt.Sprintf("a NO TRANSACTION migration holds exactly one statement in Up, found %d", len(p.up)))
	}
	created := createdTables(p.up)
	var reasons []string
	for _, stmt := range p.up {
		if dialect == db.Postgres && concurrent(stmt.text) && !p.noTx {
			problems = append(problems, "create or drop index concurrently needs -- +goose NO TRANSACTION")
		}
		reasons = append(reasons, contractReasons(stmt, dialect, created)...)
	}
	if dialect == db.Postgres && !p.global {
		problems = append(problems, unguardedTenantTables(p.up)...)
	}
	if len(reasons) > 0 && !p.contract {
		slices.Sort(reasons)
		problems = append(problems, fmt.Sprintf("contract change (%s): ship it a release later with %q before -- +goose Up",
			strings.Join(slices.Compact(reasons), ", "), ContractMarker))
	}
	return p, problems
}

// parse splits a migration first the way goose v3 does (its parser is internal to goose, so its line rules
// are restated in gooseSplit), then each goose statement into the SQL statements the server runs.
func parse(content string, dialect db.Dialect) (parsed, error) {
	g, err := gooseSplit(content)
	if err != nil {
		return parsed{}, err
	}
	p := parsed{
		noTx: g.noTx, contract: g.contract, global: g.global, globalReason: g.globalReason,
		procedural: g.procedural, proceduralReason: g.proceduralReason,
	}
	for _, s := range g.up {
		p.up = append(p.up, splitSQL(s, dialect)...)
	}
	for _, s := range g.down {
		p.down = append(p.down, splitSQL(s, dialect)...)
	}
	return p, nil
}

type gooseFile struct {
	up, down []string
	noTx     bool
	contract bool
	global   bool
	// globalReason is what follows the global marker.
	globalReason     string
	procedural       bool
	proceduralReason string
}

type gooseState int

const (
	gooseStart gooseState = iota
	gooseUp
	gooseUpBlock
	gooseDown
	gooseDownBlock
)

var errMissingSemicolon = errors.New("unfinished SQL statement (missing semicolon?)")

// gooseSplit follows goose v3.29's sqlparser.ParseSQLMigration: a statement ends at a line whose last word
// before any -- ends in a semicolon, or at StatementEnd; comment lines between statements are dropped.
func gooseSplit(content string) (gooseFile, error) {
	var f gooseFile
	state := gooseStart
	var buf strings.Builder
	store := func(to *[]string) {
		*to = append(*to, strings.TrimSpace(buf.String()))
		buf.Reset()
	}
	for line := range strings.Lines(content) {
		line = strings.TrimRight(line, "\r\n")
		trimmed := strings.TrimSpace(line)
		if state == gooseStart && trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "--") && strings.Contains(line, "+goose") {
			a, err := annotation(line)
			if err != nil {
				return gooseFile{}, err
			}
			switch a {
			case "up":
				if state != gooseStart {
					return gooseFile{}, errors.New("duplicate -- +goose Up")
				}
				state = gooseUp
			case "down":
				if state != gooseUp {
					return gooseFile{}, errors.New("-- +goose Down must follow -- +goose Up, outside a statement block")
				}
				if strings.TrimSpace(buf.String()) != "" {
					return gooseFile{}, errMissingSemicolon
				}
				buf.Reset()
				state = gooseDown
			case "statementbegin":
				switch state {
				case gooseUp:
					state = gooseUpBlock
				case gooseDown:
					state = gooseDownBlock
				case gooseStart, gooseUpBlock, gooseDownBlock:
					return gooseFile{}, errors.New("-- +goose StatementBegin must follow -- +goose Up or Down")
				}
			case "statementend":
				switch state {
				case gooseUpBlock:
					store(&f.up)
					state = gooseUp
				case gooseDownBlock:
					store(&f.down)
					state = gooseDown
				case gooseStart, gooseUp, gooseDown:
					return gooseFile{}, errors.New("-- +goose StatementEnd must follow -- +goose StatementBegin")
				}
			case "no transaction":
				f.noTx = true
			}
			continue
		}
		if buf.Len() == 0 && (strings.HasPrefix(trimmed, "--") || line == "") {
			if state == gooseStart && trimmed == ContractMarker {
				f.contract = true
			}
			if rest, ok := strings.CutPrefix(trimmed, GlobalMarker); state == gooseStart && ok && (rest == "" || rest[0] == ' ') {
				f.global, f.globalReason = true, strings.TrimSpace(rest)
			}
			if rest, ok := strings.CutPrefix(trimmed, ProceduralMarker); state == gooseStart && ok && (rest == "" || rest[0] == ' ') {
				f.procedural, f.proceduralReason = true, strings.TrimSpace(rest)
			}
			continue
		}
		if state == gooseStart {
			return gooseFile{}, errors.New("SQL before -- +goose Up")
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
		if !endsWithSemicolon(line) {
			continue
		}
		switch state {
		case gooseUp:
			store(&f.up)
		case gooseDown:
			store(&f.down)
		case gooseStart, gooseUpBlock, gooseDownBlock:
		}
	}
	switch {
	case state == gooseStart:
		return gooseFile{}, errors.New("needs both -- +goose Up and -- +goose Down")
	case state == gooseUpBlock || state == gooseDownBlock:
		return gooseFile{}, errors.New("missing -- +goose StatementEnd")
	case strings.TrimSpace(buf.String()) != "":
		return gooseFile{}, errMissingSemicolon
	case state == gooseUp:
		return gooseFile{}, errors.New("needs both -- +goose Up and -- +goose Down")
	}
	return f, nil
}

var annotations = []string{"up", "down", "statementbegin", "statementend", "no transaction", "envsub on", "envsub off"}

func annotation(line string) (string, error) {
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return "", errors.New("a goose annotation must start the line")
	}
	cmd := strings.Replace(strings.ReplaceAll(line, "--", ""), "+goose", "", 1)
	if strings.Contains(cmd, "+goose") {
		return "", errors.New("more than one goose annotation on a line")
	}
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	if !slices.Contains(annotations, cmd) {
		return "", fmt.Errorf("unknown goose annotation %q", cmd)
	}
	return cmd, nil
}

func endsWithSemicolon(line string) bool {
	prev := ""
	for _, word := range strings.Fields(line) {
		if strings.HasPrefix(word, "--") {
			break
		}
		prev = word
	}
	return strings.HasSuffix(prev, ";")
}

// statement is one SQL statement, lower-cased with comments removed and dollar-quoted bodies replaced by
// $$. text has single-quoted literals emptied; full keeps them, for comparing policy expressions. bodies
// are the dollar-quoted texts, normalised the same way.
type statement struct {
	text, full string
	bodies     []string
}

// splitSQL splits on semicolons outside literals, quoted names, comments and (Postgres) dollar quotes.
func splitSQL(src string, dialect db.Dialect) []statement {
	var out []statement
	var text, full strings.Builder
	var bodies []string
	write := func(s string) {
		text.WriteString(s)
		full.WriteString(s)
	}
	flush := func() {
		if t := normalize(text.String()); t != "" {
			out = append(out, statement{text: t, full: normalize(full.String()), bodies: bodies})
		}
		text.Reset()
		full.Reset()
		bodies = nil
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case strings.HasPrefix(src[i:], "--") || (c == '#' && dialect == db.MySQL):
			i = skipLine(src, i)
			write(" ")
		case strings.HasPrefix(src[i:], "/*"):
			i = skipBlockComment(src, i, dialect == db.Postgres)
			write(" ")
		case c == '\'':
			end := skipQuoted(src, i, '\'', backslashEscapes(src, i, dialect))
			text.WriteString("''")
			full.WriteString(src[i:end])
			i = end
		case c == '"' || c == '`':
			end := skipQuoted(src, i, c, false)
			write(src[i:end])
			i = end
		case c == '$' && dialect == db.Postgres && dollarTag(src[i:]) != "":
			tag := dollarTag(src[i:])
			rest := src[i+len(tag):]
			n := strings.Index(rest, tag)
			if n < 0 {
				n = len(rest)
			}
			write(" $$ ")
			bodies = append(bodies, normalize(rest[:n]))
			i += len(tag) + min(len(rest), n+len(tag))
		case c == ';':
			flush()
			i++
		default:
			write(string(c))
			i++
		}
	}
	flush()
	return out
}

func skipLine(src string, i int) int {
	if n := strings.IndexByte(src[i:], '\n'); n >= 0 {
		return i + n + 1
	}
	return len(src)
}

// skipBlockComment returns the index after the comment at i; Postgres block comments nest.
func skipBlockComment(src string, i int, nest bool) int {
	depth := 0
	for i < len(src) {
		switch {
		case strings.HasPrefix(src[i:], "/*"):
			if depth == 0 || nest {
				depth++
			}
			i += 2
		case strings.HasPrefix(src[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return i
}

// skipQuoted returns the index after the quoted text at i; a doubled quote is part of the text.
func skipQuoted(src string, i int, quote byte, backslash bool) int {
	for i++; i < len(src); i++ {
		switch {
		case backslash && src[i] == '\\':
			i++
		case src[i] == quote && i+1 < len(src) && src[i+1] == quote:
			i++
		case src[i] == quote:
			return i + 1
		}
	}
	return i
}

// backslashEscapes is true for MySQL strings and Postgres escape strings (E-prefixed).
func backslashEscapes(src string, i int, dialect db.Dialect) bool {
	if dialect == db.MySQL {
		return true
	}
	return i > 0 && (src[i-1] == 'e' || src[i-1] == 'E') && (i == 1 || !identChar(src[i-2]))
}

var dollarTagRE = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$`)

func dollarTag(s string) string { return dollarTagRE.FindString(s) }

func identChar(c byte) bool {
	return c == '_' || c == '$' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
}

var (
	spaceRE        = regexp.MustCompile(`\s+`)
	createTableRE  = regexp.MustCompile(`^create (?:unlogged )?table (?:if not exists )?([^\s(]+)`)
	createIndexRE  = regexp.MustCompile(`^create (?:unique )?index (concurrently )?(?:if not exists )?(?:[^\s]+ )?on (?:only )?([^\s(]+)`)
	alterTableRE   = regexp.MustCompile(`^alter table (?:if exists )?(?:only )?([^\s]+) (.*)$`)
	pgTypeChangeRE = regexp.MustCompile(`\balter (?:column )?\S+ (?:set data )?type\b`)
	dropDefaultRE  = regexp.MustCompile(`\balter (?:column )?\S+ drop default\b`)
	defaultRE      = regexp.MustCompile(`\bdefault\b`)
)

func normalize(stmt string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(strings.ToLower(stmt), " "))
}

func tableName(s string) string {
	s = strings.NewReplacer(`"`, "", "`", "").Replace(s)
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return s
}

var (
	tenantColumnRE = regexp.MustCompile(`\btenant_id\b`)
	addTenantRE    = regexp.MustCompile(`\badd (?:column )?(?:if not exists )?tenant_id\b`)
)

// unguardedTenantTables names each table this file gives a tenant_id column without, in the same file,
// enabling and forcing row-level security and creating the tenant policy (docs/tenancy.md section 4).
func unguardedTenantTables(stmts []statement) []string {
	type guard struct{ enabled, forced, policy bool }
	tables := map[string]*guard{}
	var order []string
	for _, stmt := range stmts {
		if m := createTableRE.FindStringSubmatch(stmt.text); m != nil && tenantColumnRE.MatchString(stmt.text) {
			order = append(order, tableName(m[1]))
			tables[tableName(m[1])] = &guard{}
		}
		if m := alterTableRE.FindStringSubmatch(stmt.text); m != nil && addTenantRE.MatchString(m[2]) {
			if _, seen := tables[tableName(m[1])]; !seen {
				order = append(order, tableName(m[1]))
				tables[tableName(m[1])] = &guard{}
			}
		}
	}
	for _, stmt := range stmts {
		if m := alterTableRE.FindStringSubmatch(stmt.text); m != nil && tables[tableName(m[1])] != nil {
			g := tables[tableName(m[1])]
			g.enabled = g.enabled || m[2] == "enable row level security"
			g.forced = g.forced || m[2] == "force row level security"
		}
		if p, ok := parsePolicy(stmt.full); ok && p.create && tables[p.table] != nil && p.def.tenant() {
			tables[p.table].policy = true
		}
	}
	var problems []string
	for _, name := range order {
		if g := tables[name]; !g.enabled || !g.forced || !g.policy {
			problems = append(problems, fmt.Sprintf("table %s has tenant_id: enable and force row level security and create the tenant policy in the same file, or mark a global table with %q and a reason", name, GlobalMarker))
		}
	}
	return problems
}

func createdTables(stmts []statement) map[string]bool {
	out := map[string]bool{}
	for _, stmt := range stmts {
		if m := createTableRE.FindStringSubmatch(stmt.text); m != nil {
			out[tableName(m[1])] = true
		}
	}
	return out
}

func concurrent(s string) bool {
	if m := createIndexRE.FindStringSubmatch(s); m != nil {
		return m[1] != ""
	}
	return strings.HasPrefix(s, "drop index concurrently")
}

// contractReasons lists what in stmt the running release could depend on or be blocked by. Every drop
// except a concurrent index drop counts, as do truncates, renames, type changes, defaults dropped, NOT NULL
// without a default, and on Postgres locking index builds and constraints added without NOT VALID.
func contractReasons(stmt statement, dialect db.Dialect, created map[string]bool) []string {
	s := stmt.text
	var reasons []string
	words := strings.Fields(s)
	switch {
	case strings.HasPrefix(s, "drop "):
		if r := dropReason(s, dialect); r != "" {
			reasons = append(reasons, r)
		}
	case words[0] == "truncate":
		reasons = append(reasons, "truncates a table")
	case strings.HasPrefix(s, "rename table"):
		reasons = append(reasons, "renames a table")
	case strings.HasPrefix(s, "alter type"):
		reasons = append(reasons, "alters a type")
	case strings.HasPrefix(s, "vacuum full"):
		reasons = append(reasons, "rewrites a table (vacuum full)")
	case words[0] == "alter" && !strings.HasPrefix(s, "alter table") && slices.Contains(words, "rename"):
		reasons = append(reasons, "renames a database object")
	}
	if m := createIndexRE.FindStringSubmatch(s); m != nil && dialect == db.Postgres && m[1] == "" && !created[tableName(m[2])] {
		reasons = append(reasons, "creates an index on an existing table without concurrently")
	}
	m := alterTableRE.FindStringSubmatch(s)
	if m == nil {
		return reasons
	}
	for _, clause := range splitClauses(m[2]) {
		reasons = append(reasons, alterReasons(clause, dialect)...)
	}
	return reasons
}

func dropReason(s string, dialect db.Dialect) string {
	words := strings.Fields(s)
	if len(words) < 2 {
		return ""
	}
	switch words[1] {
	case "table":
		return "drops a table"
	case "view", "materialized":
		return "drops a view"
	case "function", "procedure":
		return "drops a function"
	case "index":
		if dialect == db.Postgres && len(words) > 2 && words[2] == "concurrently" {
			return ""
		}
		return "drops an index"
	}
	return "drops a " + words[1]
}

var keepDrops = []string{"constraint", "index", "key", "primary", "foreign", "check"}

func alterReasons(clause string, dialect db.Dialect) []string {
	words := strings.Fields(clause)
	if len(words) == 0 {
		return nil
	}
	var reasons []string
	switch words[0] {
	case "drop":
		if len(words) > 1 && !slices.Contains(keepDrops, words[1]) {
			reasons = append(reasons, "drops a column")
		}
	case "rename":
		reasons = append(reasons, "renames a column or table")
	case "add":
		reasons = append(reasons, addReasons(clause, words, dialect)...)
	case "modify", "change":
		if dialect == db.MySQL {
			reasons = append(reasons, "changes a column definition")
		}
	case "alter":
		if pgTypeChangeRE.MatchString(clause) {
			reasons = append(reasons, "changes a column type")
		}
		if strings.Contains(clause, "set not null") {
			reasons = append(reasons, "sets not null on an existing column")
		}
		if dropDefaultRE.MatchString(clause) {
			reasons = append(reasons, "drops a column default")
		}
	}
	return reasons
}

func addReasons(clause string, words []string, dialect db.Dialect) []string {
	if len(words) < 2 {
		return nil
	}
	switch words[1] {
	case "constraint", "foreign", "check":
		validates := strings.Contains(clause, "foreign key") || words[1] == "check" || slices.Contains(words, "check")
		if dialect == db.Postgres && validates && !strings.Contains(clause, "not valid") {
			return []string{"adds a foreign key or check without not valid"}
		}
		return nil
	case "index", "key", "unique", "primary", "fulltext", "spatial":
		return nil
	}
	outer := withoutParens(clause)
	if strings.Contains(outer, "not null") && !defaultRE.MatchString(outer) {
		return []string{"adds a not null column without a default"}
	}
	return nil
}

// withoutParens drops parenthesised text, so a check expression or type size is not read as the column's options.
func withoutParens(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth = max(0, depth-1)
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// splitClauses splits an alter table action list on top-level commas.
func splitClauses(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

var (
	createRoutineRE = regexp.MustCompile(`^create (?:or replace )?(?:function|procedure) ([^\s(]+)\s*\(`)
	// changesSchemaRE is what a function body may not do unseen: run dynamic SQL, or change tables,
	// policies or row-level security.
	changesSchemaRE = regexp.MustCompile(`\bexecute\b|\balter table\b|\b(?:create|alter|drop) policy\b|\brow level security\b`)
)

// procedural refuses, in one file under tenancy, a DO block or a function whose body could change
// tables, policies or row-level security without the validator reading it, unless allowed.
func procedural(name string, p parsed, allowed []Procedural) []error {
	isAllowed := func(function string) bool {
		return p.procedural && slices.ContainsFunc(allowed, func(a Procedural) bool {
			return a.File == name && a.Function == function && a.Reason != "" && a.Reason == p.proceduralReason
		})
	}
	how := fmt.Sprintf("mark the file %q with why, and allow it in the procedural allowlist with the same reason", ProceduralMarker)
	var errs []error
	for _, stmt := range p.up {
		if strings.HasPrefix(stmt.text, "do ") && !isAllowed("") {
			errs = append(errs, fmt.Errorf("%s: a DO block runs procedural SQL the validator cannot read: %s", name, how))
		}
		m := createRoutineRE.FindStringSubmatch(stmt.text)
		if m == nil || !changesSchemaRE.MatchString(stmt.full+" "+strings.Join(stmt.bodies, " ")) {
			continue
		}
		fn := strings.ReplaceAll(m[1], `"`, "")
		if !strings.Contains(fn, ".") {
			fn = "public." + fn
		}
		if !isAllowed(fn) {
			errs = append(errs, fmt.Errorf("%s: function %s runs dynamic SQL or changes tables, policies or row-level security: %s", name, fn, how))
		}
	}
	return errs
}
