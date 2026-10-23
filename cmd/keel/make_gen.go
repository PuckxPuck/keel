package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/cli"
)

type moduleData struct {
	names
	ModPath string
	Dialect string
	Tenancy bool
	// Mail and Files are set when the app kept those parts.
	Mail, Files bool
	// Scope is the transaction type the module's store takes (D29).
	Scope string
}

var moduleFiles = []struct{ file, template string }{
	{"module.go", "module/module.go.tmpl"},
	{"permissions.go", "module/permissions.go.tmpl"},
	{"handlers.go", "module/handlers.go.tmpl"},
	{"service.go", "module/service.go.tmpl"},
	{"rules.go", "module/rules.go.tmpl"},
	{"store.go", "module/store.go.tmpl"},
	{"rules_test.go", "module/rules_test.go.tmpl"},
	{"store_test.go", "module/store_test.go.tmpl"},
	{"module_test.go", "module/module_test.go.tmpl"},
}

const modulesFile = "internal/app/modules.go"

func makeModule(ctx context.Context, t *tree, args []string) error {
	name := args[0]
	if err := checkModuleName(name); err != nil {
		return err
	}
	if t.exists(moduleDir(name)) {
		return fmt.Errorf("%s already exists", moduleDir(name))
	}
	dialects := t.dialects()
	if len(dialects) == 0 {
		return errNoDialect
	}
	if err := t.tableIsNew(name); err != nil {
		return err
	}
	modPath, err := t.modulePath()
	if err != nil {
		return err
	}
	data := moduleData{
		names: namesOf(name), ModPath: modPath, Dialect: dialects[0], Scope: "db.Plain",
		Mail: t.exists("internal/kit/mail"), Files: t.exists("internal/kit/files"),
	}
	if t.tenancy() && data.Dialect == "postgres" {
		data.Tenancy, data.Scope = true, "db.Tenant"
	}
	for _, f := range moduleFiles {
		src, err := renderGo(f.template, data)
		if err != nil {
			return err
		}
		if err := t.create(filepath.Join(moduleDir(name), f.file), src); err != nil {
			return err
		}
	}
	if err := writeMigrations(ctx, t, name, "create_"+name, true); err != nil {
		return err
	}
	pkg := modPath + "/internal/modules/" + name
	return t.register(modulesFile, "import \""+pkg+"\" and add "+name+".New(...) to the list modules returns", func(src []byte) ([]byte, error) {
		src, w, err := useParam(src, "modules", false, "w")
		if err != nil {
			return nil, err
		}
		if src, err = addImport(src, pkg); err != nil {
			return nil, err
		}
		deps := fmt.Sprintf("Realm: RealmTenant, BasePath: BasePath, DB: %s.db, Audit: %s.audit, Cursors: %s.cursors, Jobs: %s.queue", w, w, w, w)
		if data.Mail {
			deps += ", Mail: " + w + ".mail"
		}
		if data.Files {
			deps += ", Files: " + w + ".files"
		}
		return insertListItem(src, listReturnedBy("modules"), fmt.Sprintf("%s.New(%s.Deps{%s}),", name, name, deps))
	})
}

// register edits the file that lists a module, job or command. A file the generator cannot read as a list
// stops the run before anything is written, and the error says what to add by hand.
func (t *tree) register(rel, byHand string, fn func([]byte) ([]byte, error)) error {
	err := t.edit(rel, fn)
	if err != nil {
		return fmt.Errorf("%w\nnothing was written; to register by hand in %s: %s", err, rel, byHand)
	}
	return nil
}

func makeMigrationCmd(ctx context.Context, t *tree, args []string) error {
	module, what := args[0], args[1]
	if !moduleNameRE.MatchString(module) {
		return cli.Usagef("module %q must be a lower-case identifier of letters and digits", module)
	}
	if !whatRE.MatchString(what) {
		return cli.Usagef("%q must be lower-case letters, digits and underscores, starting with a letter", what)
	}
	if !t.exists(moduleDir(module)) {
		return cli.Usagef("%s not found: name the module the migration belongs to", moduleDir(module))
	}
	if table, ok := strings.CutPrefix(what, "create_"); ok {
		if err := checkTableName(table); err != nil {
			return err
		}
		if err := t.tableIsNew(table); err != nil {
			return err
		}
	}
	return writeMigrations(ctx, t, module, what, false)
}

type migrationData struct {
	Table string
	// Example adds the columns and sort indexes of make:module's example resource.
	Example bool
	// Tenancy writes the table as a tenant table (Postgres under tenancy): tenant_id, tenant-leading keys
	// and the row-level security policy in the one file (D36).
	Tenancy bool
}

// writeMigrations writes <stamp>_<module>_<what>.sql in every dialect folder; create_<table> gets the
// table template, under tenancy in its final shape on Postgres (D36).
func writeMigrations(ctx context.Context, t *tree, module, what string, example bool) error {
	dialects := t.dialects()
	if len(dialects) == 0 {
		return errNoDialect
	}
	table, create := strings.CutPrefix(what, "create_")
	stamp := migrationStamp(ctx, t, map[string]bool{})
	for _, d := range dialects {
		tpl := "migration/change.sql.tmpl"
		if create {
			tpl = "migration/create_" + d + ".sql.tmpl"
		}
		data := migrationData{Table: table, Example: example, Tenancy: d == "postgres" && t.tenancy()}
		src, err := render(tpl, data)
		if err != nil {
			return err
		}
		if err := t.create(filepath.Join(migrationsDir, d, stamp+"_"+module+"_"+what+".sql"), src); err != nil {
			return err
		}
	}
	return nil
}

// tableIsNew refuses a table name some migration already creates.
func (t *tree) tableIsNew(table string) error {
	creates := regexp.MustCompile(`(?im)^\s*create\s+table\s+(if\s+not\s+exists\s+)?` + regexp.QuoteMeta(table) + `\s*\(`)
	for _, d := range t.dialects() {
		files, err := filepath.Glob(filepath.Join(t.root, migrationsDir, d, "*.sql"))
		if err != nil {
			return err
		}
		for _, f := range files {
			src, err := os.ReadFile(f) //nolint:gosec // migration files of the repository
			if err != nil {
				return err
			}
			if creates.Match(src) {
				return fmt.Errorf("table %s already exists (%s)", table, filepath.Base(f))
			}
		}
	}
	return nil
}

type jobData struct {
	moduleData
	KindName string
	Kind     string
	Func     string
}

func makeJob(_ context.Context, t *tree, args []string) error {
	module, kind := args[0], args[1]
	dir := moduleDir(module)
	if !moduleNameRE.MatchString(module) || !t.exists(filepath.Join(dir, "module.go")) {
		return cli.Usagef("%s/module.go not found: make:job adds to a module made by make:module", dir)
	}
	if !whatRE.MatchString(kind) {
		return cli.Usagef("kind %q must be lower-case letters, digits and underscores, starting with a letter", kind)
	}
	modPath, err := t.modulePath()
	if err != nil {
		return err
	}
	data := jobData{moduleData: moduleData{names: namesOf(module), ModPath: modPath}, KindName: kind, Kind: camel(kind), Func: "run" + camel(kind)}
	files := []struct{ file, template string }{{"job_" + kind + ".go", "job.go.tmpl"}, {"job_" + kind + "_test.go", "job_test.go.tmpl"}}
	for _, f := range files {
		src, err := renderGo(f.template, data)
		if err != nil {
			return err
		}
		if err := t.create(filepath.Join(dir, f.file), src); err != nil {
			return err
		}
	}
	line := fmt.Sprintf("q.Handle(Kind%s, jobs.Typed(m.%s))", data.Kind, data.Func)
	return t.register(filepath.Join(dir, "module.go"), "add "+line+" to the Jobs method", func(src []byte) ([]byte, error) {
		src, q, err := useParam(src, "Jobs", true, "q")
		if err != nil {
			return nil, err
		}
		return insertGo(src, methodEnd("Jobs"), fmt.Sprintf("%s.Handle(Kind%s, jobs.Typed(m.%s))", q, data.Kind, data.Func))
	})
}

type commandData struct {
	ModPath string
	Name    string
	Func    string
	Summary string
}

func makeAppCommand(_ context.Context, t *tree, args []string) error {
	name := args[0]
	if !commandRE.MatchString(name) {
		return cli.Usagef("command %q must be group:action in lower case (letters, digits and dashes)", name)
	}
	group, action, _ := strings.Cut(name, ":")
	if err := t.refuseUsed([]string{"internal", "cmd/app"}, `"`+name+`"`); err != nil {
		return err
	}
	modPath, err := t.modulePath()
	if err != nil {
		return err
	}
	data := commandData{
		ModPath: modPath, Name: name,
		Func:    lowerFirst(camel(group)) + camel(action) + "Command",
		Summary: upperFirst(strings.ReplaceAll(group+" "+action, "-", " ")),
	}
	src, err := renderGo("command.go.tmpl", data)
	if err != nil {
		return err
	}
	file := strings.ReplaceAll(group+"_"+action, "-", "_") + "_command.go"
	if err := t.create(filepath.Join("internal/app", file), src); err != nil {
		return err
	}
	return t.register(modulesFile, "add "+data.Func+"(environ), to the list appCommands returns", func(src []byte) ([]byte, error) {
		src, environ, err := useParam(src, "appCommands", false, "environ")
		if err != nil {
			return nil, err
		}
		return insertListItem(src, listReturnedBy("appCommands"), data.Func+"("+environ+"),")
	})
}

const maxPermCode = 128

func makePermission(_ context.Context, t *tree, args []string) error {
	code := args[0]
	m := permRE.FindStringSubmatch(code)
	if m == nil || len(code) > maxPermCode {
		return cli.Usagef("permission %q must look like <module>.<action> in lower case, up to %d characters", code, maxPermCode)
	}
	module, action := m[1], strings.TrimPrefix(m[2], ".")
	file := filepath.Join(moduleDir(module), "permissions.go")
	if !t.exists(file) {
		return cli.Usagef("%s not found: the first segment of a permission names its module", file)
	}
	src, err := t.read(file)
	if err != nil {
		return err
	}
	if bytes.Contains(src, []byte(`"`+code+`"`)) {
		return fmt.Errorf("%s is already in %s", code, file)
	}
	constant := "Perm" + camel(action)
	label := upperFirst(strings.Join(strings.FieldsFunc(action, func(r rune) bool { return r == '.' || r == '_' || r == '-' }), " ")) + " " + module
	return t.edit(file, func(src []byte) ([]byte, error) {
		src, err := insertGo(src, constBlockOf("rbac", "Code"), fmt.Sprintf("%s rbac.Code = %q", constant, code))
		if err != nil {
			return nil, err
		}
		return insertListItem(src, varList("permissions"), fmt.Sprintf("{Code: %s, Area: %q, Label: %q},", constant, upperFirst(module), label))
	})
}

// refuseUsed refuses a literal that already appears in a Go file under dirs.
func (t *tree) refuseUsed(dirs []string, literal string) error {
	return t.refuseMatch(dirs, func(src []byte) bool { return bytes.Contains(src, []byte(literal)) }, literal)
}

func (t *tree) refuseMatch(dirs []string, match func([]byte) bool, what string) error {
	for _, dir := range dirs {
		files, err := t.goFiles(dir)
		if err != nil {
			return err
		}
		for _, f := range files {
			src, err := t.read(f)
			if err != nil {
				return err
			}
			if match(src) {
				return fmt.Errorf("%s is already used in %s", what, f)
			}
		}
	}
	return nil
}
