package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/clock"
)

var (
	moduleNameRE = regexp.MustCompile(`^[a-z][a-z0-9]{1,29}$`)
	whatRE       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,59}$`)
	commandRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,29}:[a-z][a-z0-9-]{0,29}$`)
	permRE       = regexp.MustCompile(`^([a-z][a-z0-9]{1,29})((?:\.[a-z][a-z0-9_-]*)+)$`)
)

func moduleDir(name string) string { return filepath.Join("internal/modules", name) }

// names are the spellings of a module's resource in generated code.
type names struct {
	Module string // package, table and path: invoices
	Type   string // Go type: Invoice
	Var    string // lower camel: invoice
	Title  string // permission area: Invoices
	Table  string // Jet identifier of the table: Invoices
}

func namesOf(module string) names {
	single := singular(module)
	return names{Module: module, Type: upperFirst(single), Var: single, Title: upperFirst(module), Table: upperFirst(module)}
}

func singular(s string) string {
	switch {
	case strings.HasSuffix(s, "ies") && len(s) > 3:
		return strings.TrimSuffix(s, "ies") + "y"
	case strings.HasSuffix(s, "sses"), strings.HasSuffix(s, "xes"), strings.HasSuffix(s, "ches"), strings.HasSuffix(s, "shes"):
		return strings.TrimSuffix(s, "es")
	case strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss"):
		return strings.TrimSuffix(s, "s")
	}
	return s
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// camel joins the words of s (split on _, - and .) as UpperCamel.
func camel(s string) string {
	var b strings.Builder
	for w := range strings.FieldsFuncSeq(s, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		b.WriteString(upperFirst(w))
	}
	return b.String()
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// generator is one make:* command: it writes through the tree and may regenerate code afterwards.
type generator func(ctx context.Context, t *tree, args []string) error

func makeCommand(name, summary, usage string, nargs int, gen generator, regen bool) cli.Command {
	return cli.Command{
		Name: name, Summary: summary + " (" + usage + ")",
		Run: func(ctx context.Context, fs *flag.FlagSet, args []string) error {
			if len(args) != nargs {
				return cli.Usagef("usage: keel %s %s", name, usage)
			}
			t, err := repoTree()
			if err != nil {
				return err
			}
			return runGenerator(ctx, fs.Output(), t, gen, args, regen)
		},
	}
}

// runGenerator plans what gen writes, checks the plan, writes it, and regenerates code when asked. Any
// failure leaves the tree as it was.
func runGenerator(ctx context.Context, out io.Writer, t *tree, gen generator, args []string, regen bool) error {
	if err := gen(ctx, t, args); err != nil {
		return err
	}
	if err := t.validate(); err != nil {
		return err
	}
	var generated snapshot
	if regen {
		generated = t.snapshot(dbgenDir, specDir)
	}
	if err := t.commit(); err != nil {
		return err
	}
	if regen {
		if err := regenerate(ctx, out, t); err != nil {
			return errors.Join(fmt.Errorf("keel gen failed, so nothing was kept: %w", err), t.undo(), generated.restore(t))
		}
	}
	t.report(out)
	return nil
}

// regenerate runs keel gen after a generator changed the schema or the operations. When a database the
// migration folders need is not reachable it says to run keel gen later instead.
func regenerate(ctx context.Context, out io.Writer, t *tree) error {
	for _, e := range engines {
		if !slices.Contains(t.dialects(), e.name) {
			continue
		}
		if _, ok := e.url(ctx); !ok {
			_, _ = fmt.Fprintf(out, "no %s database reachable for keel gen (set %s or run %s); run `keel gen` once one is\n", e.name, e.urlVar, e.hint)
			return nil
		}
	}
	return runGenIn(ctx, out, t, false)
}

func makeCommands() []cli.Command {
	return []cli.Command{
		makeCommand("make:module", "Scaffold internal/modules/<name> with an example resource and mount it", "<name>", 1, makeModule, true),
		makeCommand("make:migration", "New goose migration in every dialect folder; create_<table> uses the table template", "<module> <what>", 2, makeMigrationCmd, true),
		makeCommand("make:job", "Job kind, payload, handler, registration and test in a module", "<module> <kind>", 2, makeJob, false),
		makeCommand("make:command", "A new app command and its registration", "<group:action>", 1, makeAppCommand, false),
		makeCommand("make:permission", "Add a permission to its module's catalogue", "<module.action>", 1, makePermission, false),
	}
}

// migrationStamp is a version not used in any dialect folder, at or after now.
func migrationStamp(ctx context.Context, t *tree, taken map[string]bool) string {
	at := clock.Wall(ctx).Now().UTC().Truncate(time.Second)
	for {
		stamp := at.Format("20060102150405")
		if !taken[stamp] && !t.stampUsed(stamp) {
			taken[stamp] = true
			return stamp
		}
		at = at.Add(time.Second)
	}
}

func (t *tree) stampUsed(stamp string) bool {
	for _, d := range t.dialects() {
		if m, _ := filepath.Glob(filepath.Join(t.root, migrationsDir, d, stamp+"_*.sql")); len(m) > 0 {
			return true
		}
	}
	return false
}

var errNoDialect = errors.New("no migration folder under db/migrations")
