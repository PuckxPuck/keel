package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
)

func initFlags(fs *flag.FlagSet) {
	fs.String("module", "", "Go module path of the app, such as example.com/me/shop (required)")
	fs.String("name", "", "binary, database role and deploy name, ^[a-z][a-z0-9]{1,29}$ (required)")
	fs.String("db", "", "the one database the app keeps: postgres or mysql (required)")
	fs.String("without", "", "parts to remove, comma-separated, or all: "+strings.Join(optionalParts(), ", "))
	fs.String("with", "", "example modules to keep: notes (needs Postgres, tenancy, files, mail and xlsx)")
	fs.String("env-prefix", "APP_", "prefix of the app's environment variables")
	fs.Bool("dry-run", false, "print the plan and write nothing")
	fs.Bool("keep-on-failure", false, "leave the result for inspection when build, gen or check fails, instead of resetting")
}

func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func runInit(ctx context.Context, fs *flag.FlagSet, args []string) error {
	if len(args) != 0 {
		return cli.Usagef("usage: keel init --module <path> --name <name> --db postgres|mysql [--without a,b|all] [--with notes]")
	}
	value := func(name string) string { return fs.Lookup(name).Value.String() }
	opts := initOptions{
		module: value("module"), name: value("name"), db: value("db"), envPrefix: value("env-prefix"),
		without: splitList(value("without")), with: splitList(value("with")),
	}
	t, err := repoTree()
	if err != nil {
		return err
	}
	return runInitIn(ctx, fs.Output(), t, opts, initRun{dryRun: value("dry-run") == "true", keep: value("keep-on-failure") == "true", steps: initSteps})
}

// initRun says how far keel init goes after writing its plan.
type initRun struct {
	dryRun, keep bool
	steps        func() []step
}

// initSteps run after the plan is written: build first, since it fails fastest on embed and compile
// problems, then gen and the full check.
func initSteps() []step {
	return append(initBuildSteps(), []step{
		{name: "keel gen", args: []string{"run", "./cmd/keel", "gen"}, db: true},
		{name: "keel check", args: []string{"run", "./cmd/keel", "check"}, db: true},
	}...)
}

func initBuildSteps() []step {
	return []step{
		{name: "go mod tidy (root)", args: []string{"mod", "tidy"}},
		{name: "go mod tidy (tools)", dir: "tools", args: []string{"mod", "tidy"}},
		{name: "go build", args: []string{"build", "./..."}},
		{name: "go vet", args: []string{"vet", "./..."}},
	}
}

// initState is what preflight found: the commit to reset to, the keel version, and the database URL gen
// and check use (resolved before the rewrite renames the local database).
type initState struct {
	head, version, dbURL string
}

func runInitIn(ctx context.Context, out io.Writer, t *tree, opts initOptions, run initRun) error {
	if _, err := opts.removedParts(); err != nil {
		return err
	}
	st, err := initPreflight(ctx, out, t, opts)
	if err != nil {
		return err
	}
	pl, err := buildInitPlan(ctx, t, opts, st.version)
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	if run.dryRun {
		pl.report(out)
		_, err := fmt.Fprintln(out, "dry run: nothing was written")
		return err
	}
	return applyInit(ctx, out, pl, st, run)
}

// applyInit writes the plan and runs the steps. A failure after the first write, or an interrupt, resets
// the checkout to the preflight HEAD; --keep-on-failure only keeps a step's failed result.
func applyInit(ctx context.Context, out io.Writer, pl *initPlan, st initState, run initRun) error {
	rollback := func(err error) error {
		// the signal that cancelled ctx must not stop the reset too
		if rerr := resetTree(context.WithoutCancel(ctx), pl.root, st.head); rerr != nil {
			return errors.Join(err, rerr)
		}
		return fmt.Errorf("%w; the checkout was reset to %s", err, st.head)
	}
	if err := pl.commitAll(); err != nil {
		return rollback(err)
	}
	e := engineNamed(pl.opts.db)
	steps := run.steps()
	for i := range steps {
		if steps[i].db {
			steps[i].env = []string{e.urlVar + "=" + st.dbURL, otherURLVar(pl.opts.db) + "="}
		}
	}
	err := runSteps(ctx, out, steps)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if run.keep && ctx.Err() == nil {
			return fmt.Errorf("%w; the result is left for inspection (git reset --hard %s && git clean -fd undoes it)", err, st.head)
		}
		return rollback(err)
	}
	pl.report(out)
	initNotes(out, pl)
	return nil
}

func engineNamed(name string) engine {
	for _, e := range engines {
		if e.name == name {
			return e
		}
	}
	return engines[0]
}

func otherURLVar(db string) string {
	for _, e := range engines {
		if e.name != db {
			return e.urlVar
		}
	}
	return ""
}

func initPreflight(ctx context.Context, out io.Writer, t *tree, opts initOptions) (initState, error) {
	if _, err := os.Stat(t.path(keelVersionFile)); err == nil {
		return initState{}, fmt.Errorf("%s exists: keel init has already run here", keelVersionFile)
	}
	if !gitSucceeds(ctx, t.root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}") {
		return initState{}, errors.New("keel init needs a git checkout of keel with at least one commit, so a failure can be reset")
	}
	if top, err := gitOutput(ctx, t.root, "rev-parse", "--show-prefix"); err != nil || strings.TrimSpace(string(top)) != "" {
		return initState{}, errors.New("run keel init from the repository root")
	}
	dirty, err := gitOutput(ctx, t.root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return initState{}, err
	}
	if len(strings.TrimSpace(string(dirty))) > 0 {
		return initState{}, errors.New("the working tree has changes or untracked files: commit or remove them first, since a failed init resets the tree")
	}
	head, err := gitOutput(ctx, t.root, "rev-parse", "HEAD")
	if err != nil {
		return initState{}, err
	}
	version, err := gitOutput(ctx, t.root, "describe", "--tags", "--always")
	if err != nil {
		return initState{}, err
	}
	if !gitSucceeds(ctx, t.root, "describe", "--tags", "--exact-match", "--match", releaseTagPattern) {
		_, _ = fmt.Fprintf(out, "warning: HEAD is not on a keel release tag; %s records %s, and upgrade:diff works best from a tag\n", keelVersionFile, strings.TrimSpace(string(version)))
	}
	e := engineNamed(opts.db)
	u, ok := e.url(ctx)
	if !ok {
		return initState{}, fmt.Errorf("keel gen needs a %s database: set %s, or start one with %s (%s)", e.name, e.urlVar, e.hint, e.unreachable())
	}
	if err := pingDatabase(ctx, u); err != nil {
		return initState{}, fmt.Errorf("keel gen needs a %s database it can reach (%s or the compose default): %w", e.name, e.urlVar, err)
	}
	return initState{head: strings.TrimSpace(string(head)), version: strings.TrimSpace(string(version)), dbURL: u}, nil
}

// pingDatabase connects to rawURL with the credentials keel gen will use.
func pingDatabase(ctx context.Context, rawURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg := db.Defaults()
	cfg.MaxOpen, cfg.MaxIdle = 1, 1
	pool, _, err := db.OpenSQL(ctx, rawURL, cfg)
	if err != nil {
		return err
	}
	return pool.Close()
}

// resetTree puts the checkout back to head. No -x: ignored files such as .env survive, and the clean
// tree preflight means nothing else is lost.
func resetTree(ctx context.Context, root, head string) error {
	for _, args := range [][]string{{"reset", "--hard", "--quiet", head}, {"clean", "-fdq"}} {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...) //nolint:gosec // fixed subcommands, a commit git printed
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("reset failed, run git reset --hard %s && git clean -fd: %w: %s", head, err, out)
		}
	}
	return nil
}

func initNotes(out io.Writer, pl *initPlan) {
	if pl.isRemoved("mail") {
		_, _ = fmt.Fprintln(out, "warning: mail is removed, so outside local the app refuses to start until it passes a Notifier in Deps")
	}
	if pl.opts.name != "keel" {
		_, _ = fmt.Fprintf(out, "note: stop keel's local containers before make up (docker compose -p keel down): they hold the same ports and know only keel's database names, not %s's\n", pl.opts.name)
	}
	_, _ = fmt.Fprintln(out, "done: review the result, then git add -A && git commit -m \"keel init\"")
}
