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
)

const toolsModfile = "-modfile=tools/go.mod"

type step struct {
	name string
	dir  string
	args []string
	// race is true for steps that link the race detector, which needs cgo on Linux.
	race bool
	// db is true for steps that need the test databases; race steps always do.
	db  bool
	env []string
	// run replaces the go command for steps that are more than one.
	run func(ctx context.Context, out io.Writer) error
}

func goTool(name string, args ...string) []string {
	return append([]string{"tool", toolsModfile, name}, args...)
}

func tidySteps() []step {
	return []step{
		{name: "go mod tidy (root)", args: []string{"mod", "tidy", "-diff"}},
		{name: "go mod tidy (tools)", dir: "tools", args: []string{"mod", "tidy", "-diff"}},
	}
}

func lintSteps(args ...string) []step {
	return append([]step{
		{name: "format", args: goTool("golangci-lint", "fmt", "--diff")},
		{name: "lint", args: goTool("golangci-lint", append([]string{"run"}, args...)...)},
		{name: "vet", args: []string{"vet", "./..."}},
	}, tenantSettingSteps()...)
}

func vulnSteps() []step {
	return []step{{name: "govulncheck", args: goTool("govulncheck", "./...")}}
}

func testSteps(pkg, run string) []step {
	args := []string{"test", "-race"}
	if run != "" {
		args = append(args, "-run", run)
	}
	return []step{{name: "test " + strings.TrimSpace(pkg), args: append(args, pkg), race: true}}
}

func genCheckSteps() []step {
	return []step{{name: "generated code", args: []string{"run", "./cmd/keel", "gen", "--check"}, db: true}}
}

func apiCompatSteps() []step {
	return []step{{name: "public API compatibility", run: checkAPICompat}}
}

func checkSteps() []step {
	var steps []step
	for _, group := range [][]step{tidySteps(), lintSteps(), vulnSteps(), genCheckSteps(), apiCompatSteps(), testSteps("./...", "")} {
		steps = append(steps, group...)
	}
	return steps
}

func runSteps(ctx context.Context, out io.Writer, steps []step) error {
	if _, err := os.Stat("tools/go.mod"); err != nil {
		return errors.New("run keel from the repository root (tools/go.mod not found)")
	}
	for _, s := range steps {
		_, _ = fmt.Fprintf(out, "==> %s\n", s.name)
		if s.run != nil {
			if err := s.run(ctx, out); err != nil {
				return fmt.Errorf("%s failed: %w", s.name, err)
			}
			continue
		}
		cmd := exec.CommandContext(ctx, "go", s.args...) //nolint:gosec // arguments are fixed in this file
		cmd.Dir = s.dir
		cmd.Stdout, cmd.Stderr = out, os.Stderr
		cgo := "CGO_ENABLED=0"
		if s.race {
			cgo = "CGO_ENABLED=1"
		}
		cmd.Env = append(append(os.Environ(), cgo), s.env...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s failed: %w", s.name, err)
		}
	}
	return nil
}

func runCheck(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	steps, err := withTestDatabases(ctx, fs.Output(), "", checkSteps())
	if err != nil {
		return err
	}
	return runSteps(ctx, fs.Output(), steps)
}

// withTestDatabases gives the steps that need them the URLs of the reachable test databases.
func withTestDatabases(ctx context.Context, out io.Writer, only string, steps []step) ([]step, error) {
	urls, err := databaseURLs(ctx, out, only)
	if err != nil {
		return nil, err
	}
	for i := range steps {
		if steps[i].race || steps[i].db {
			steps[i].env = testEnv(urls)
		}
	}
	return steps, nil
}

func runTidy(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	return runSteps(ctx, fs.Output(), tidySteps())
}

func runVuln(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	return runSteps(ctx, fs.Output(), vulnSteps())
}

func testFlags(fs *flag.FlagSet) {
	fs.String("pkg", "./...", "package pattern to test")
	fs.String("run", "", "run only tests matching this regular expression")
	fs.String("engine", "", "test against one database engine only: postgres or mysql")
}

func runTest(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	only := fs.Lookup("engine").Value.String()
	if only != "" && only != "postgres" && only != "mysql" {
		return fmt.Errorf("--engine must be postgres or mysql, got %q", only)
	}
	steps, err := withTestDatabases(ctx, fs.Output(), only, testSteps(fs.Lookup("pkg").Value.String(), fs.Lookup("run").Value.String()))
	if err != nil {
		return err
	}
	return runSteps(ctx, fs.Output(), steps)
}

func runLint(ctx context.Context, fs *flag.FlagSet, args []string) error {
	return runSteps(ctx, fs.Output(), lintSteps(args...))
}

func runFmt(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	return runSteps(ctx, fs.Output(), []step{{name: "format", args: goTool("golangci-lint", "fmt")}})
}
