package cli_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PuckxPuck/keel/internal/kit/cli"
)

func testApp(t *testing.T) (cli.App, *[]string) {
	t.Helper()
	var calls []string
	app := cli.App{
		Name:    "tool",
		Summary: "a test tool",
		Commands: []cli.Command{
			{
				Name:    "about",
				Summary: "Show build information",
				Run: func(context.Context, *flag.FlagSet, []string) error {
					calls = append(calls, "about")
					return nil
				},
			},
			{
				Name:    "queue:work",
				Summary: "Run workers",
				Flags: func(fs *flag.FlagSet) {
					fs.String("lanes", "fast", "lanes to run")
					fs.Bool("once", false, "run a single pass")
				},
				Run: func(_ context.Context, fs *flag.FlagSet, args []string) error {
					calls = append(calls, "queue:work lanes="+fs.Lookup("lanes").Value.String()+" args="+strings.Join(args, ","))
					return nil
				},
			},
			{
				Name:    "queue:status",
				Summary: "Show queue depth",
				Run:     func(context.Context, *flag.FlagSet, []string) error { return errors.New("database is down") },
			},
			{
				Name:    "user:create",
				Summary: "Create a user",
				Run: func(context.Context, *flag.FlagSet, []string) error {
					return cli.Usagef("email is required")
				},
			},
		},
	}
	return app, &calls
}

func run(t *testing.T, app cli.App, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = app.Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_ExitCodesAndRouting(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
		wantCalls  []string
	}{
		{name: "no arguments lists commands", args: nil, wantCode: cli.ExitOK, wantStdout: "Usage: tool <command>"},
		{name: "list is built in", args: []string{"list"}, wantCode: cli.ExitOK, wantStdout: "queue:work"},
		{name: "help flag lists commands", args: []string{"--help"}, wantCode: cli.ExitOK, wantStdout: "Usage: tool <command>"},
		{name: "runs a command", args: []string{"about"}, wantCode: cli.ExitOK, wantCalls: []string{"about"}},
		{
			name:      "passes flags and positional arguments",
			args:      []string{"queue:work", "--lanes", "slow", "a", "b"},
			wantCode:  cli.ExitOK,
			wantCalls: []string{"queue:work lanes=slow args=a,b"},
		},
		{name: "unknown command is a usage error", args: []string{"nope"}, wantCode: cli.ExitUsage, wantStderr: `unknown command "nope"`},
		{name: "unknown flag is a usage error", args: []string{"about", "--bogus"}, wantCode: cli.ExitUsage, wantStderr: "flag provided but not defined: -bogus"},
		{name: "command error exits 1", args: []string{"queue:status"}, wantCode: cli.ExitError, wantStderr: "error: database is down"},
		{name: "usage error from a command exits 2", args: []string{"user:create"}, wantCode: cli.ExitUsage, wantStderr: "error: email is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, calls := testApp(t)
			code, stdout, stderr := run(t, app, tt.args...)

			assert.Equal(t, tt.wantCode, code)
			assert.Contains(t, stdout, tt.wantStdout)
			assert.Contains(t, stderr, tt.wantStderr)
			if tt.wantCalls != nil {
				assert.Equal(t, tt.wantCalls, *calls)
			} else {
				assert.Empty(t, *calls)
			}
		})
	}
}

func TestRun_CommandHelpPrintsFlags(t *testing.T) {
	app, calls := testApp(t)

	code, stdout, _ := run(t, app, "queue:work", "--help")

	assert.Equal(t, cli.ExitOK, code)
	assert.Contains(t, stdout, "Usage: tool queue:work")
	assert.Contains(t, stdout, "Run workers")
	assert.Contains(t, stdout, "-lanes string")
	assert.Contains(t, stdout, "-once")
	assert.Empty(t, *calls, "help must not run the command")
}

func TestList_GroupsAndAligns(t *testing.T) {
	app, _ := testApp(t)

	_, stdout, _ := run(t, app, "list")

	want := `tool: a test tool

Usage: tool <command> [flags] [arguments]

Commands
  about         Show build information
  list          List commands

queue
  queue:status  Show queue depth
  queue:work    Run workers

user
  user:create   Create a user

Run 'tool <command> --help' for a command's flags.
`
	assert.Equal(t, want, stdout)
}

func TestRun_PanicsOnProgrammerErrors(t *testing.T) {
	noop := func(context.Context, *flag.FlagSet, []string) error { return nil }
	tests := []struct {
		name string
		cmds []cli.Command
	}{
		{name: "duplicate name", cmds: []cli.Command{{Name: "a", Run: noop}, {Name: "a", Run: noop}}},
		{name: "shadowing the built-in list", cmds: []cli.Command{{Name: "list", Run: noop}}},
		{name: "missing Run", cmds: []cli.Command{{Name: "a"}}},
		{name: "missing name", cmds: []cli.Command{{Run: noop}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := cli.App{Name: "tool", Commands: tt.cmds}
			assert.Panics(t, func() { run(t, app, "list") })
		})
	}
}

func TestRun_CommandOutputGoesToStdout(t *testing.T) {
	app := cli.App{Name: "tool", Commands: []cli.Command{{
		Name: "hello",
		Run: func(_ context.Context, fs *flag.FlagSet, _ []string) error {
			_, err := fs.Output().Write([]byte("hi\n"))
			return err
		},
	}}}

	_, stdout, _ := run(t, app, "hello")

	assert.Equal(t, "hi\n", stdout)
}
