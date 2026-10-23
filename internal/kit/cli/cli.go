package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
)

const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2

	exitInterrupted = 130
)

const listCommand = "list"

type App struct {
	Name     string
	Summary  string
	Commands []Command
}

type Command struct {
	Name    string
	Summary string
	Flags   func(fs *flag.FlagSet)
	// Run writes normal output to fs.Output().
	Run func(ctx context.Context, fs *flag.FlagSet, args []string) error
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// Usagef makes Run exit with ExitUsage and print the command help.
func Usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

func (a App) Main() {
	ctx, stop := SignalContext(context.Background())
	code := a.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// SignalContext is cancelled by the first SIGINT or SIGTERM; a second one exits the process
// immediately, so a hung shutdown can still be interrupted.
func SignalContext(parent context.Context) (ctx context.Context, stop context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	stopped := make(chan struct{})
	var once sync.Once
	go escalate(ctx, cancel, sigs, stopped, os.Exit)
	return ctx, func() {
		once.Do(func() {
			signal.Stop(sigs)
			close(stopped)
			cancel()
		})
	}
}

func escalate(ctx context.Context, cancel context.CancelFunc, sigs <-chan os.Signal, stopped <-chan struct{}, exit func(int)) {
	select {
	case <-sigs:
		cancel()
	case <-ctx.Done():
		return
	}
	select {
	case <-sigs:
		exit(exitInterrupted)
	case <-stopped:
	}
}

// Run panics on duplicate or incomplete commands (a startup programmer error).
func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	index := a.index()

	if len(args) == 0 {
		a.writeList(stdout)
		return ExitOK
	}
	name := args[0]
	switch name {
	case "-h", "--help", "-help", "help":
		a.writeList(stdout)
		return ExitOK
	}

	cmd, ok := index[name]
	if !ok {
		say(stderr, "unknown command %q\n\n", name)
		a.writeList(stderr)
		return ExitUsage
	}
	if name == listCommand && cmd.Run == nil {
		a.writeList(stdout)
		return ExitOK
	}
	return a.execute(ctx, cmd, args[1:], stdout, stderr)
}

func (a App) execute(ctx context.Context, cmd Command, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if cmd.Flags != nil {
		cmd.Flags(fs)
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.writeHelp(stdout, cmd, fs)
			return ExitOK
		}
		say(stderr, "error: %v\n\n", err)
		a.writeHelp(stderr, cmd, fs)
		return ExitUsage
	}

	fs.SetOutput(stdout)
	err := cmd.Run(ctx, fs, fs.Args())
	if err == nil {
		return ExitOK
	}
	var usage *usageError
	if errors.As(err, &usage) {
		say(stderr, "error: %v\n\n", err)
		a.writeHelp(stderr, cmd, fs)
		return ExitUsage
	}
	say(stderr, "error: %v\n", err)
	return ExitError
}

func (a App) index() map[string]Command {
	index := make(map[string]Command, len(a.Commands)+1)
	index[listCommand] = Command{Name: listCommand, Summary: "List commands"}
	for _, c := range a.Commands {
		if c.Name == "" || c.Run == nil {
			panic("cli: command needs a name and a Run function")
		}
		if _, dup := index[c.Name]; dup {
			panic("cli: duplicate command " + c.Name)
		}
		index[c.Name] = c
	}
	return index
}

func (a App) writeList(w io.Writer) {
	index := a.index()
	names := make([]string, 0, len(index))
	width := 0
	for name := range index {
		names = append(names, name)
		width = max(width, len(name))
	}
	sort.Strings(names)

	if a.Summary != "" {
		say(w, "%s: %s\n\n", a.Name, a.Summary)
	}
	say(w, "Usage: %s <command> [flags] [arguments]\n", a.Name)

	var group string
	first := true
	for _, name := range names {
		g := groupOf(name)
		if first || g != group {
			say(w, "\n%s\n", groupTitle(g))
			group, first = g, false
		}
		say(w, "  %-*s  %s\n", width, name, index[name].Summary)
	}
	say(w, "\nRun '%s <command> --help' for a command's flags.\n", a.Name)
}

func (a App) writeHelp(w io.Writer, cmd Command, fs *flag.FlagSet) {
	say(w, "Usage: %s %s [flags] [arguments]\n", a.Name, cmd.Name)
	if cmd.Summary != "" {
		say(w, "\n%s\n", cmd.Summary)
	}
	var hasFlags bool
	fs.VisitAll(func(*flag.Flag) { hasFlags = true })
	if !hasFlags {
		return
	}
	say(w, "\nFlags:\n")
	prev := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(prev)
}

func groupOf(name string) string {
	group, _, found := strings.Cut(name, ":")
	if !found {
		return ""
	}
	return group
}

func groupTitle(group string) string {
	if group == "" {
		return "Commands"
	}
	return group
}

// say ignores write errors: a closed terminal leaves nothing to report to.
func say(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
