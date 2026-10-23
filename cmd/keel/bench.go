package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/cli"
)

const (
	benchDir      = "var/bench"
	benchBaseline = benchDir + "/baseline.txt"
	benchCurrent  = benchDir + "/current.txt"
	// benchAgainstFile holds the --against run, which is read once and never kept as a baseline.
	benchAgainstFile = benchDir + "/against.txt"
)

func benchFlags(fs *flag.FlagSet) {
	fs.String("baseline", benchBaseline, "results saved earlier on this machine class to compare with")
	fs.String("against", "", "git ref to benchmark in a temporary worktree and compare with, on this machine, back to back (CI: the last good commit)")
	fs.String("bench", ".", "regular expression selecting benchmarks (go test -bench)")
	fs.Int("count", 6, "runs of each benchmark; benchstat needs several to tell change from noise")
	fs.Float64("threshold", 10, "percent worse in time, memory, allocations or throughput that fails the run")
	fs.Bool("save", false, "save this run as the baseline, unless it found regressions")
	fs.Bool("force", false, "with --save, replace the baseline even when this run found regressions (accepts them)")
}

type benchOptions struct {
	bench     string
	count     int
	threshold float64
}

// runBench runs every package with benchmarks into var/bench/current.txt and compares it with a baseline:
// a saved file, or the same benchmarks at --against's commit run just before on this machine. It fails on a
// significant regression above the threshold. Results from another machine class are not compared.
func runBench(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	if _, err := os.Stat("tools/go.mod"); err != nil {
		return errors.New("run keel from the repository root (tools/go.mod not found)")
	}
	out := fs.Output()
	flagValue := func(name string) string { return fs.Lookup(name).Value.String() }
	baseline, against := flagValue("baseline"), flagValue("against")
	save, force := flagValue("save") == "true", flagValue("force") == "true"
	count, err := strconv.Atoi(flagValue("count"))
	if err != nil || count < 1 {
		return errors.New("--count must be a positive number")
	}
	threshold, err := strconv.ParseFloat(flagValue("threshold"), 64)
	if err != nil {
		return errors.New("--threshold must be a number")
	}
	switch {
	case against != "" && save:
		return cli.Usagef("--against compares two runs of this machine and keeps no baseline: drop --save")
	case force && !save:
		return cli.Usagef("--force only goes with --save")
	case against != "" && !versionRE.MatchString(against):
		return cli.Usagef("--against %q is not a tag, branch or commit name", against)
	}
	opts := benchOptions{bench: flagValue("bench"), count: count, threshold: threshold}
	if err := os.MkdirAll(benchDir, 0o750); err != nil {
		return err
	}
	if against != "" {
		baseline = benchAgainstFile
		if err := benchRef(ctx, out, against, opts, baseline); err != nil {
			return err
		}
	}
	results, err := runBenchmarks(ctx, out, ".", opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(benchCurrent, results, 0o600); err != nil {
		return err
	}
	found, err := compareWithBaseline(ctx, out, baseline, results, threshold)
	if err != nil {
		return err
	}
	if save {
		if len(found) > 0 && !force {
			_, _ = fmt.Fprintf(out, "not saved: the run found regressions, so %s keeps the last good results (--save --force accepts them)\n", baseline)
		} else {
			if err := os.WriteFile(baseline, results, 0o600); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "saved %s\n", baseline)
			found = nil
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("regressions above %g%%:\n  %s", threshold, strings.Join(found, "\n  "))
	}
	return nil
}

// compareWithBaseline prints benchstat's comparison and returns the regressions. It compares nothing when
// there is no baseline or the baseline came from another kind of machine.
func compareWithBaseline(ctx context.Context, out io.Writer, baseline string, current []byte, threshold float64) ([]string, error) {
	saved, err := os.ReadFile(baseline) //nolint:gosec // a path from a flag
	if errors.Is(err, fs.ErrNotExist) {
		_, _ = fmt.Fprintf(out, "no baseline at %s: nothing to compare (--save keeps this run as one)\n", baseline)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if was, now := machineClass(saved), machineClass(current); was != now {
		_, _ = fmt.Fprintf(out, "not comparing: %s was recorded on %q and this machine is %q (--save records a baseline for this one)\n", baseline, was, now)
		return nil, nil
	}
	return compareBench(ctx, out, baseline, benchCurrent, threshold)
}

// machineClass is the part of a benchmark run's header that decides whether two runs are comparable.
func machineClass(results []byte) string {
	var parts []string
	for _, key := range []string{"goos", "goarch", "cpu"} {
		for line := range bytes.Lines(results) {
			if v, ok := strings.CutPrefix(string(line), key+": "); ok {
				parts = append(parts, strings.TrimSpace(v))
				break
			}
		}
	}
	return strings.Join(parts, " ")
}

// benchRef benchmarks ref in a temporary git worktree and writes the results to file.
func benchRef(ctx context.Context, out io.Writer, ref string, opts benchOptions, file string) error {
	if err := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "--quiet", ref+"^{commit}").Run(); err != nil { //nolint:gosec // ref matches versionRE
		return fmt.Errorf("--against %s: no such commit here (in CI, fetch the full history: fetch-depth 0)", ref)
	}
	dir, err := os.MkdirTemp("", "keel-bench-base-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := exec.CommandContext(ctx, "git", "worktree", "add", "--detach", dir, ref).Run(); err != nil { //nolint:gosec // as above
		return fmt.Errorf("git worktree add %s: %w", ref, err)
	}
	defer func() {
		_ = exec.CommandContext(context.WithoutCancel(ctx), "git", "worktree", "remove", "--force", dir).Run() //nolint:gosec // the directory made above
	}()
	_, _ = fmt.Fprintf(out, "==> baseline: %s\n", ref)
	results, err := runBenchmarks(ctx, out, dir, opts)
	if errors.Is(err, errNoBenchmarks) {
		_, _ = fmt.Fprintf(out, "%s has no benchmarks: nothing to compare\n", ref)
		return os.RemoveAll(file)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(file, results, 0o600)
}

var errNoBenchmarks = errors.New("no package has a benchmark")

// runBenchmarks runs the benchmarks of the checkout at dir and returns go test's output.
func runBenchmarks(ctx context.Context, out io.Writer, dir string, opts benchOptions) ([]byte, error) {
	pkgs, err := benchPackages(dir)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, errNoBenchmarks
	}
	var results bytes.Buffer
	args := append([]string{"test", "-run", "^$", "-bench", opts.bench, "-benchmem", "-count", strconv.Itoa(opts.count)}, pkgs...)
	_, _ = fmt.Fprintf(out, "==> go %s\n", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // go test with flags and package paths found here
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, io.MultiWriter(&results, out), os.Stderr
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("benchmarks failed: %w", err)
	}
	return results.Bytes(), nil
}

func compareBench(ctx context.Context, out io.Writer, baseline, current string, threshold float64) ([]string, error) {
	inputs := []string{"baseline=" + baseline, "current=" + current}
	text := exec.CommandContext(ctx, "go", goTool("benchstat", inputs...)...) //nolint:gosec // fixed tool, file paths from flags
	text.Stdout, text.Stderr = out, os.Stderr
	if err := text.Run(); err != nil {
		return nil, fmt.Errorf("benchstat: %w", err)
	}
	table, err := exec.CommandContext(ctx, "go", goTool("benchstat", append([]string{"-format", "csv"}, inputs...)...)...).Output() //nolint:gosec // as above
	if err != nil {
		return nil, fmt.Errorf("benchstat: %w", err)
	}
	return regressions(table, threshold)
}

// regressions reads benchstat's CSV and lists each benchmark and unit whose significant change is worse
// than threshold percent. Time, bytes and allocations per op are lower-better; throughput is higher-better.
func regressions(table []byte, threshold float64) ([]string, error) {
	r := csv.NewReader(bytes.NewReader(table))
	r.FieldsPerRecord, r.LazyQuotes = -1, true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read benchstat output: %w", err)
	}
	var found []string
	var pkg, unit string
	for _, rec := range records {
		switch {
		case len(rec) == 1 && strings.HasPrefix(rec[0], "pkg: "):
			pkg = strings.TrimPrefix(rec[0], "pkg: ")
		case len(rec) >= 7 && rec[0] == "" && rec[5] == "vs base":
			unit = rec[1]
		case len(rec) >= 7 && rec[0] != "" && rec[0] != "geomean" && strings.HasSuffix(rec[5], "%"):
			delta, err := strconv.ParseFloat(strings.TrimSuffix(rec[5], "%"), 64)
			if higherIsBetter[unit] {
				delta = -delta
			}
			if err == nil && delta > threshold {
				found = append(found, fmt.Sprintf("%s %s %s: %s", pkg, rec[0], unit, rec[5]))
			}
		}
	}
	return found, nil
}

var higherIsBetter = map[string]bool{"B/s": true}

// benchPackages lists the packages under root (as ./ paths relative to it) whose tests declare a benchmark.
func benchPackages(root string) ([]string, error) {
	var pkgs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "tools" || name == "var" || name == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // test files of the repository
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		if dir := "./" + filepath.ToSlash(rel); bytes.Contains(src, []byte("\nfunc Benchmark")) && !slices.Contains(pkgs, dir) {
			pkgs = append(pkgs, dir)
		}
		return nil
	})
	slices.Sort(pkgs)
	return pkgs, err
}
