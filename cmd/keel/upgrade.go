package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/cli"
)

// keelVersionFile records the keel release an app was made from or last upgraded to (written by keel init).
const keelVersionFile = ".keel-version"

// upgradePaths are what an app takes from keel as diffs; everything else in an app is its own.
var upgradePaths = []string{"internal/kit", "cmd/keel"}

var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)

func upgradeFlags(fs *flag.FlagSet) {
	fs.String("keel", os.Getenv("KEEL_CHECKOUT"), "path to a local keel checkout holding both versions as git tags (default $KEEL_CHECKOUT)")
	fs.Bool("stat", false, "list changed files only")
}

// upgradePathspec is upgradePaths without the kit directories keel had at from that the app in appDir
// removed (keel init drops optional parts), so git apply does not fail on them.
func upgradePathspec(ctx context.Context, checkout, from, appDir string) ([]string, error) {
	out, err := gitOutput(ctx, checkout, "ls-tree", "-d", "-r", "--name-only", from, "--", "internal/kit")
	if err != nil {
		return nil, err
	}
	paths := slices.Clone(upgradePaths)
	var removed []string
	for _, dir := range strings.Fields(string(out)) {
		if slices.ContainsFunc(removed, func(r string) bool { return strings.HasPrefix(dir, r+"/") }) {
			continue
		}
		if _, err := os.Stat(filepath.Join(appDir, dir)); errors.Is(err, fs.ErrNotExist) { //nolint:gosec // dir is a kit directory git listed
			removed = append(removed, dir)
			paths = append(paths, ":(exclude)"+dir)
		}
	}
	return paths, nil
}

// runUpgradeDiff prints `git diff <from> <to> -- internal/kit cmd/keel`, less the kit directories the
// app removed, in a keel checkout, from the version in .keel-version to the one asked for, with keel's
// module path rewritten to the app's.
func runUpgradeDiff(ctx context.Context, fs *flag.FlagSet, args []string) error {
	if len(args) != 1 {
		return cli.Usagef("usage: keel upgrade:diff [--keel <checkout>] <version>")
	}
	to := args[0]
	checkout := fs.Lookup("keel").Value.String()
	if checkout == "" {
		return cli.Usagef("--keel (or KEEL_CHECKOUT) must name a local keel checkout")
	}
	raw, err := os.ReadFile(keelVersionFile)
	if err != nil {
		return fmt.Errorf("read %s (keel init writes it): %w", keelVersionFile, err)
	}
	from := strings.TrimSpace(string(raw))
	for _, v := range []string{from, to} {
		if !versionRE.MatchString(v) {
			return fmt.Errorf("%q is not a version tag", v)
		}
		if err := exec.CommandContext(ctx, "git", "-C", checkout, "rev-parse", "--verify", "--quiet", v+"^{commit}").Run(); err != nil { //nolint:gosec // checked tag, path from a flag
			return fmt.Errorf("%s has no version %s (git fetch --tags there)", checkout, v)
		}
	}
	if from == to {
		return errors.New(".keel-version is already " + to)
	}
	diff := []string{"diff"}
	if fs.Lookup("stat").Value.String() == "true" {
		diff = append(diff, "--stat")
	}
	paths, err := upgradePathspec(ctx, checkout, from, ".")
	if err != nil {
		return err
	}
	keelMod, err := gitOutput(ctx, checkout, "show", to+":go.mod")
	if err != nil {
		return err
	}
	appMod, err := (&tree{root: "."}).modulePath()
	if err != nil {
		return err
	}
	m := modulePathRE.FindSubmatch(keelMod)
	if m == nil {
		return fmt.Errorf("%s:go.mod in %s has no module line", to, checkout)
	}
	patch, err := gitOutput(ctx, checkout, append(append(diff, from, to, "--"), paths...)...)
	if err != nil {
		return err
	}
	_, err = fs.Output().Write(rewriteModulePath(patch, string(m[1]), appMod))
	return err
}

// rewriteModulePath moves keel's module path in a diff to the app's, plain and regex-escaped, so the
// diff applies to an app keel init rewrote.
func rewriteModulePath(src []byte, from, to string) []byte {
	if from == to {
		return src
	}
	for _, f := range [][2]string{{from, to}, {regexp.QuoteMeta(from), regexp.QuoteMeta(to)}} {
		re := regexp.MustCompile(regexp.QuoteMeta(f[0]) + "($|[^A-Za-z0-9_-])")
		src = re.ReplaceAll(src, []byte(strings.ReplaceAll(f[1], "$", "$$")+"$1"))
	}
	return src
}
