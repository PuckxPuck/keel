package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// apiSpec is the public api realm's document, which keel gen exports.
const apiSpec = specDir + "/api.openapi.yaml"

// releaseTagPattern keeps deploy and other tags out of the comparison.
const releaseTagPattern = "v[0-9]*"

func runCompat(ctx context.Context, fs *flag.FlagSet, _ []string) error {
	return checkAPICompat(ctx, fs.Output())
}

// checkAPICompat fails on a breaking change to the public API since the latest release tag. The tag's
// document is compared with the working tree's, which keel gen --check keeps equal to the code.
func checkAPICompat(ctx context.Context, out io.Writer) error {
	if _, err := os.Stat(apiSpec); err != nil {
		if _, kit := os.Stat("internal/kit/apikeys"); kit != nil {
			_, err = fmt.Fprintln(out, "skipped: the app has no public api realm")
			return err
		}
		return fmt.Errorf("%s is missing: run keel gen", apiSpec)
	}
	tag, skip, err := latestReleaseTag(ctx, ".")
	if err != nil {
		return err
	}
	if skip != "" {
		_, err = fmt.Fprintln(out, "skipped: "+skip)
		return err
	}
	released, err := gitOutput(ctx, ".", "show", tag+":./"+apiSpec)
	if err != nil {
		_, err = fmt.Fprintf(out, "skipped: %s has no %s\n", tag, apiSpec)
		return err
	}
	file, err := os.CreateTemp("", "keel-api-released-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, err = file.Write(released)
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "comparing %s with %s\n", apiSpec, tag)
	diff := exec.CommandContext(ctx, "go", goTool("oasdiff", "breaking", "--fail-on", "WARN", file.Name(), apiSpec)...) //nolint:gosec // fixed arguments, a temporary file
	diff.Stdout, diff.Stderr = out, os.Stderr
	diff.Env = append(os.Environ(), "CGO_ENABLED=0")
	return diff.Run()
}

// latestReleaseTag is the newest v* tag reachable from HEAD in dir. In an app, keel's own tags (those
// reachable from the commit in .keel-version) do not count. When there is nothing to compare with it
// returns skip, the reason; err is for failures that should stop the run.
func latestReleaseTag(ctx context.Context, dir string) (tag, skip string, err error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", "git is not installed", nil //nolint:nilerr // a missing git is a reason to skip
	}
	if !gitSucceeds(ctx, dir, "rev-parse", "--is-inside-work-tree") {
		return "", "not a git repository", nil
	}
	if !gitSucceeds(ctx, dir, "rev-parse", "--verify", "--quiet", "HEAD^{commit}") {
		return "", "the repository has no commits yet", nil
	}
	describe := []string{"describe", "--tags", "--abbrev=0", "--match", releaseTagPattern}
	keelTags, made, err := keelReleaseTags(ctx, dir)
	if err != nil {
		return "", "", err
	}
	for _, t := range keelTags {
		describe = append(describe, "--exclude", t)
	}
	out, err := gitOutput(ctx, dir, describe...)
	if err == nil {
		return strings.TrimSpace(string(out)), "", nil
	}
	if isShallow(ctx, dir) {
		return "", "", errShallow
	}
	if made {
		return "", "no release tag (" + releaseTagPattern + ") of the app yet; keel's own tags do not count", nil
	}
	return "", "no release tag (" + releaseTagPattern + ") yet", nil
}

var errShallow = errors.New("this is a shallow clone, so release tags may be missing: fetch them (git fetch --unshallow --tags, or fetch-depth: 0 in CI)")

func isShallow(ctx context.Context, dir string) bool {
	out, _ := gitOutput(ctx, dir, "rev-parse", "--is-shallow-repository")
	return strings.TrimSpace(string(out)) == "true"
}

// keelReleaseTags are the v* tags reachable from the keel commit an app was made from; made says dir is
// such an app. A full clone of the app's own remote has none of keel's tags (git push does not send
// them), so there is nothing to exclude; only a shallow clone cannot tell.
func keelReleaseTags(ctx context.Context, dir string) (tags []string, made bool, err error) {
	raw, err := os.ReadFile(filepath.Join(dir, keelVersionFile)) //nolint:gosec // a fixed name in the checkout
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	version := strings.TrimSpace(string(raw))
	if !versionRE.MatchString(version) {
		return nil, true, fmt.Errorf("%s holds %q, which is not a version", keelVersionFile, version)
	}
	if !gitSucceeds(ctx, dir, "rev-parse", "--verify", "--quiet", version+"^{commit}") {
		if isShallow(ctx, dir) {
			return nil, true, errShallow
		}
		return nil, true, nil
	}
	out, err := gitOutput(ctx, dir, "tag", "--list", releaseTagPattern, "--merged", version+"^{commit}")
	if err != nil {
		return nil, true, err
	}
	return strings.Fields(string(out)), true, nil
}

func gitSucceeds(ctx context.Context, dir string, args ...string) bool {
	_, err := gitOutput(ctx, dir, args...)
	return err == nil
}

func gitOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...) //nolint:gosec // fixed subcommands, tags git itself listed
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
