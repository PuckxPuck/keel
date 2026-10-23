package main

import "github.com/PuckxPuck/keel/internal/kit/cli"

func main() {
	cli.App{
		Name:    "keel",
		Summary: "development tool",
		Commands: append([]cli.Command{
			{Name: "check", Summary: "Run everything CI runs, stopping at the first failure", Run: runCheck},
			{Name: "tidy", Summary: "Fail if go mod tidy would change go.mod or go.sum", Run: runTidy},
			{Name: "lint", Summary: "Check formatting, run golangci-lint and go vet", Run: runLint},
			{Name: "vuln", Summary: "Run govulncheck", Run: runVuln},
			{Name: "test", Summary: "Run tests with the race detector", Flags: testFlags, Run: runTest},
			{Name: "fmt", Summary: "Format code with golangci-lint fmt", Run: runFmt},
			{Name: "gen", Summary: "Regenerate the Jet types in internal/dbgen and the OpenAPI documents in spec", Flags: genFlags, Run: runGen},
			{Name: "compat", Summary: "Fail on a breaking change to the public API since the latest release tag", Run: runCompat},
			{Name: "bench", Summary: "Run the benchmarks and compare them with a saved baseline", Flags: benchFlags, Run: runBench},
			{Name: "init", Summary: "Make a new app from keel: module path, name, database and optional parts", Flags: initFlags, Run: runInit},
			{Name: "upgrade:diff", Summary: "Show the internal/kit and cmd/keel changes between .keel-version and a newer keel (<version>)", Flags: upgradeFlags, Run: runUpgradeDiff},
		}, makeCommands()...),
	}.Main()
}
