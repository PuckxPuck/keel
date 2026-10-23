package main

import (
	"os"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/cli"
)

func main() {
	cli.App{
		Name:     app.Name,
		Summary:  "production binary",
		Commands: append(app.Commands(os.Environ()), app.ModuleCommands(os.Environ())...),
	}.Main()
}
