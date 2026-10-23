package app

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// Module is what a feature package under internal/modules gives the app. Its constructor takes what it
// uses from the wiring; Permissions must not depend on that, since catalogues are built before wiring.
type Module interface {
	// Permissions are the module's catalogue entries on realm; the tenant realm's admin role holds them.
	Permissions(realm string) []rbac.Perm
	// Register declares the module's operations on realm's API.
	Register(realm string, api huma.API)
	// Mapper turns the module's domain errors into problems.
	Mapper(err error) (*problem.Problem, bool)
	// Jobs registers the module's job kinds and schedules on the queue.
	Jobs(q *jobs.Queue)
	Commands(open Opener) []cli.Command
}

// Opener opens the database for a module's command; done closes it. It never carries the operator pool.
type Opener = func(ctx context.Context) (d *db.DB, done func(), err error)

// OperatorModule is a module with commands that work across tenants on the operator pool (D29). Only
// the tenancy part offers them; a build without it leaves them out.
type OperatorModule interface {
	OperatorCommands(open OperatorOpener) []cli.Command
}

// OperatorOpener opens the database and the operator pool for an operator command; done closes both.
type OperatorOpener = func(ctx context.Context) (d *db.DB, operator *db.OperatorAccess, done func(), err error)

// modules are mounted in this order, so a module comes after those it uses. keel make:module adds to it.
func modules(_ *wiring) []Module {
	return []Module{}
}

// appModules are keel's example module, when kept, then the app's own.
func appModules(w *wiring) []Module {
	return append(notesModules(w), modules(w)...)
}

// extraModules are mounted after those modules returns; the package's tests use it.
var extraModules func(w *wiring) []Module

// mounted are the module instances one wiring mounts.
func mounted(w *wiring) []Module {
	list := appModules(w)
	if extraModules != nil {
		list = append(list, extraModules(w)...)
	}
	return list
}

// appCommands are the commands keel make:command wrote into this package.
func appCommands(_ []string) []cli.Command {
	return []cli.Command{}
}

// withModules adds each mounted module's operations to the realms in ops.
func withModules(w *wiring, ops map[string][]func(huma.API)) map[string][]func(huma.API) {
	for name := range ops {
		for _, m := range w.modules {
			ops[name] = append(ops[name], func(api huma.API) { m.Register(name, api) })
		}
	}
	return ops
}

func modulePermissions(realm string) []rbac.Perm {
	var out []rbac.Perm
	for _, m := range appModules(&wiring{}) {
		out = append(out, m.Permissions(realm)...)
	}
	return out
}

func moduleCodes(realm string) []rbac.Code { return permCodes(modulePermissions(realm)) }

func permCodes(perms []rbac.Perm) []rbac.Code {
	out := make([]rbac.Code, len(perms))
	for i, p := range perms {
		out[i] = p.Code
	}
	return out
}

// ModuleCommands are the modules' commands and those keel make:command wrote, listed beside Commands.
func ModuleCommands(environ []string) []cli.Command {
	open := func(ctx context.Context) (*db.DB, func(), error) {
		_, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return nil, nil, err
		}
		return deps.DB, func() { _ = deps.DB.Close() }, nil
	}
	list := appModules(&wiring{})
	var out []cli.Command
	for _, m := range list {
		out = append(out, m.Commands(open)...)
	}
	out = append(out, operatorModuleCommands(environ, list)...)
	return append(out, appCommands(environ)...)
}
