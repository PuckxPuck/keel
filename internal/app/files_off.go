//go:build nofiles

package app

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

type (
	FilesConfig struct{}
	filesWiring struct{}
)

func (w *wiring) openFiles(context.Context, Config, Deps) error { return nil }

func (w *wiring) filesMaintenance() {}

func (w *wiring) registerFiles(huma.API) {}

func checkUploadNeeds(*rbac.Catalogue) error { return nil }

func filesMapper(error) (*problem.Problem, bool) { return nil, false }

func filesParts(Config) []string { return nil }

func filesChecks(context.Context, Config) []Check { return nil }
