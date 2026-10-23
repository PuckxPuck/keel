package app

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// publicSince is when keel's first operations joined the public API.
const publicSince = "2026-10-22"

type Pong struct {
	Message string `json:"message" example:"pong"`
}

func registerPing(api huma.API) {
	httpx.Register(api, huma.Operation{
		OperationID: "ping",
		Method:      http.MethodGet,
		Path:        "/ping",
		Summary:     "Check that the API answers",
		Tags:        []string{"system"},
	}, func(context.Context, *struct{}) (*httpx.One[Pong], error) {
		return httpx.OneOf(Pong{Message: "pong"}), nil
	}, rbac.Public(), ratelimit.Class(ratelimit.ClassAPIRead), httpx.Public(publicSince))
}
