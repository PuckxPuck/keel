//go:build deploytest

package app

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// The deploy test's hold route answers only after its slot was told to stop, so the request spans the
// slot's retirement: a stop that cut in-flight requests would fail it.
const (
	holdAfterStop = 2 * time.Second
	holdAtMost    = 7 * time.Second
)

var stopping = sync.OnceValue(func() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		<-sig
		close(done)
	}()
	return done
})

func init() {
	taggedOperations = append(taggedOperations, func(api huma.API) {
		httpx.Register(api, huma.Operation{OperationID: "deployTestHold", Method: http.MethodGet, Path: "/deploytest/hold", Tags: []string{"deploytest"}},
			hold, rbac.Public(), ratelimit.Class(ratelimit.ClassHealth))
	})
	stopping()
}

type held struct {
	Retired bool `json:"retired"`
}

func hold(ctx context.Context, _ *struct{}) (*httpx.One[held], error) {
	select {
	case <-stopping():
		time.Sleep(holdAfterStop)
		return httpx.OneOf(held{Retired: true}), nil
	case <-time.After(holdAtMost):
		return httpx.OneOf(held{Retired: false}), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
