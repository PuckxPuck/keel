package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

const (
	LivePath  = "/livez"
	ReadyPath = "/readyz"

	resultTTL    = 5 * time.Second
	checkTimeout = 3 * time.Second
)

type Check struct {
	Name string
	Run  func(ctx context.Context) error
}

type Health struct {
	checks   []*cachedCheck
	started  atomic.Bool
	draining atomic.Bool
}

func New(checks ...Check) *Health {
	h := &Health{}
	for _, c := range checks {
		h.checks = append(h.checks, &cachedCheck{Check: c})
	}
	return h
}

// Ready opens the startup gate: /readyz fails until the app has finished starting.
func (h *Health) Ready() { h.started.Store(true) }

// Drain makes /readyz fail from now on, so the proxy moves traffic away before shutdown.
func (h *Health) Drain() { h.draining.Store(true) }

func (h *Health) Mount(r chi.Router) {
	r.Get(LivePath, h.live)
	r.Head(LivePath, h.live)
	r.Get(ReadyPath, h.ready)
	r.Head(ReadyPath, h.ready)
}

func (h *Health) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "ok"}})
}

func (h *Health) ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case h.draining.Load():
		problem.Write(w, r, problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "shutting down"))
		return
	case !h.started.Load():
		problem.Write(w, r, problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "starting"))
		return
	}
	statuses := make(map[string]string, len(h.checks))
	failing := false
	for _, c := range h.checks {
		if err := c.result(r.Context()); err != nil {
			statuses[c.Name], failing = "failing", true
			continue
		}
		statuses[c.Name] = "ok"
	}
	if failing {
		p := problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "a dependency is not ready")
		p.Extensions = map[string]any{"checks": statuses}
		problem.Write(w, r, p)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": "ready", "checks": statuses}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a failed write means the client is gone
}

type flight struct {
	done chan struct{}
	err  error
}

// cachedCheck keeps a check's last result for resultTTL and runs it at most once at a time.
// The lock is never held while the check runs, so a slow dependency cannot block readers.
type cachedCheck struct {
	Check
	mu     sync.Mutex
	at     time.Time
	err    error
	flight *flight
}

func (c *cachedCheck) run(ctx context.Context) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("check %s panicked: %v", c.Name, v)
		}
	}()
	return c.Run(ctx)
}

func (c *cachedCheck) result(ctx context.Context) error {
	now := clock.Wall(ctx).Now()

	c.mu.Lock()
	if !c.at.IsZero() && now.Sub(c.at) < resultTTL {
		err := c.err
		c.mu.Unlock()
		return err
	}
	if f := c.flight; f != nil {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	c.flight = f
	c.mu.Unlock()

	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), checkTimeout)
	f.err = c.run(runCtx)
	cancel()

	c.mu.Lock()
	c.at, c.err, c.flight = clock.Wall(ctx).Now(), f.err, nil
	c.mu.Unlock()
	close(f.done)
	return f.err
}
