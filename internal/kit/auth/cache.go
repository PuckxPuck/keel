package auth

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const maxCached = 10000

// principalKey includes the user's access version, which every request reads from the database with
// its session: a change moves the version, so an entry filled before it can never be served after it,
// on this replica or any other.
type principalKey struct {
	user    users.ID
	realm   string
	version int64
	tenant  uuid.UUID
}

// principalCache holds loaded principals for a few seconds, so a burst of requests loads permissions
// once.
type principalCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[principalKey]cached
}

type cached struct {
	p     rbac.Principal
	until time.Time
}

func newPrincipalCache(ttl time.Duration) *principalCache {
	return &principalCache{ttl: ttl, entries: map[principalKey]cached{}}
}

func (c *principalCache) get(k principalKey, now time.Time) (rbac.Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || !now.Before(e.until) {
		return rbac.Principal{}, false
	}
	return e.p, true
}

// forgetUser drops every entry of user (a tenant switch).
func (c *principalCache) forgetUser(user users.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if k.user == user {
			delete(c.entries, k)
		}
	}
}

func (c *principalCache) put(k principalKey, p rbac.Principal, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxCached {
		for key, e := range c.entries {
			if !now.Before(e.until) {
				delete(c.entries, key)
			}
		}
		if len(c.entries) >= maxCached {
			clear(c.entries)
		}
	}
	c.entries[k] = cached{p: p, until: now.Add(c.ttl)}
}
