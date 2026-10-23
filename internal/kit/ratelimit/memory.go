package ratelimit

import (
	"context"
	"hash/maphash"
	"math"
	"sync"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
)

// Memory is a token-bucket store holding at most maxKeys buckets, spread over locked shards.
type Memory struct {
	seed     maphash.Seed
	shards   []memShard
	perShard int
}

type memShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
	period time.Duration
}

const keysPerShard = 256

func NewMemory(maxKeys int) *Memory {
	maxKeys = max(1, maxKeys)
	n := min(64, max(1, maxKeys/keysPerShard))
	m := &Memory{seed: maphash.MakeSeed(), shards: make([]memShard, n), perShard: maxKeys / n}
	for i := range m.shards {
		m.shards[i].buckets = map[string]*bucket{}
	}
	return m
}

func (m *Memory) Take(ctx context.Context, key string, rate Rate) (Decision, error) {
	now := clock.Wall(ctx).Now()
	s := &m.shards[maphash.String(m.seed, key)%uint64(len(m.shards))]
	s.mu.Lock()
	defer s.mu.Unlock()

	capacity := float64(rate.Limit)
	perSecond := capacity / rate.Period.Seconds()
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) >= m.perShard {
			s.evict(now)
		}
		b = &bucket{tokens: capacity, last: now, period: rate.Period}
		s.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(capacity, b.tokens+elapsed*perSecond)
	}
	b.last, b.period = now, rate.Period

	d := Decision{Limit: rate.Limit, Window: rate.Period}
	if b.tokens >= 1 {
		b.tokens--
		d.Allowed = true
		d.Remaining = int(b.tokens)
		d.Reset = seconds((capacity - b.tokens) / perSecond)
		return d, nil
	}
	d.RetryAfter = seconds((1 - b.tokens) / perSecond)
	d.Reset = d.RetryAfter
	return d, nil
}

// evictSample bounds the work of evict at a large maxKeys; map order is random, so it is a sample.
const evictSample = 64

// evict drops buckets that have refilled (forgetting them changes nothing), and when none has, the
// least recently used one, looking at a sample of the shard.
func (s *memShard) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	dropped := false
	seen := 0
	for k, b := range s.buckets {
		if seen++; seen > evictSample {
			break
		}
		if now.Sub(b.last) >= b.period {
			delete(s.buckets, k)
			dropped = true
			continue
		}
		if oldestKey == "" || b.last.Before(oldest) {
			oldestKey, oldest = k, b.last
		}
	}
	if !dropped && oldestKey != "" {
		delete(s.buckets, oldestKey)
	}
}

func (m *Memory) size() int {
	n := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		n += len(s.buckets)
		s.mu.Unlock()
	}
	return n
}

func seconds(s float64) time.Duration {
	return time.Duration(math.Ceil(s)) * time.Second
}
