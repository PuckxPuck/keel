package ratelimit

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/clock"
)

var start = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) context.Context {
	return clock.WithWall(context.Background(), clock.Fixed(start.Add(d)))
}

func TestMemory_TokenBucket(t *testing.T) {
	rate := Rate{Limit: 3, Period: time.Minute}
	type hit struct {
		at          time.Duration
		allowed     bool
		remaining   int
		retryAfter  time.Duration
		description string
	}
	steps := []hit{
		{0, true, 2, 0, "a full bucket allows a burst"},
		{0, true, 1, 0, ""},
		{0, true, 0, 0, ""},
		{0, false, 0, 20 * time.Second, "empty: retry when one token is back"},
		{10 * time.Second, false, 0, 10 * time.Second, "half a token is not enough"},
		{20 * time.Second, true, 0, 0, "one token refilled"},
		{10 * time.Minute, true, 2, 0, "refills to capacity, never beyond"},
	}
	m := NewMemory(10)
	for i, s := range steps {
		d, err := m.Take(at(s.at), "k", rate)
		require.NoError(t, err)
		assert.Equal(t, s.allowed, d.Allowed, "step %d %s", i, s.description)
		assert.Equal(t, s.remaining, d.Remaining, "step %d", i)
		assert.Equal(t, s.retryAfter, d.RetryAfter, "step %d", i)
	}
}

func TestMemory_StaysBoundedAndEvicts(t *testing.T) {
	rate := Rate{Limit: 2, Period: time.Minute}
	m := NewMemory(3)

	for i := range 3 {
		_, err := m.Take(at(time.Duration(i)*time.Second), "k"+strconv.Itoa(i), rate)
		require.NoError(t, err)
	}
	_, _ = m.Take(at(3*time.Second), "k0", rate)
	_, _ = m.Take(at(3*time.Second), "k0", rate) // k0 is empty and the most recently used

	_, err := m.Take(at(4*time.Second), "new", rate)
	require.NoError(t, err)
	assert.Equal(t, 3, m.size(), "never more than maxKeys buckets")
	d, _ := m.Take(at(4*time.Second), "k0", rate)
	assert.False(t, d.Allowed, "the least recently used bucket (k1) went, not the busy one")

	for i := range 100 {
		_, _ = m.Take(at(5*time.Minute), "flood"+strconv.Itoa(i), rate)
	}
	assert.Equal(t, 3, m.size())
}
