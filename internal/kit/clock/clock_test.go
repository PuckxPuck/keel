package clock_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/dates"
)

var pinned = time.Date(2026, 10, 22, 23, 30, 0, 0, time.UTC)

func TestWithFixed_AffectsBusinessOnly(t *testing.T) {
	ctx := clock.WithFixed(context.Background(), pinned)

	assert.Equal(t, pinned, clock.Business(ctx).Now())
	assert.WithinDuration(t, time.Now(), clock.Wall(ctx).Now(), 5*time.Second)
}

func TestWithOffset_AffectsBusinessOnly(t *testing.T) {
	ctx := clock.WithOffset(context.Background(), 48*time.Hour)

	assert.WithinDuration(t, time.Now().Add(48*time.Hour), clock.Business(ctx).Now(), 5*time.Second)
	assert.WithinDuration(t, time.Now(), clock.Wall(ctx).Now(), 5*time.Second)
}

func TestWithOffset_ComposesWithFixed(t *testing.T) {
	ctx := clock.WithOffset(clock.WithFixed(context.Background(), pinned), time.Hour)

	assert.Equal(t, pinned.Add(time.Hour), clock.Business(ctx).Now())
}

func TestWithWall_InjectsATestClock(t *testing.T) {
	ctx := clock.WithWall(context.Background(), clock.Fixed(pinned))

	assert.Equal(t, pinned, clock.Wall(ctx).Now())
	assert.WithinDuration(t, time.Now(), clock.Business(ctx).Now(), 5*time.Second)
}

func TestToday(t *testing.T) {
	ahead := time.FixedZone("UTC+5", 5*3600)
	ctx := clock.WithFixed(context.Background(), pinned)

	tests := []struct {
		name string
		loc  *time.Location
		want dates.Date
	}{
		{"UTC", time.UTC, dates.MustParse("2026-10-22")},
		{"a zone ahead of UTC crosses midnight", ahead, dates.MustParse("2026-10-23")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, clock.Today(ctx, tt.loc))
		})
	}
}
