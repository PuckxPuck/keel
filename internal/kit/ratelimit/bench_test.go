package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

// Every request takes from the in-memory buckets, from many goroutines over many keys.
func BenchmarkMemoryTake(b *testing.B) {
	m := NewMemory(100_000)
	rate := Rate{Limit: 1_000_000, Period: time.Minute}
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = "ip:198.51.100." + strconv.Itoa(i)
	}
	ctx := at(0)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := m.Take(ctx, keys[i%len(keys)], rate); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
}
