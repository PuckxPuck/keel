package cli

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscalate_SecondSignalExitsAfterTheFirstCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 2)
	exits := make(chan int, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		escalate(ctx, cancel, sigs, make(chan struct{}), func(code int) { exits <- code })
	}()

	sigs <- os.Interrupt
	<-ctx.Done()
	assert.Empty(t, exits, "the first signal only cancels")

	sigs <- os.Interrupt
	<-done
	assert.Equal(t, exitInterrupted, <-exits)
}
