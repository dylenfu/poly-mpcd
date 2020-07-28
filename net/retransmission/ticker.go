package retransmission

import (
	"context"
	"sync"
	"time"
)

// Ticker controls the frequence of retransmission
type Ticker struct {
	ticks         <-chan uint64
	handlersMutex sync.Mutex
	handlers      map[context.Context]func()
}

// NewTicker creates and starts a new ticker for the provider channel.
// for each item read from the channel, new ticker is triggered. all handlers
// are unregistered and ticker is stopped when the provider channel get closed.
func NewTicker(ticks <-chan uint64) *Ticker {
	ticker := &Ticker{
		ticks:    ticks,
		handlers: make(map[context.Context]func()),
	}

	go ticker.start()
	return ticker
}

// NewTimeTicker is a convenience function allowing to create time-based
// retransmission.Ticker for the provided duration. When the provided context is
// done, all handlers are unregistered and retransmission.Ticker is stopped.
func NewTimeTicker(ctx context.Context, duration time.Duration) *Ticker {
	ticks := make(chan uint64)
	timeTicker := time.NewTicker(duration)

	// pipe ticks from time ticker
	go func() {
		for {
			select {
			case tick := <-timeTicker.C:
				ticks <- uint64(tick.Unix())

			case <-ctx.Done():
				timeTicker.Stop()
				close(ticks)
				return
			}
		}
	}()

	return NewTicker(ticks)
}

func (t *Ticker) start() {
	for range t.ticks {
		t.handlersMutex.Lock()

		for ctx, handler := range t.handlers {
			if ctx.Err() != nil {
				delete(t.handlers, ctx)
				continue
			}

			handler()
		}

		t.handlersMutex.Unlock()
	}

	for ctx := range t.handlers {
		delete(t.handlers, ctx)
	}
}

func (t *Ticker) onTick(ctx context.Context, handler func()) {
	t.handlersMutex.Lock()
	t.handlers[ctx] = handler
	t.handlersMutex.Unlock()
}
