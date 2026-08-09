// Package eventbus provides an in-process implementation of usecase.EventBus
// for fanning vault change events out to a user's connected devices.
package eventbus

import (
	"context"
	"sync"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
)

// InMemory is a per-process EventBus. It is sufficient for a single-instance
// deployment; a multi-instance setup would back this with Redis/NATS.
type InMemory struct {
	// mu guards subs.
	mu sync.Mutex
	// subs maps user ID to that user's subscriber channels.
	subs map[string]map[chan entity.ChangeEvent]struct{}
}

// New returns an empty in-memory event bus.
func New() *InMemory {
	return &InMemory{subs: make(map[string]map[chan entity.ChangeEvent]struct{})}
}

// Publish delivers ev to all current subscribers of userID, dropping the
// event for any slow subscriber rather than blocking.
func (b *InMemory) Publish(userID string, ev entity.ChangeEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[userID] {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribe returns a channel of change events for userID. The subscription
// is removed and the channel closed when ctx is cancelled.
func (b *InMemory) Subscribe(ctx context.Context, userID string) <-chan entity.ChangeEvent {
	ch := make(chan entity.ChangeEvent, 8)

	b.mu.Lock()
	if b.subs[userID] == nil {
		b.subs[userID] = make(map[chan entity.ChangeEvent]struct{})
	}
	b.subs[userID][ch] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.subs[userID], ch)
		if len(b.subs[userID]) == 0 {
			delete(b.subs, userID)
		}
		b.mu.Unlock()
		close(ch)
	}()
	return ch
}
