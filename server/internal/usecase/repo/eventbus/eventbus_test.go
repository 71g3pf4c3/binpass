package eventbus

import (
	"context"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublishSubscribe(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := b.Subscribe(ctx, "user1")
	b.Publish("user1", entity.ChangeEvent{Generation: 5})

	select {
	case ev := <-ch:
		assert.Equal(t, uint64(5), ev.Generation)
	case <-time.After(time.Second):
		t.Fatal("expected event")
	}
}

func TestUnsubscribeOnCancel(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	ch := b.Subscribe(ctx, "user1")
	cancel()

	// Channel closes after cancellation.
	select {
	case _, ok := <-ch:
		assert.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("expected channel close")
	}
}

func TestPublishNoSubscribersIsNoop(t *testing.T) {
	b := New()
	require.NotPanics(t, func() {
		b.Publish("nobody", entity.ChangeEvent{Generation: 1})
	})
}

func TestIsolationBetweenUsers(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chA := b.Subscribe(ctx, "a")
	b.Publish("b", entity.ChangeEvent{Generation: 1})

	select {
	case <-chA:
		t.Fatal("user a must not receive user b events")
	case <-time.After(100 * time.Millisecond):
	}
}
