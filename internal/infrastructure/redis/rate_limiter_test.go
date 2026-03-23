package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRateLimiter(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	rl := NewRateLimiter(client)
	ctx := context.Background()
	cfg := RateLimitConfig{
		Key:      "test:limit",
		MaxCount: 2,
		Window:   1 * time.Second,
	}

	// First hit
	res, err := rl.Check(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Error("expected allowed=true for first hit")
	}
	if res.Remaining != 1 {
		t.Errorf("expected remaining=1, got %d", res.Remaining)
	}

	// Second hit
	res, err = rl.Check(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Error("expected allowed=true for second hit")
	}
	if res.Remaining != 0 {
		t.Errorf("expected remaining=0, got %d", res.Remaining)
	}

	// Third hit (exceed limit)
	res, err = rl.Check(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Error("expected allowed=false for third hit")
	}

	// Reset
	if err := rl.Reset(ctx, cfg.Key); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	res, err = rl.Check(ctx, cfg)
	if !res.Allowed {
		t.Error("expected allowed=true after reset")
	}
}
