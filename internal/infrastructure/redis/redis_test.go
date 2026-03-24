package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSessionCache(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	sc := NewSessionCache(client, 5*time.Minute)
	ctx := context.Background()

	session := &CachedSession{
		SessionID: "s1",
		UserID:    "u1",
		TenantID:  "t1",
	}

	tokenHash := "h1"

	// Set
	if err := sc.Set(ctx, tokenHash, session); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	// Get
	got, err := sc.Get(ctx, tokenHash)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.UserID != session.UserID {
		t.Errorf("expected user_id %s, got %s", session.UserID, got.UserID)
	}

	// Delete
	if err := sc.Delete(ctx, session.UserID, tokenHash); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Get after delete
	_, err = sc.Get(ctx, tokenHash)
	if err == nil {
		t.Error("expected error getting deleted session, got nil")
	}
}

func TestDistributedLock(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	dl := NewDistributedLock(client)
	ctx := context.Background()

	key := "lock:1"

	// Acquire
	ok, err := dl.Acquire(ctx, key, 1*time.Second)
	if err != nil || !ok {
		t.Fatalf("acquire failed: %v, ok: %v", err, ok)
	}

	// Double acquire
	ok, err = dl.Acquire(ctx, key, 1*time.Second)
	if err != nil || ok {
		t.Fatalf("double acquire should fail: %v, ok: %v", err, ok)
	}

	// Release
	if err := dl.Release(ctx, key); err != nil {
		t.Fatalf("release failed: %v", err)
	}

	// Acquire again
	ok, err = dl.Acquire(ctx, key, 1*time.Second)
	if !ok {
		t.Error("expected acquire success after release")
	}
}

func TestCSRFManager(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cm := NewCSRFManager(client, 1*time.Hour)
	ctx := context.Background()

	sessionID := "sess1"

	// Generate
	token, err := cm.Generate(ctx, sessionID)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if token == "" {
		t.Fatal("generated token is empty")
	}

	// Validate success
	ok, err := cm.Validate(ctx, sessionID, token)
	if err != nil || !ok {
		t.Errorf("validation failed: %v, ok: %v", err, ok)
	}

	// Validate failure
	ok, err = cm.Validate(ctx, sessionID, "wrong-token")
	if ok {
		t.Error("expected validation failure for wrong token")
	}

	// Invalidate
	if err := cm.Invalidate(ctx, sessionID); err != nil {
		t.Fatalf("invalidate failed: %v", err)
	}

	// Validate after invalidate
	ok, err = cm.Validate(ctx, sessionID, token)
	if ok {
		t.Error("expected validation failure after invalidation")
	}
}
