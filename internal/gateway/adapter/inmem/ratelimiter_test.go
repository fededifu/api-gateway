package inmem_test

import (
	"sync"
	"testing"
	"time"

	"gateway/internal/gateway/adapter/inmem"
)

func TestTokenBucketAllowsBurst(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(10, 5, clock) // 10/sec rate, burst of 5

	// Should allow burst of 5
	for i := range 5 {
		result := rl.Allow("test-key")
		if !result.Allowed {
			t.Errorf("request %d should be allowed within burst", i)
		}
	}

	// 6th request should be denied
	result := rl.Allow("test-key")
	if result.Allowed {
		t.Error("request 6 should be denied (burst exhausted)")
	}
	if result.RetryAfter <= 0 {
		t.Error("expected positive RetryAfter")
	}
}

func TestTokenBucketRefills(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(10, 2, clock) // 10/sec rate, burst of 2

	// Exhaust burst
	rl.Allow("key")
	rl.Allow("key")
	result := rl.Allow("key")
	if result.Allowed {
		t.Error("should be denied after burst")
	}

	// Advance time by 200ms → 2 tokens refilled (10/sec * 0.2s = 2)
	now = now.Add(200 * time.Millisecond)

	result = rl.Allow("key")
	if !result.Allowed {
		t.Error("should be allowed after refill")
	}
}

func TestTokenBucketSeparateKeys(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(10, 1, clock)

	// Exhaust key1
	rl.Allow("key1")
	result := rl.Allow("key1")
	if result.Allowed {
		t.Error("key1 should be denied")
	}

	// key2 should still work
	result = rl.Allow("key2")
	if !result.Allowed {
		t.Error("key2 should be allowed (separate bucket)")
	}
}

func TestTokenBucketDoesNotExceedBurst(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(10, 3, clock)

	// Use 1 token
	rl.Allow("key")

	// Advance time by 1 second (would refill 10 tokens, but cap at burst=3)
	now = now.Add(1 * time.Second)

	// Should get at most 3 (burst) allowed
	allowed := 0
	for range 10 {
		if rl.Allow("key").Allowed {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("expected 3 allowed (burst cap), got %d", allowed)
	}
}

func TestTokenBucketConcurrentAccess(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(100, 10, clock) // burst of 10

	var wg sync.WaitGroup
	results := make([]bool, 100)

	// Hammer same key from many goroutines
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = rl.Allow("same-key").Allowed
		}(i)
	}
	wg.Wait()

	allowed := 0
	for _, ok := range results {
		if ok {
			allowed++
		}
	}

	// Should allow exactly burst amount (10), not more
	if allowed != 10 {
		t.Errorf("concurrent access: expected 10 allowed, got %d", allowed)
	}
}

func TestTokenBucketConcurrentDifferentKeys(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(100, 1, clock) // burst of 1 per key

	var wg sync.WaitGroup
	allowed := make([]bool, 50)

	// Each goroutine uses a unique key — all should be allowed
	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key-" + time.Duration(idx).String()
			allowed[idx] = rl.Allow(key).Allowed
		}(i)
	}
	wg.Wait()

	for i, ok := range allowed {
		if !ok {
			t.Errorf("unique key %d should be allowed", i)
		}
	}
}

func TestTokenBucketConcurrentCleanup(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(100, 5, clock)

	// Create some buckets
	for i := range 20 {
		key := "key-" + time.Duration(i).String()
		rl.Allow(key)
	}

	// Advance time past stale threshold
	now = now.Add(11 * time.Minute)

	// Run Allow and Cleanup concurrently — should not race
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			rl.Allow("concurrent-key")
		}()
		go func() {
			defer wg.Done()
			rl.Cleanup()
		}()
	}
	wg.Wait()
}

func TestTokenBucketCleanup(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(10, 5, clock)

	// Create some buckets
	rl.Allow("key1")
	rl.Allow("key2")
	rl.Allow("key3")

	if rl.BucketCount() != 3 {
		t.Errorf("expected 3 buckets, got %d", rl.BucketCount())
	}

	// Advance time past stale threshold (default 10 minutes)
	now = now.Add(11 * time.Minute)

	rl.Cleanup()

	if rl.BucketCount() != 0 {
		t.Errorf("expected 0 buckets after cleanup, got %d", rl.BucketCount())
	}
}
