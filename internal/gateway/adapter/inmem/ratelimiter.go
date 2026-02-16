package inmem

import (
	"math"
	"sync"
	"time"

	"gateway/internal/gateway"
)

const staleThreshold = 10 * time.Minute

// RateLimiter implements a token bucket rate limiter with separate buckets per key.
type RateLimiter struct {
	rate  float64       // tokens per second
	burst int           // max tokens (bucket capacity)
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter creates a rate limiter.
// rate is tokens per second, burst is the maximum bucket capacity.
// clock is injectable for deterministic testing.
func NewRateLimiter(rate float64, burst int, clock func() time.Time) *RateLimiter {
	return &RateLimiter{
		rate:    rate,
		burst:   burst,
		now:     clock,
		buckets: make(map[string]*bucket),
	}
}

// Allow checks whether a request identified by key should be allowed.
func (rl *RateLimiter) Allow(key string) gateway.RateLimitResult {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, exists := rl.buckets[key]
	if !exists {
		b = &bucket{
			tokens:   float64(rl.burst),
			lastSeen: now,
		}
		rl.buckets[key] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return gateway.RateLimitResult{Allowed: true}
	}

	// Calculate retry-after: time until next token
	deficit := 1.0 - b.tokens
	retryAfter := max(int(math.Ceil(deficit/rl.rate)), 1)

	return gateway.RateLimitResult{
		Allowed:    false,
		RetryAfter: retryAfter,
	}
}

// Cleanup removes stale buckets that haven't been seen recently.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	for key, b := range rl.buckets {
		if now.Sub(b.lastSeen) > staleThreshold {
			delete(rl.buckets, key)
		}
	}
}

// BucketCount returns the number of active buckets (for testing).
func (rl *RateLimiter) BucketCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}
