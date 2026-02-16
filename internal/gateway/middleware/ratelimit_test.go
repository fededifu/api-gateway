package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gateway/internal/domain"
	"gateway/internal/gateway/adapter/inmem"
	"gateway/internal/gateway/middleware"
)

func TestRateLimitAllowsWithinBurst(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(100, 3, clock)

	handler := middleware.RateLimit(rl, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	for i := range 3 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitDeniesWhenBurstExhausted(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(100, 2, clock)

	handler := middleware.RateLimit(rl, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Exhaust burst
	for range 2 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		handler.ServeHTTP(rec, req)
	}

	// Third request should be rate limited
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}

	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}

	var errResp domain.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != "rate_limited" {
		t.Errorf("expected error 'rate_limited', got %q", errResp.Error)
	}
}

func TestRateLimitDifferentIPsIndependent(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	rl := inmem.NewRateLimiter(100, 1, clock)

	handler := middleware.RateLimit(rl, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Exhaust IP1
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	handler.ServeHTTP(rec1, req1)

	// IP1 is now exhausted
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("IP1 second request: expected 429, got %d", rec2.Code)
	}

	// IP2 should still work
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "10.0.0.2:1234"
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("IP2 should be allowed, got %d", rec3.Code)
	}
}
