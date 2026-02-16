package middleware

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"gateway/internal/domain"
	gw "gateway/internal/gateway"
	"gateway/internal/platform/telemetry"
)

// RateLimit returns middleware that enforces per-IP rate limits.
// The metrics parameter is optional; pass nil to skip metric recording.
func RateLimit(limiter gw.RateLimiter, m *telemetry.GatewayMetrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if result := limiter.Allow(ip); !result.Allowed {
				if m != nil {
					m.RecordRateLimitDecision(r.Context(), "ip", "denied")
				}
				writeRateLimitError(w, result.RetryAfter)
				return
			}

			if m != nil {
				m.RecordRateLimitDecision(r.Context(), "ip", "allowed")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	// Use RemoteAddr directly. X-Forwarded-For is client-controlled and
	// must not be trusted without a validated trusted proxy list.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeRateLimitError(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.WriteHeader(http.StatusTooManyRequests)
	if err := json.NewEncoder(w).Encode(domain.ErrorResponse{
		Error:      "rate_limited",
		Message:    "too many requests",
		RetryAfter: retryAfter,
	}); err != nil {
		slog.Error("encoding error response", "error", err)
	}
}
