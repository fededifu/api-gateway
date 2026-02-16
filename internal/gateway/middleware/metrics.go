package middleware

import (
	"net/http"
	"time"

	gw "gateway/internal/gateway"
	"gateway/internal/platform/telemetry"
)

// Metrics returns middleware that records HTTP request metrics.
// Place as the outermost middleware to capture the full request lifecycle.
func Metrics(m *telemetry.GatewayMetrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &gw.StatusWriter{ResponseWriter: w, Code: http.StatusOK}

			next.ServeHTTP(sw, r)

			if m != nil {
				duration := time.Since(start).Seconds()
				m.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, sw.Code, duration)
			}
		})
	}
}
