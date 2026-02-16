package middleware

import (
	"log/slog"
	"net/http"
	"time"

	gw "gateway/internal/gateway"
)

// Logging returns a middleware that logs each request using slog.
func Logging(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &gw.StatusWriter{ResponseWriter: w, Code: http.StatusOK}

			next.ServeHTTP(sw, r)

			reqID := gw.RequestIDFromContext(r.Context())
			principal, _ := gw.PrincipalFromContext(r.Context())

			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.Code,
				"duration_ms", float64(time.Since(start).Microseconds())/1000.0,
				"request_id", reqID,
				"principal_id", principal.ID,
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}
