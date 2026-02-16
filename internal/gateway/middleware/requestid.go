package middleware

import (
	"net/http"

	"github.com/google/uuid"

	"gateway/internal/gateway"
)

// RequestID assigns a unique request ID to each request.
// If the incoming request already has an X-Request-ID header, it is preserved.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.New().String()
		}
		ctx := gateway.ContextWithRequestID(r.Context(), id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
