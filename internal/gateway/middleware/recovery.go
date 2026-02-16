package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"

	"gateway/internal/domain"
	"gateway/internal/gateway"
)

// Recovery catches panics from downstream handlers and returns a 500 JSON error.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				reqID := gateway.RequestIDFromContext(r.Context())
				slog.Error("panic recovered",
					"error", err,
					"request_id", reqID,
					"stack", string(debug.Stack()),
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				if encErr := json.NewEncoder(w).Encode(domain.ErrorResponse{
					Error:   "internal_error",
					Message: "an unexpected error occurred",
				}); encErr != nil {
					slog.Error("encoding error response", "error", encErr)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}
