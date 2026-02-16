package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/internal/gateway/middleware"
)

func TestMaxBodySize(t *testing.T) {
	const limit int64 = 16

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{
			name:       "body within limit",
			method:     http.MethodPost,
			body:       "hello",
			wantStatus: http.StatusOK,
		},
		{
			name:       "body exceeds limit",
			method:     http.MethodPost,
			body:       strings.Repeat("x", int(limit)+1),
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "exact boundary",
			method:     http.MethodPost,
			body:       strings.Repeat("x", int(limit)),
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty body",
			method:     http.MethodPost,
			body:       "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "no body GET request",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := io.ReadAll(r.Body)
				if err != nil {
					// MaxBytesReader triggers http.MaxBytesError on read
					http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := middleware.MaxBodySize(limit)(inner)

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/v1/vectors", body)
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}
