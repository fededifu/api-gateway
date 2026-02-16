package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/internal/gateway"
	"gateway/internal/gateway/middleware"
)

func TestRequestIDSetsHeader(t *testing.T) {
	var capturedID string
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = gateway.RequestIDFromContext(r.Context())
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if capturedID == "" {
		t.Error("expected request ID in context")
	}

	// Should also be set as response header
	if rec.Header().Get("X-Request-ID") != capturedID {
		t.Errorf("expected X-Request-ID header %q, got %q", capturedID, rec.Header().Get("X-Request-ID"))
	}
}

func TestRequestIDPreservesExisting(t *testing.T) {
	var capturedID string
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = gateway.RequestIDFromContext(r.Context())
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "existing-id")
	handler.ServeHTTP(rec, req)

	if capturedID != "existing-id" {
		t.Errorf("expected preserved request ID 'existing-id', got %q", capturedID)
	}
}
