package middleware_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/internal/gateway/middleware"
)

func TestLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := middleware.Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Parse the log output
	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("parsing log output: %v\nraw: %s", err, buf.String())
	}

	if logEntry["method"] != "GET" {
		t.Errorf("expected method GET, got %v", logEntry["method"])
	}
	if logEntry["path"] != "/test" {
		t.Errorf("expected path /test, got %v", logEntry["path"])
	}
	// status should be logged as a number
	status, ok := logEntry["status"].(float64)
	if !ok || int(status) != 200 {
		t.Errorf("expected status 200, got %v", logEntry["status"])
	}
	// duration should be present
	if _, ok := logEntry["duration_ms"]; !ok {
		t.Error("expected duration_ms in log output")
	}
}
