package telemetry_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/internal/platform/telemetry"
)

func TestSetupAndShutdown(t *testing.T) {
	shutdown, err := telemetry.Setup(context.Background(), "test-service")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestMetricsHandler(t *testing.T) {
	shutdown, err := telemetry.Setup(context.Background(), "test-service")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer shutdown(context.Background())

	handler := telemetry.MetricsHandler()
	if handler == nil {
		t.Fatal("expected non-nil metrics handler")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGatewayMetrics(t *testing.T) {
	shutdown, err := telemetry.Setup(context.Background(), "gateway")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer shutdown(context.Background())

	m, err := telemetry.NewGatewayMetrics()
	if err != nil {
		t.Fatalf("NewGatewayMetrics failed: %v", err)
	}

	// Record some observations
	ctx := context.Background()
	m.RecordHTTPRequest(ctx, "GET", "/v1/vectors", 200, 0.05)
	m.RecordAuthValidation(ctx, "success")
	m.RecordJWKSRefresh(ctx, "success")
	m.RecordRateLimitDecision(ctx, "global", "allowed")
	m.RecordProxyRequest(ctx, "vectordb", 200, 0.1)

	// Verify metrics are accessible via the handler
	handler := telemetry.MetricsHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Body)
	output := string(body)

	expected := []string{
		"gateway_http_requests_total",
		"gateway_http_request_duration_seconds",
		"gateway_auth_validations_total",
		"gateway_jwks_refreshes_total",
		"gateway_ratelimit_decisions_total",
		"gateway_proxy_requests_total",
		"gateway_proxy_duration_seconds",
	}
	for _, metric := range expected {
		if !strings.Contains(output, metric) {
			t.Errorf("metrics output missing %q", metric)
			// Print first 500 chars for debugging
			if len(output) > 500 {
				fmt.Printf("metrics output (first 500 chars): %s\n", output[:500])
			}
		}
	}
}
