package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// ShutdownFunc releases telemetry resources.
type ShutdownFunc func(ctx context.Context) error

// Setup initializes OpenTelemetry with a Prometheus exporter.
// Returns a shutdown function that must be called on exit.
func Setup(ctx context.Context, serviceName string) (ShutdownFunc, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	return provider.Shutdown, nil
}

// MetricsHandler returns an http.Handler that serves Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// GatewayMetrics holds all OTel instruments for the gateway.
type GatewayMetrics struct {
	httpRequestsTotal        otelmetric.Int64Counter
	httpRequestDuration      otelmetric.Float64Histogram
	authValidationsTotal     otelmetric.Int64Counter
	jwksRefreshesTotal       otelmetric.Int64Counter
	rateLimitDecisionsTotal  otelmetric.Int64Counter
	proxyRequestsTotal       otelmetric.Int64Counter
	proxyDuration            otelmetric.Float64Histogram
}

// NewGatewayMetrics creates and registers all gateway metrics.
func NewGatewayMetrics() (*GatewayMetrics, error) {
	meter := otel.Meter("gateway")
	m := &GatewayMetrics{}
	var err error

	latencyBuckets := otelmetric.WithExplicitBucketBoundaries(
		0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
	)

	if m.httpRequestsTotal, err = meter.Int64Counter("gateway_http_requests_total",
		otelmetric.WithDescription("Total HTTP requests")); err != nil {
		return nil, fmt.Errorf("creating http_requests_total: %w", err)
	}
	if m.httpRequestDuration, err = meter.Float64Histogram("gateway_http_request_duration_seconds",
		otelmetric.WithDescription("HTTP request duration"), latencyBuckets); err != nil {
		return nil, fmt.Errorf("creating http_request_duration: %w", err)
	}
	if m.authValidationsTotal, err = meter.Int64Counter("gateway_auth_validations_total",
		otelmetric.WithDescription("Total auth validations")); err != nil {
		return nil, fmt.Errorf("creating auth_validations_total: %w", err)
	}
	if m.jwksRefreshesTotal, err = meter.Int64Counter("gateway_jwks_refreshes_total",
		otelmetric.WithDescription("Total JWKS refreshes")); err != nil {
		return nil, fmt.Errorf("creating jwks_refreshes_total: %w", err)
	}
	if m.rateLimitDecisionsTotal, err = meter.Int64Counter("gateway_ratelimit_decisions_total",
		otelmetric.WithDescription("Total rate limit decisions")); err != nil {
		return nil, fmt.Errorf("creating ratelimit_decisions_total: %w", err)
	}
	if m.proxyRequestsTotal, err = meter.Int64Counter("gateway_proxy_requests_total",
		otelmetric.WithDescription("Total proxy requests")); err != nil {
		return nil, fmt.Errorf("creating proxy_requests_total: %w", err)
	}
	if m.proxyDuration, err = meter.Float64Histogram("gateway_proxy_duration_seconds",
		otelmetric.WithDescription("Proxy request duration"), latencyBuckets); err != nil {
		return nil, fmt.Errorf("creating proxy_duration: %w", err)
	}

	return m, nil
}

// RecordHTTPRequest records an HTTP request metric.
func (m *GatewayMetrics) RecordHTTPRequest(ctx context.Context, method, path string, status int, durationSec float64) {
	attrs := otelmetric.WithAttributes(
		methodAttr(method),
		pathAttr(path),
		statusAttr(status),
	)
	m.httpRequestsTotal.Add(ctx, 1, attrs)
	m.httpRequestDuration.Record(ctx, durationSec, attrs)
}

// RecordAuthValidation records an auth validation result.
func (m *GatewayMetrics) RecordAuthValidation(ctx context.Context, result string) {
	m.authValidationsTotal.Add(ctx, 1, otelmetric.WithAttributes(resultAttr(result)))
}

// RecordJWKSRefresh records a JWKS refresh attempt.
func (m *GatewayMetrics) RecordJWKSRefresh(ctx context.Context, result string) {
	m.jwksRefreshesTotal.Add(ctx, 1, otelmetric.WithAttributes(resultAttr(result)))
}

// RecordRateLimitDecision records a rate limit decision.
func (m *GatewayMetrics) RecordRateLimitDecision(ctx context.Context, layer, result string) {
	m.rateLimitDecisionsTotal.Add(ctx, 1, otelmetric.WithAttributes(
		layerAttr(layer),
		resultAttr(result),
	))
}

// RecordProxyRequest records a proxied request to a backend.
func (m *GatewayMetrics) RecordProxyRequest(ctx context.Context, backend string, status int, durationSec float64) {
	attrs := otelmetric.WithAttributes(
		backendAttr(backend),
		statusAttr(status),
	)
	m.proxyRequestsTotal.Add(ctx, 1, attrs)
	m.proxyDuration.Record(ctx, durationSec, attrs)
}
