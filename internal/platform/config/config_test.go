package config_test

import (
	"testing"

	"gateway/internal/platform/config"
)

func TestLoadDefaults(t *testing.T) {
	cfg := config.Load()

	if cfg.GatewayAddr != ":8080" {
		t.Errorf("expected default gateway addr :8080, got %q", cfg.GatewayAddr)
	}
	if cfg.VectorDBURL != "http://localhost:8082" {
		t.Errorf("expected default vectordb URL, got %q", cfg.VectorDBURL)
	}
	if cfg.FileServiceURL != "http://localhost:8083" {
		t.Errorf("expected default fileservice URL, got %q", cfg.FileServiceURL)
	}
	if cfg.JWKSEndpoint != "http://localhost:8081/.well-known/jwks.json" {
		t.Errorf("expected default JWKS endpoint, got %q", cfg.JWKSEndpoint)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.LogLevel)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("GATEWAY_ADDR", ":9090")
	t.Setenv("VECTORDB_URL", "http://vectordb:9092")
	t.Setenv("FILESERVICE_URL", "http://fileservice:9093")
	t.Setenv("JWKS_ENDPOINT", "http://custom:9091/.well-known/jwks.json")
	t.Setenv("LOG_LEVEL", "debug")

	cfg := config.Load()

	if cfg.GatewayAddr != ":9090" {
		t.Errorf("expected :9090, got %q", cfg.GatewayAddr)
	}
	if cfg.VectorDBURL != "http://vectordb:9092" {
		t.Errorf("expected vectordb URL, got %q", cfg.VectorDBURL)
	}
	if cfg.FileServiceURL != "http://fileservice:9093" {
		t.Errorf("expected fileservice URL, got %q", cfg.FileServiceURL)
	}
	if cfg.JWKSEndpoint != "http://custom:9091/.well-known/jwks.json" {
		t.Errorf("expected custom JWKS endpoint, got %q", cfg.JWKSEndpoint)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected 'debug', got %q", cfg.LogLevel)
	}
}

func TestRateLimitDefaults(t *testing.T) {
	cfg := config.Load()

	if cfg.RateLimit.Rate != 100 {
		t.Errorf("expected rate 100, got %f", cfg.RateLimit.Rate)
	}
	if cfg.RateLimit.Burst != 20 {
		t.Errorf("expected burst 20, got %d", cfg.RateLimit.Burst)
	}
}
