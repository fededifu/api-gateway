package config

import (
	"log/slog"
	"os"
	"strconv"
)

// Config holds all configuration for the gateway system.
type Config struct {
	GatewayAddr    string
	VectorDBURL    string // Full URL for proxy target (e.g. http://vectordb:8082)
	FileServiceURL string // Full URL for proxy target (e.g. http://fileservice:8083)
	IdentityURL    string // Full URL for identity service proxy target (e.g. http://identity:8081)
	JWKSEndpoint   string
	LogLevel       string
	RateLimit      RateLimitConfig
}

// RateLimitConfig holds token bucket parameters for per-IP rate limiting.
type RateLimitConfig struct {
	Rate  float64
	Burst int
}

// Load reads configuration from environment variables, falling back to defaults.
func Load() Config {
	return Config{
		GatewayAddr:    envOr("GATEWAY_ADDR", ":8080"),
		VectorDBURL:    envOr("VECTORDB_URL", "http://localhost:8082"),
		FileServiceURL: envOr("FILESERVICE_URL", "http://localhost:8083"),
		IdentityURL:    envOr("IDENTITY_URL", "http://localhost:8081"),
		JWKSEndpoint:   envOr("JWKS_ENDPOINT", "http://localhost:8081/.well-known/jwks.json"),
		LogLevel:       envOr("LOG_LEVEL", "info"),
		RateLimit: RateLimitConfig{
			Rate:  envFloat("RATE_LIMIT_RATE", 100),
			Burst: envInt("RATE_LIMIT_BURST", 20),
		},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			slog.Warn("invalid integer env var, using default", "key", key, "value", v, "default", fallback)
			return fallback
		}
		return n
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			slog.Warn("invalid float env var, using default", "key", key, "value", v, "default", fallback)
			return fallback
		}
		return f
	}
	return fallback
}
