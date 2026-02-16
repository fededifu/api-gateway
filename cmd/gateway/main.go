package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gateway/internal/gateway/adapter/inmem"
	"gateway/internal/gateway/adapter/jwks"
	"gateway/internal/gateway/adapter/proxy"
	"gateway/internal/gateway/middleware"
	"gateway/internal/platform/config"
	"gateway/internal/platform/server"
	"gateway/internal/platform/telemetry"
)

func main() {
	cfg := config.Load()

	// Logging
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Telemetry
	shutdown, err := telemetry.Setup(context.Background(), "gateway")
	if err != nil {
		slog.Error("telemetry setup failed", "error", err)
		os.Exit(1)
	}

	// JWKS client
	jwksClient := jwks.NewClient(cfg.JWKSEndpoint, 5*time.Minute)

	// Rate limiter
	rl := inmem.NewRateLimiter(cfg.RateLimit.Rate, cfg.RateLimit.Burst, time.Now)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rl.Cleanup()
			}
		}
	}()

	// Metrics
	metrics, err := telemetry.NewGatewayMetrics()
	if err != nil {
		slog.Error("metrics initialization failed", "error", err)
		os.Exit(1)
	}

	// Router
	router, err := proxy.NewRouter(cfg.VectorDBURL, cfg.FileServiceURL, cfg.IdentityURL, metrics)
	if err != nil {
		slog.Error("router initialization failed", "error", err)
		os.Exit(1)
	}

	// Public paths (no auth required)
	publicPaths := []string{"/healthz", "/readyz", "/metrics", "/auth/token", "/.well-known/jwks.json"}

	// Assemble middleware chain
	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.MetricsHandler())
	const maxBodyBytes = 1 << 20 // 1MB
	mux.Handle("/", middleware.Chain(
		router,
		middleware.Metrics(metrics),
		middleware.RequestID,
		middleware.Logging(logger),
		middleware.Recovery,
		middleware.MaxBodySize(maxBodyBytes),
		middleware.RateLimit(rl, metrics),
		middleware.Auth(jwksClient, publicPaths, metrics),
	))

	// Start server
	srv := server.New(cfg.GatewayAddr, mux)

	slog.Info("gateway starting",
		"addr", cfg.GatewayAddr,
		"jwks_endpoint", cfg.JWKSEndpoint,
		"vectordb_url", cfg.VectorDBURL,
		"fileservice_url", cfg.FileServiceURL,
		"identity_url", cfg.IdentityURL,
	)

	if err := srv.Run(ctx); err != nil {
		slog.Error("server error", "error", err)
	}

	if err := shutdown(context.Background()); err != nil {
		slog.Error("telemetry shutdown error", "error", err)
	}
}
