package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gateway/internal/platform/server"
)

func main() {
	addr := envOr("ADDR", ":8082")
	name := envOr("BACKEND_NAME", "mock-backend")
	baseDelay := envDuration("LATENCY_BASE", 0)
	jitter := envDuration("LATENCY_JITTER", 0)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("mock backend starting", "addr", addr, "name", name,
		"latency_base", baseDelay, "latency_jitter", jitter)

	mux := http.NewServeMux()

	// Catch-all: echo request details
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		simulateWork(baseDelay, jitter)
		resp := map[string]any{
			"backend":          name,
			"method":           r.Method,
			"path":             r.URL.Path,
			"principal_id":     r.Header.Get("X-Principal-ID"),
			"principal_scopes": r.Header.Get("X-Principal-Scopes"),
			"request_id":       r.Header.Get("X-Request-ID"),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": name})
	})

	srv := server.New(addr, mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		slog.Error("server error", "error", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envDuration reads a duration in milliseconds from an env var (e.g. "50" -> 50ms).
func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return fallback
}

// simulateWork sleeps for base + random(0, jitter) to mimic real backend processing.
func simulateWork(base, jitter time.Duration) {
	if base == 0 && jitter == 0 {
		return
	}
	delay := base
	if jitter > 0 {
		delay += time.Duration(rand.Int64N(int64(jitter)))
	}
	time.Sleep(delay)
}
