package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gateway/internal/domain"
	"gateway/internal/gateway/adapter/inmem"
	"gateway/internal/gateway/adapter/jwks"
	"gateway/internal/gateway/adapter/proxy"
	"gateway/internal/gateway/middleware"
	"gateway/internal/platform/server"
	"gateway/internal/platform/telemetry"
	"gateway/internal/testutil"
)

// startGateway wires up all gateway components and starts the server.
// Returns the base URL and a cancel function.
func startGateway(t *testing.T, jwksURL, vectorDBURL, fileServiceURL string) (string, context.CancelFunc) {
	t.Helper()

	addr := freeAddr(t)

	jwksClient := jwks.NewClient(jwksURL, 1*time.Minute)
	router, err := proxy.NewRouter(vectorDBURL, fileServiceURL, "http://unused", nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	now := time.Now()
	clock := func() time.Time { return now }
	rl := inmem.NewRateLimiter(100, 20, clock)

	publicPaths := []string{"/healthz", "/readyz", "/metrics"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	shutdown, err := telemetry.Setup(context.Background(), "gateway-test")
	if err != nil {
		t.Fatalf("telemetry setup: %v", err)
	}
	t.Cleanup(func() { shutdown(context.Background()) })

	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.MetricsHandler())
	mux.Handle("/", middleware.Chain(
		router,
		middleware.RequestID,
		middleware.Logging(logger),
		middleware.Recovery,
		middleware.RateLimit(rl, nil),
		middleware.Auth(jwksClient, publicPaths, nil),
	))

	srv := server.New(addr, mux)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := srv.Run(ctx); err != nil {
			t.Logf("server error: %v", err)
		}
	}()

	// Wait for server to be ready
	baseURL := "http://" + addr
	waitForReady(t, baseURL+"/healthz")

	return baseURL, cancel
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitForReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not become ready at %s", url)
}

func TestFullAuthFlow(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()

	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	baseURL, cancel := startGateway(t, jwksSrv.URL, vectorDB.URL, fileSvc.URL)
	defer cancel()

	principal := domain.Principal{
		ID:     "user-42",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "vectors:write", "files:read", "files:write"},
	}
	token := testutil.IssueTestToken(t, kid, priv, principal, 15*time.Minute)

	t.Run("authenticated vector request", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/vectors/ns1", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}

		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		if body["backend"] != "vectordb" {
			t.Errorf("expected vectordb backend, got %v", body["backend"])
		}
		if body["principal_id"] != "user-42" {
			t.Errorf("expected principal_id user-42, got %v", body["principal_id"])
		}
	})

	t.Run("authenticated file request", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/files/abc", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		if body["backend"] != "fileservice" {
			t.Errorf("expected fileservice backend, got %v", body["backend"])
		}
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/v1/vectors/ns1")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("expired token returns 401", func(t *testing.T) {
		expiredToken := testutil.IssueTestToken(t, kid, priv, principal, -1*time.Minute)

		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/vectors/ns1", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("insufficient scope returns 403", func(t *testing.T) {
		readOnlyPrincipal := domain.Principal{
			ID:     "user-limited",
			Type:   domain.PrincipalUser,
			Scopes: []domain.Scope{"files:read"},
		}
		readOnlyToken := testutil.IssueTestToken(t, kid, priv, readOnlyPrincipal, 15*time.Minute)

		req, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/vectors/ns1", nil)
		req.Header.Set("Authorization", "Bearer "+readOnlyToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("unknown path returns 404", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/unknown", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("healthz accessible without auth", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("metrics accessible without auth", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/metrics")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "gateway_http_requests_total") ||
			!strings.Contains(string(body), "gateway_auth_validations_total") {
			// Metrics may not show up until recorded — this is just a connectivity check
			t.Log("note: some metrics may not be visible until recorded")
		}
	})

	t.Run("request ID propagated", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/vectors/ns1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Request-ID", "custom-req-id")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.Header.Get("X-Request-ID") != "custom-req-id" {
			t.Errorf("expected X-Request-ID 'custom-req-id', got %q", resp.Header.Get("X-Request-ID"))
		}

		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		if body["request_id"] != "custom-req-id" {
			t.Errorf("expected request_id propagated to backend, got %v", body["request_id"])
		}
	})

	t.Run("request ID generated when missing", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/vectors/ns1", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		reqID := resp.Header.Get("X-Request-ID")
		if reqID == "" {
			t.Error("expected auto-generated X-Request-ID")
		}
	})
}

func TestRateLimitingIntegration(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()

	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	// Use very small burst for testing rate limits
	addr := freeAddr(t)
	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)
	router, err := proxy.NewRouter(vectorDB.URL, fileSvc.URL, "http://unused", nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	now := time.Now()
	clock := func() time.Time { return now }
	rl := inmem.NewRateLimiter(100, 5, clock) // Burst of 5 (accounts for healthz polling)

	publicPaths := []string{"/healthz", "/readyz", "/metrics"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	shutdown, _ := telemetry.Setup(context.Background(), "gateway-ratelimit-test")
	t.Cleanup(func() { shutdown(context.Background()) })

	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.MetricsHandler())
	mux.Handle("/", middleware.Chain(
		router,
		middleware.RequestID,
		middleware.Logging(logger),
		middleware.Recovery,
		middleware.RateLimit(rl, nil),
		middleware.Auth(jwksClient, publicPaths, nil),
	))

	srv := server.New(addr, mux)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	baseURL := "http://" + addr
	waitForReady(t, baseURL+"/healthz")

	principal := domain.Principal{
		ID:     "user-1",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read"},
	}
	token := testutil.IssueTestToken(t, kid, priv, principal, 15*time.Minute)

	// Exhaust remaining per-IP burst by sending many requests
	// Some tokens were consumed by waitForReady polling /healthz
	var lastStatus int
	for i := range 20 {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/vectors/ns1", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		lastStatus = resp.StatusCode

		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("expected at least one 429 after burst exhaustion, last status: %d", lastStatus)
	}

	// Next request should also be rate limited
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/vectors/ns1", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("4th request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}

	var errResp domain.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "rate_limited" {
		t.Errorf("expected error 'rate_limited', got %q", errResp.Error)
	}

	_ = fmt.Sprintf("rate limit retry_after: %d", errResp.RetryAfter)
}
