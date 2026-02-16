package loadtest_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"

	"gateway/internal/domain"
	"gateway/internal/gateway/adapter/inmem"
	"gateway/internal/gateway/adapter/jwks"
	"gateway/internal/gateway/adapter/proxy"
	"gateway/internal/gateway/middleware"
	"gateway/internal/platform/server"
	"gateway/internal/platform/telemetry"
	"gateway/internal/testutil"
)

// testEnv holds all the infrastructure needed for a load test.
type testEnv struct {
	baseURL    string
	token      string
	cancel     context.CancelFunc
	jwksSrv    *httptest.Server
	vectorDB   *httptest.Server
	fileSvc    *httptest.Server
}

type rlConfig struct {
	perIPRate  float64
	perIPBurst int
}

func setupTestEnv(t *testing.T, rl rlConfig) *testEnv {
	t.Helper()

	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	env := &testEnv{
		jwksSrv:  httptest.NewServer(testutil.MockJWKSHandler(kid, pub)),
		vectorDB: httptest.NewServer(testutil.MockBackendHandler("vectordb")),
		fileSvc:  httptest.NewServer(testutil.MockBackendHandler("fileservice")),
	}
	t.Cleanup(func() {
		env.jwksSrv.Close()
		env.vectorDB.Close()
		env.fileSvc.Close()
	})

	principal := domain.Principal{
		ID:     "loadtest-user",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "vectors:write", "files:read", "files:write"},
	}
	env.token = testutil.IssueTestToken(t, kid, priv, principal, 30*time.Minute)

	addr := freeAddr(t)
	jwksClient := jwks.NewClient(env.jwksSrv.URL, 1*time.Minute)
	router, err := proxy.NewRouter(env.vectorDB.URL, env.fileSvc.URL, "http://unused", nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	rateLimiter := inmem.NewRateLimiter(rl.perIPRate, rl.perIPBurst, time.Now)

	publicPaths := []string{"/healthz", "/readyz", "/metrics"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	shutdown, _ := telemetry.Setup(context.Background(), "gateway-loadtest")
	t.Cleanup(func() { shutdown(context.Background()) })

	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.MetricsHandler())
	mux.Handle("/", middleware.Chain(
		router,
		middleware.RequestID,
		middleware.Logging(logger),
		middleware.Recovery,
		middleware.RateLimit(rateLimiter, nil),
		middleware.Auth(jwksClient, publicPaths, nil),
	))

	srv := server.New(addr, mux)
	ctx, cancel := context.WithCancel(context.Background())
	env.cancel = cancel
	t.Cleanup(cancel)

	go srv.Run(ctx)

	env.baseURL = "http://" + addr
	waitForReady(t, env.baseURL+"/healthz")

	return env
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

func loadtestDuration() time.Duration {
	if d := os.Getenv("LOADTEST_DURATION"); d != "" {
		dur, err := time.ParseDuration(d)
		if err == nil {
			return dur
		}
	}
	if testing.Short() {
		return 2 * time.Second
	}
	return 5 * time.Second
}

func loadtestRate() int {
	if r := os.Getenv("LOADTEST_RATE"); r != "" {
		rate, err := strconv.Atoi(r)
		if err == nil {
			return rate
		}
	}
	if testing.Short() {
		return 50
	}
	return 100
}

func printReport(t *testing.T, name string, metrics *vegeta.Metrics) {
	t.Helper()
	t.Logf("\n=== %s ===", name)
	t.Logf("  Requests:    %d", metrics.Requests)
	t.Logf("  Rate:        %.1f req/s", metrics.Rate)
	t.Logf("  Throughput:  %.1f req/s", metrics.Throughput)
	t.Logf("  Duration:    %s", metrics.Duration)
	t.Logf("  Latencies:")
	t.Logf("    Mean:    %s", metrics.Latencies.Mean)
	t.Logf("    P50:     %s", metrics.Latencies.P50)
	t.Logf("    P95:     %s", metrics.Latencies.P95)
	t.Logf("    P99:     %s", metrics.Latencies.P99)
	t.Logf("    Max:     %s", metrics.Latencies.Max)
	t.Logf("  Status Codes:")
	for code, count := range metrics.StatusCodes {
		t.Logf("    %s: %d", code, count)
	}
	if len(metrics.Errors) > 0 {
		t.Logf("  Errors (first 5):")
		for i, e := range metrics.Errors {
			if i >= 5 {
				break
			}
			t.Logf("    %s", e)
		}
	}
	t.Logf("  Success:     %.1f%%", metrics.Success*100)
}

func TestBaselineAuthenticated(t *testing.T) {
	env := setupTestEnv(t, rlConfig{perIPRate: 10000, perIPBurst: 10000})

	rate := vegeta.Rate{Freq: loadtestRate(), Per: time.Second}
	duration := loadtestDuration()

	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    env.baseURL + "/v1/vectors/ns1",
		Header: http.Header{
			"Authorization": []string{"Bearer " + env.token},
		},
	})

	attacker := vegeta.NewAttacker()
	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, duration, "baseline") {
		metrics.Add(res)
	}
	metrics.Close()

	printReport(t, "Baseline Authenticated", &metrics)

	// Assertions
	if metrics.Success < 0.99 {
		t.Errorf("expected >99%% success rate, got %.1f%%", metrics.Success*100)
	}
	if metrics.Latencies.P99 > 100*time.Millisecond {
		t.Errorf("P99 latency too high: %s", metrics.Latencies.P99)
	}
}

func TestRampUp(t *testing.T) {
	env := setupTestEnv(t, rlConfig{perIPRate: 10000, perIPBurst: 10000})

	duration := loadtestDuration()
	stages := []struct {
		name string
		rate int
	}{
		{"low", loadtestRate() / 2},
		{"medium", loadtestRate()},
		{"high", loadtestRate() * 3},
	}

	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    env.baseURL + "/v1/vectors/ns1",
		Header: http.Header{
			"Authorization": []string{"Bearer " + env.token},
		},
	})

	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			rate := vegeta.Rate{Freq: stage.rate, Per: time.Second}
			attacker := vegeta.NewAttacker()
			var metrics vegeta.Metrics
			stageDuration := duration / time.Duration(len(stages))
			for res := range attacker.Attack(targeter, rate, stageDuration, stage.name) {
				metrics.Add(res)
			}
			metrics.Close()

			printReport(t, fmt.Sprintf("Ramp Up - %s (%d req/s)", stage.name, stage.rate), &metrics)

			if metrics.Success < 0.95 {
				t.Errorf("expected >95%% success, got %.1f%%", metrics.Success*100)
			}
		})
	}
}

func TestRateLimitBehavior(t *testing.T) {
	// Use a low per-IP rate+burst so we trigger rate limiting at the test attack rate
	env := setupTestEnv(t, rlConfig{perIPRate: 5, perIPBurst: 10})

	// Send at a rate that will exceed the burst
	rate := vegeta.Rate{Freq: loadtestRate(), Per: time.Second}
	duration := loadtestDuration()

	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    env.baseURL + "/v1/vectors/ns1",
		Header: http.Header{
			"Authorization": []string{"Bearer " + env.token},
		},
	})

	attacker := vegeta.NewAttacker()
	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, duration, "rate-limit") {
		metrics.Add(res)
	}
	metrics.Close()

	printReport(t, "Rate Limit Behavior", &metrics)

	// Should see a mix of 200s and 429s
	has200 := metrics.StatusCodes["200"] > 0
	has429 := metrics.StatusCodes["429"] > 0

	if !has200 {
		t.Error("expected some 200 responses (initial burst)")
	}
	if !has429 {
		t.Error("expected some 429 responses (rate limited)")
	}
}

func TestExpiredTokens(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()
	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()
	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	// Issue an expired token
	principal := domain.Principal{
		ID:     "expired-user",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read"},
	}
	expiredToken := testutil.IssueTestToken(t, kid, priv, principal, -1*time.Minute)

	addr := freeAddr(t)
	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)
	router, err := proxy.NewRouter(vectorDB.URL, fileSvc.URL, "http://unused", nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	rateLimiter := inmem.NewRateLimiter(10000, 10000, time.Now)
	publicPaths := []string{"/healthz", "/readyz", "/metrics"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	shutdown, _ := telemetry.Setup(context.Background(), "gateway-expired-test")
	defer shutdown(context.Background())

	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.MetricsHandler())
	mux.Handle("/", middleware.Chain(
		router,
		middleware.RequestID,
		middleware.Logging(logger),
		middleware.Recovery,
		middleware.RateLimit(rateLimiter, nil),
		middleware.Auth(jwksClient, publicPaths, nil),
	))

	srv := server.New(addr, mux)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	baseURL := "http://" + addr
	waitForReady(t, baseURL+"/healthz")

	rate := vegeta.Rate{Freq: loadtestRate(), Per: time.Second}
	duration := loadtestDuration()

	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    baseURL + "/v1/vectors/ns1",
		Header: http.Header{
			"Authorization": []string{"Bearer " + expiredToken},
		},
	})

	attacker := vegeta.NewAttacker()
	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, duration, "expired") {
		metrics.Add(res)
	}
	metrics.Close()

	printReport(t, "Expired Tokens", &metrics)

	// All requests should be 401
	if metrics.StatusCodes["401"] == 0 {
		t.Error("expected all 401 responses for expired tokens")
	}
	// Success should be 0 (all 401s)
	if metrics.Success > 0.01 {
		t.Errorf("expected ~0%% success for expired tokens, got %.1f%%", metrics.Success*100)
	}
}

func TestMixedTraffic(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()
	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()
	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	validPrincipal := domain.Principal{
		ID:     "mixed-user",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "vectors:write", "files:read", "files:write"},
	}
	validToken := testutil.IssueTestToken(t, kid, priv, validPrincipal, 30*time.Minute)
	invalidToken := "invalid.token.here"

	addr := freeAddr(t)
	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)
	router, err := proxy.NewRouter(vectorDB.URL, fileSvc.URL, "http://unused", nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	rateLimiter := inmem.NewRateLimiter(10000, 10000, time.Now)
	publicPaths := []string{"/healthz", "/readyz", "/metrics"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	shutdown, _ := telemetry.Setup(context.Background(), "gateway-mixed-test")
	defer shutdown(context.Background())

	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.MetricsHandler())
	mux.Handle("/", middleware.Chain(
		router,
		middleware.RequestID,
		middleware.Logging(logger),
		middleware.Recovery,
		middleware.RateLimit(rateLimiter, nil),
		middleware.Auth(jwksClient, publicPaths, nil),
	))

	srv := server.New(addr, mux)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	baseURL := "http://" + addr
	waitForReady(t, baseURL+"/healthz")

	// Mixed targeter: 70% reads, 20% writes, 10% invalid
	targets := make([]vegeta.Target, 10)
	// 7 reads
	for i := range 7 {
		targets[i] = vegeta.Target{
			Method: http.MethodGet,
			URL:    baseURL + "/v1/vectors/ns1",
			Header: http.Header{
				"Authorization": []string{"Bearer " + validToken},
			},
		}
	}
	// 2 writes
	for i := 7; i < 9; i++ {
		targets[i] = vegeta.Target{
			Method: http.MethodPost,
			URL:    baseURL + "/v1/files",
			Header: http.Header{
				"Authorization": []string{"Bearer " + validToken},
			},
		}
	}
	// 1 invalid
	targets[9] = vegeta.Target{
		Method: http.MethodGet,
		URL:    baseURL + "/v1/vectors/ns1",
		Header: http.Header{
			"Authorization": []string{"Bearer " + invalidToken},
		},
	}

	targeter := vegeta.NewStaticTargeter(targets...)

	rate := vegeta.Rate{Freq: loadtestRate(), Per: time.Second}
	duration := loadtestDuration()

	attacker := vegeta.NewAttacker()
	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, duration, "mixed") {
		metrics.Add(res)
	}
	metrics.Close()

	printReport(t, "Mixed Traffic (70% read, 20% write, 10% invalid)", &metrics)

	// Should have both 200s and 401s
	if metrics.StatusCodes["200"] == 0 {
		t.Error("expected some 200 responses")
	}
	if metrics.StatusCodes["401"] == 0 {
		t.Error("expected some 401 responses from invalid tokens")
	}

	// Majority should succeed (90% valid, 10% invalid)
	total := float64(metrics.Requests)
	successCount := float64(metrics.StatusCodes["200"])
	successRate := successCount / total
	if successRate < 0.80 {
		t.Errorf("expected >80%% success rate, got %.1f%%", successRate*100)
	}
}
