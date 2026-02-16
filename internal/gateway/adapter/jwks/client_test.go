package jwks_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/gateway/adapter/jwks"
	"gateway/internal/testutil"
)

func TestClientFetchesAndCachesKey(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)
	var fetchCount atomic.Int64

	handler := testutil.MockJWKSHandler(kid, pub)
	srv := httptest.NewServer(countingHandler(&fetchCount, handler))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	ctx := context.Background()

	// First call should fetch
	key1, err := client.GetKey(ctx, kid)
	if err != nil {
		t.Fatalf("first GetKey: %v", err)
	}
	if key1 == nil {
		t.Fatal("expected non-nil key")
	}
	if key1.N.Cmp(pub.N) != 0 {
		t.Error("returned key doesn't match expected public key")
	}

	// Second call should use cache (no additional fetch)
	key2, err := client.GetKey(ctx, kid)
	if err != nil {
		t.Fatalf("second GetKey: %v", err)
	}
	if key2.N.Cmp(pub.N) != 0 {
		t.Error("cached key doesn't match expected public key")
	}

	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount.Load())
	}
}

func TestClientUnknownKID(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)

	srv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	_, err := client.GetKey(context.Background(), "unknown-kid")
	if err == nil {
		t.Error("expected error for unknown kid")
	}
}

func TestClientRefreshesAfterMinInterval(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)
	var fetchCount atomic.Int64

	srv := httptest.NewServer(countingHandler(&fetchCount, testutil.MockJWKSHandler(kid, pub)))
	defer srv.Close()

	// Very short min refresh interval for testing
	client := jwks.NewClient(srv.URL, 10*time.Millisecond)

	ctx := context.Background()

	// First fetch
	_, err := client.GetKey(ctx, kid)
	if err != nil {
		t.Fatalf("first GetKey: %v", err)
	}

	// Wait past refresh interval
	time.Sleep(20 * time.Millisecond)

	// Request unknown kid should trigger refresh attempt
	_, _ = client.GetKey(ctx, "new-kid")

	if fetchCount.Load() < 2 {
		t.Errorf("expected at least 2 fetches after refresh interval, got %d", fetchCount.Load())
	}
}

func TestClientEndpointDown(t *testing.T) {
	// Use a closed server
	srv := httptest.NewServer(testutil.MockJWKSHandler("kid", nil))
	srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	_, err := client.GetKey(context.Background(), "any-kid")
	if err == nil {
		t.Error("expected error when JWKS endpoint is unreachable")
	}
}

func TestClientEndpoint4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	_, err := client.GetKey(context.Background(), "any-kid")
	if err == nil {
		t.Error("expected error for 403 response")
	}
}

func TestClientEndpoint5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	_, err := client.GetKey(context.Background(), "any-kid")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestClientMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys": not valid json`))
	}))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	_, err := client.GetKey(context.Background(), "any-kid")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestClientEmptyKeyset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys": []}`))
	}))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	_, err := client.GetKey(context.Background(), "any-kid")
	if err == nil {
		t.Error("expected error for empty keyset")
	}
}

func TestClientContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // slow response
	}))
	defer srv.Close()

	client := jwks.NewClient(srv.URL, 1*time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.GetKey(ctx, "any-kid")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func countingHandler(count *atomic.Int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		next.ServeHTTP(w, r)
	})
}
