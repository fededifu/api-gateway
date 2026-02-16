package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/internal/domain"
	gw "gateway/internal/gateway"
	"gateway/internal/gateway/adapter/proxy"
	"gateway/internal/testutil"
)

func newTestRouter(t *testing.T, vectorDBURL, fileSvcURL, identityURL string) *proxy.Router {
	t.Helper()
	router, err := proxy.NewRouter(vectorDBURL, fileSvcURL, identityURL, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return router
}

func TestRouterRoutesVectors(t *testing.T) {
	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()
	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	router := newTestRouter(t, vectorDB.URL, fileSvc.URL, "http://unused")

	principal := domain.Principal{
		ID:     "user-42",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "vectors:write"},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vectors/ns1", nil)
	ctx := gw.ContextWithPrincipal(req.Context(), principal)
	ctx = gw.ContextWithRequestID(ctx, "req-123")
	router.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	if body["backend"] != "vectordb" {
		t.Errorf("expected vectordb backend, got %v", body["backend"])
	}
	if body["principal_id"] != "user-42" {
		t.Errorf("expected principal_id user-42, got %v", body["principal_id"])
	}
	if body["principal_scopes"] != "vectors:read vectors:write" {
		t.Errorf("expected scopes, got %v", body["principal_scopes"])
	}
}

func TestRouterRoutesFiles(t *testing.T) {
	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()
	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	router := newTestRouter(t, vectorDB.URL, fileSvc.URL, "http://unused")

	principal := domain.Principal{
		ID:     "user-42",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"files:read"},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/files/abc-123", nil)
	ctx := gw.ContextWithPrincipal(req.Context(), principal)
	router.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	if body["backend"] != "fileservice" {
		t.Errorf("expected fileservice backend, got %v", body["backend"])
	}
}

func TestRouterStripsAuthorizationHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization header should be stripped, got %q", auth)
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer backend.Close()

	router := newTestRouter(t, backend.URL, backend.URL, "http://unused")

	principal := domain.Principal{ID: "user-1", Scopes: []domain.Scope{"vectors:read"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors/ns1", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	ctx := gw.ContextWithPrincipal(req.Context(), principal)
	router.ServeHTTP(rec, req.WithContext(ctx))
}

func TestRouterUnknownPath404(t *testing.T) {
	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()
	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	router := newTestRouter(t, vectorDB.URL, fileSvc.URL, "http://unused")

	principal := domain.Principal{ID: "user-1", Scopes: []domain.Scope{"vectors:read"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown", nil)
	ctx := gw.ContextWithPrincipal(req.Context(), principal)
	router.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestRouterInsufficientScopes403(t *testing.T) {
	vectorDB := httptest.NewServer(testutil.MockBackendHandler("vectordb"))
	defer vectorDB.Close()
	fileSvc := httptest.NewServer(testutil.MockBackendHandler("fileservice"))
	defer fileSvc.Close()

	router := newTestRouter(t, vectorDB.URL, fileSvc.URL, "http://unused")

	principal := domain.Principal{
		ID:     "user-1",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"files:read"},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vectors/ns1", nil)
	ctx := gw.ContextWithPrincipal(req.Context(), principal)
	router.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestHealthzEndpoint(t *testing.T) {
	router := newTestRouter(t, "http://unused", "http://unused", "http://unused")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestReadyzEndpoint(t *testing.T) {
	router := newTestRouter(t, "http://unused", "http://unused", "http://unused")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRouterProxiesAuthToken(t *testing.T) {
	identity := httptest.NewServer(testutil.MockBackendHandler("identity"))
	defer identity.Close()

	router := newTestRouter(t, "http://unused", "http://unused", identity.URL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["backend"] != "identity" {
		t.Errorf("expected identity backend, got %v", body["backend"])
	}
	if body["path"] != "/auth/token" {
		t.Errorf("expected path /auth/token, got %v", body["path"])
	}
}

func TestRouterProxiesAuthTokenWithoutPrincipal(t *testing.T) {
	identity := httptest.NewServer(testutil.MockBackendHandler("identity"))
	defer identity.Close()

	router := newTestRouter(t, "http://unused", "http://unused", identity.URL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	// No principal in context — public routes must work without authentication
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; auth/token should not require authentication", rec.Code)
	}
}

func TestRouterProxiesJWKS(t *testing.T) {
	identity := httptest.NewServer(testutil.MockBackendHandler("identity"))
	defer identity.Close()

	router := newTestRouter(t, "http://unused", "http://unused", identity.URL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["backend"] != "identity" {
		t.Errorf("expected identity backend, got %v", body["backend"])
	}
	if body["path"] != "/.well-known/jwks.json" {
		t.Errorf("expected path /.well-known/jwks.json, got %v", body["path"])
	}
}

func TestPublicRoutesPropagateRequestID(t *testing.T) {
	identity := httptest.NewServer(testutil.MockBackendHandler("identity"))
	defer identity.Close()

	router := newTestRouter(t, "http://unused", "http://unused", identity.URL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	ctx := gw.ContextWithRequestID(req.Context(), "req-abc")
	router.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["request_id"] != "req-abc" {
		t.Errorf("expected request_id req-abc, got %v", body["request_id"])
	}
}
