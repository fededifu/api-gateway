package middleware_test

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gateway/internal/domain"
	"gateway/internal/gateway"
	"gateway/internal/gateway/adapter/jwks"
	"gateway/internal/gateway/middleware"
	"gateway/internal/testutil"
)

func TestAuthValidToken(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	principal := domain.Principal{
		ID:     "user-42",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "files:write"},
	}
	token := testutil.IssueTestToken(t, kid, priv, principal, 15*time.Minute)

	var capturedPrincipal domain.Principal
	var hasPrincipal bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, hasPrincipal = gateway.PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Auth(jwksClient, nil, nil)(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !hasPrincipal {
		t.Fatal("expected principal in context")
	}
	if capturedPrincipal.ID != "user-42" {
		t.Errorf("expected principal ID 'user-42', got %q", capturedPrincipal.ID)
	}
	if !capturedPrincipal.HasScope("vectors:read") {
		t.Error("expected scope vectors:read")
	}
	if !capturedPrincipal.HasScope("files:write") {
		t.Error("expected scope files:write")
	}
}

func TestAuthMissingToken(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	handler := middleware.Auth(jwksClient, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	var errResp domain.ErrorResponse
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp.Error != "unauthorized" {
		t.Errorf("expected error 'unauthorized', got %q", errResp.Error)
	}
}

func TestAuthExpiredToken(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	principal := domain.Principal{
		ID:     "user-1",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read"},
	}
	token := testutil.IssueTestToken(t, kid, priv, principal, -1*time.Minute)

	handler := middleware.Auth(jwksClient, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired token")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMalformedHeader(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	handler := middleware.Auth(jwksClient, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "just-a-token"},
		{"empty bearer", "Bearer "},
		{"basic auth", "Basic dXNlcjpwYXNz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
			req.Header.Set("Authorization", tt.header)
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", rec.Code)
			}
		})
	}
}

func TestAuthPublicPathBypasses(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	publicPaths := []string{"/healthz", "/readyz", "/metrics"}

	called := false
	handler := middleware.Auth(jwksClient, publicPaths, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range publicPaths {
		called = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		// No Authorization header
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", path, rec.Code)
		}
		if !called {
			t.Errorf("%s: handler should have been called", path)
		}
	}
}

func TestAuthAlgorithmNone(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	// Craft a token with alg:none
	handler := middleware.Auth(jwksClient, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for alg:none")
	}))

	// A token with alg: none is essentially "header.payload." with no signature
	// We can craft one manually, but any non-RS256 token should be rejected
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for alg:none, got %d", rec.Code)
	}
}

// signCustomClaims creates a signed RS256 JWT with arbitrary MapClaims for testing.
func signCustomClaims(t *testing.T, kid string, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func TestAuthBearerTokenEdgeCases(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	validToken := testutil.IssueTestToken(t, kid, priv, domain.Principal{
		ID:     "user-1",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read"},
	}, 15*time.Minute)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := middleware.Auth(jwksClient, nil, nil)(inner)

	tests := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{
			name:       "lowercase bearer",
			header:     "bearer " + validToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "uppercase BEARER",
			header:     "BEARER " + validToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "leading space in token value",
			header:     "Bearer  " + validToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "wrong scheme Token",
			header:     "Token abc123",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "no space after Bearer",
			header:     "Bearertoken",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
			req.Header.Set("Authorization", tt.header)
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestAuthServicePrincipal(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)

	token := testutil.IssueTestToken(t, kid, priv, domain.Principal{
		ID:     "svc-bot",
		Type:   domain.PrincipalService,
		Scopes: []domain.Scope{"vectors:write"},
	}, 15*time.Minute)

	var captured domain.Principal
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = gateway.PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Auth(jwksClient, nil, nil)(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if captured.Type != domain.PrincipalService {
		t.Errorf("expected PrincipalService, got %v", captured.Type)
	}
	if captured.ID != "svc-bot" {
		t.Errorf("expected ID 'svc-bot', got %q", captured.ID)
	}
}

func TestAuthPrincipalEdgeCases(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	jwksSrv := httptest.NewServer(testutil.MockJWKSHandler(kid, pub))
	defer jwksSrv.Close()

	jwksClient := jwks.NewClient(jwksSrv.URL, 1*time.Minute)
	now := time.Now()

	t.Run("no type claim defaults to user", func(t *testing.T) {
		token := signCustomClaims(t, kid, priv, jwt.MapClaims{
			"sub":    "user-99",
			"scopes": "vectors:read",
			"iat":    now.Unix(),
			"exp":    now.Add(15 * time.Minute).Unix(),
			"iss":    "gateway-test",
		})

		var captured domain.Principal
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured, _ = gateway.PrincipalFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		handler := middleware.Auth(jwksClient, nil, nil)(inner)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if captured.Type != domain.PrincipalUser {
			t.Errorf("expected PrincipalUser, got %v", captured.Type)
		}
	})

	t.Run("empty sub rejected", func(t *testing.T) {
		token := signCustomClaims(t, kid, priv, jwt.MapClaims{
			"sub": "",
			"iat": now.Unix(),
			"exp": now.Add(15 * time.Minute).Unix(),
			"iss": "gateway-test",
		})

		handler := middleware.Auth(jwksClient, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called for empty sub")
		}))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}

		var errResp domain.ErrorResponse
		json.NewDecoder(rec.Body).Decode(&errResp)
		if errResp.Message != "invalid token claims" {
			t.Errorf("expected message 'invalid token claims', got %q", errResp.Message)
		}
	})

	t.Run("no scopes yields empty slice", func(t *testing.T) {
		token := signCustomClaims(t, kid, priv, jwt.MapClaims{
			"sub": "user-no-scopes",
			"iat": now.Unix(),
			"exp": now.Add(15 * time.Minute).Unix(),
			"iss": "gateway-test",
		})

		var captured domain.Principal
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured, _ = gateway.PrincipalFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		handler := middleware.Auth(jwksClient, nil, nil)(inner)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if len(captured.Scopes) != 0 {
			t.Errorf("expected empty scopes, got %v", captured.Scopes)
		}
	})

	t.Run("whitespace-only scopes yields empty slice", func(t *testing.T) {
		token := signCustomClaims(t, kid, priv, jwt.MapClaims{
			"sub":    "user-ws-scopes",
			"scopes": "   ",
			"iat":    now.Unix(),
			"exp":    now.Add(15 * time.Minute).Unix(),
			"iss":    "gateway-test",
		})

		var captured domain.Principal
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured, _ = gateway.PrincipalFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		handler := middleware.Auth(jwksClient, nil, nil)(inner)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vectors", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if len(captured.Scopes) != 0 {
			t.Errorf("expected empty scopes, got %v", captured.Scopes)
		}
	})
}
