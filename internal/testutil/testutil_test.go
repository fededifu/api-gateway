package testutil_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gateway/internal/domain"
	"gateway/internal/testutil"
)

func TestGenerateTestKeyPair(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	if kid == "" {
		t.Error("expected non-empty kid")
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}

	// Verify it's a valid RSA key pair by signing and verifying
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test",
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	parsed, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if !parsed.Valid {
		t.Error("parsed token should be valid")
	}
}

func TestIssueTestToken(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	principal := domain.Principal{
		ID:     "user-42",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "files:write"},
	}

	tokenStr := testutil.IssueTestToken(t, kid, priv, principal, 15*time.Minute)
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}

	// Verify the token is valid and has the right claims
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}
	if claims["sub"] != "user-42" {
		t.Errorf("expected sub 'user-42', got %v", claims["sub"])
	}
	if claims["type"] != "user" {
		t.Errorf("expected type 'user', got %v", claims["type"])
	}

	scopes, ok := claims["scopes"].(string)
	if !ok {
		t.Fatal("expected scopes as string")
	}
	if scopes != "vectors:read files:write" {
		t.Errorf("expected 'vectors:read files:write', got %q", scopes)
	}
}

func TestIssueExpiredToken(t *testing.T) {
	kid, priv, pub := testutil.GenerateTestKeyPair(t)

	principal := domain.Principal{
		ID:     "user-1",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read"},
	}

	tokenStr := testutil.IssueTestToken(t, kid, priv, principal, -1*time.Minute)

	_, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestMockJWKSServer(t *testing.T) {
	kid, _, pub := testutil.GenerateTestKeyPair(t)

	handler := testutil.MockJWKSHandler(kid, pub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decoding JWKS: %v", err)
	}

	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}

	key := keys[0].(map[string]any)
	if key["kid"] != kid {
		t.Errorf("expected kid %q, got %v", kid, key["kid"])
	}
	if key["kty"] != "RSA" {
		t.Errorf("expected kty RSA, got %v", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("expected alg RS256, got %v", key["alg"])
	}
}

func TestMockBackendHandler(t *testing.T) {
	handler := testutil.MockBackendHandler("test-backend")
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Should echo request details and principal headers
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/vectors/ns1", nil)
	req.Header.Set("X-Principal-ID", "user-42")
	req.Header.Set("X-Principal-Scopes", "vectors:read")
	req.Header.Set("X-Request-ID", "req-123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}

	if body["backend"] != "test-backend" {
		t.Errorf("expected backend 'test-backend', got %v", body["backend"])
	}
	if body["principal_id"] != "user-42" {
		t.Errorf("expected principal_id 'user-42', got %v", body["principal_id"])
	}
	if !strings.Contains(body["path"].(string), "/v1/vectors/ns1") {
		t.Errorf("expected path to contain '/v1/vectors/ns1', got %v", body["path"])
	}
}

func TestGenerateTestKeyPairDifferentKeys(t *testing.T) {
	kid1, _, pub1 := testutil.GenerateTestKeyPair(t)
	kid2, _, pub2 := testutil.GenerateTestKeyPair(t)

	if kid1 == kid2 {
		t.Error("expected different key IDs for different key pairs")
	}
	if pub1.N.Cmp(pub2.N) == 0 && pub1.E == pub2.E {
		t.Error("expected different public keys")
	}
}
