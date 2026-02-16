package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gateway/internal/domain"
)

// GenerateTestKeyPair generates an RSA key pair for testing.
// Returns (keyID, privateKey, publicKey).
func GenerateTestKeyPair(t *testing.T) (string, *rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	kid := fmt.Sprintf("test-key-%d", time.Now().UnixNano())
	return kid, priv, &priv.PublicKey
}

// IssueTestToken creates a signed JWT for testing.
// A negative ttl produces an already-expired token.
func IssueTestToken(t *testing.T, kid string, priv *rsa.PrivateKey, principal domain.Principal, ttl time.Duration) string {
	t.Helper()

	now := time.Now()
	scopes := make([]string, len(principal.Scopes))
	for i, s := range principal.Scopes {
		scopes[i] = string(s)
	}

	claims := jwt.MapClaims{
		"sub":    principal.ID,
		"type":   principal.Type.String(),
		"scopes": strings.Join(scopes, " "),
		"iat":    now.Unix(),
		"exp":    now.Add(ttl).Unix(),
		"iss":    "gateway-test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

// MockJWKSHandler returns an http.Handler that serves a JWKS response
// containing the given public key.
func MockJWKSHandler(kid string, pub *rsa.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": kid,
					"n":   base64URLEncode(pub.N.Bytes()),
					"e":   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})
}

// MockBackendHandler returns an http.Handler that echoes request details.
// Used to test that the gateway correctly proxies requests with principal headers.
func MockBackendHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
