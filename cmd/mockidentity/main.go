package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gateway/internal/domain"
	"gateway/internal/platform/server"
)

func main() {
	addr := envOr("IDENTITY_ADDR", ":8081")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Generate RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("generating RSA key", "error", err)
		os.Exit(1)
	}
	kid := fmt.Sprintf("mock-key-%d", time.Now().Unix())

	slog.Info("mock identity service starting",
		"addr", addr,
		"kid", kid,
	)

	// Seed users
	users := map[string]string{
		"admin": "admin",
		"user":  "password",
	}
	apiKeys := map[string]string{
		"test-api-key-1": "service-account-1",
	}

	slog.Info("seeded credentials",
		"users", "admin:admin, user:password",
		"api_keys", "test-api-key-1",
	)

	mux := http.NewServeMux()

	// JWKS endpoint
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &priv.PublicKey
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": kid,
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// Token issuance
	mux.HandleFunc("POST /auth/token", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			APIKey   string `json:"api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		var principalID string
		var principalType domain.PrincipalType

		switch {
		case req.APIKey != "":
			id, ok := apiKeys[req.APIKey]
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid API key")
				return
			}
			principalID = id
			principalType = domain.PrincipalService
		case req.Username != "":
			expectedPass, ok := users[req.Username]
			if !ok || expectedPass != req.Password {
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
				return
			}
			principalID = req.Username
			principalType = domain.PrincipalUser
		default:
			writeError(w, http.StatusBadRequest, "bad_request", "provide username/password or api_key")
			return
		}

		// All mock users get full scopes
		scopes := "vectors:read vectors:write files:read files:write"
		ttl := 15 * time.Minute
		now := time.Now()

		claims := jwt.MapClaims{
			"sub":    principalID,
			"type":   principalType.String(),
			"scopes": scopes,
			"iat":    now.Unix(),
			"exp":    now.Add(ttl).Unix(),
			"iss":    "mock-identity",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid

		signed, err := token.SignedString(priv)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to sign token")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(domain.TokenPair{
			AccessToken: signed,
			ExpiresIn:   int(ttl.Seconds()),
			TokenType:   "Bearer",
		})
	})

	// Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "mock-identity"})
	})

	srv := server.New(addr, mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		slog.Error("server error", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(domain.ErrorResponse{Error: code, Message: msg})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

