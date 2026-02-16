package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gateway/internal/domain"
	gw "gateway/internal/gateway"
	"gateway/internal/platform/telemetry"
)

const maxClockSkew = 30 * time.Second

// Auth returns a middleware that validates JWT Bearer tokens.
// It uses the provided JWKSProvider to look up public keys by kid.
// Paths in publicPaths are exempt from authentication.
// The metrics parameter is optional; pass nil to skip metric recording.
func Auth(jwks gw.JWKSProvider, publicPaths []string, m *telemetry.GatewayMetrics) Middleware {
	public := make(map[string]struct{}, len(publicPaths))
	for _, p := range publicPaths {
		public[p] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for public paths
			if _, ok := public[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}

			tokenStr, ok := extractBearerToken(r)
			if !ok {
				if m != nil {
					m.RecordAuthValidation(r.Context(), "failure")
				}
				writeAuthError(w, "unauthorized", "missing or malformed authorization header")
				return
			}

			// Parse and validate the JWT
			// SECURITY: Only allow RS256 — prevents algorithm confusion attacks
			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
				kidRaw, ok := t.Header["kid"]
				if !ok {
					return nil, domain.ErrInvalidToken
				}
				kid, ok := kidRaw.(string)
				if !ok {
					return nil, domain.ErrInvalidToken
				}
				return jwks.GetKey(r.Context(), kid)
			},
				jwt.WithValidMethods([]string{"RS256"}),
				jwt.WithLeeway(maxClockSkew),
			)

			if err != nil {
				slog.Debug("auth validation failed", "error", err)
				if m != nil {
					m.RecordAuthValidation(r.Context(), "failure")
				}
				writeAuthError(w, "unauthorized", "invalid or expired token")
				return
			}

			if !token.Valid {
				if m != nil {
					m.RecordAuthValidation(r.Context(), "failure")
				}
				writeAuthError(w, "unauthorized", "invalid token")
				return
			}

			// Extract principal from claims
			principal, err := extractPrincipal(token.Claims)
			if err != nil {
				slog.Debug("extracting principal", "error", err)
				if m != nil {
					m.RecordAuthValidation(r.Context(), "failure")
				}
				writeAuthError(w, "unauthorized", "invalid token claims")
				return
			}

			if m != nil {
				m.RecordAuthValidation(r.Context(), "success")
			}
			ctx := gw.ContextWithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return strings.TrimSpace(parts[1]), true
}

func extractPrincipal(claims jwt.Claims) (domain.Principal, error) {
	mc, ok := claims.(jwt.MapClaims)
	if !ok {
		return domain.Principal{}, domain.ErrInvalidToken
	}

	sub, _ := mc["sub"].(string)
	if sub == "" {
		return domain.Principal{}, domain.ErrInvalidToken
	}

	ptype := domain.PrincipalUser
	if typeStr, ok := mc["type"].(string); ok && typeStr == "service" {
		ptype = domain.PrincipalService
	}

	var scopes []domain.Scope
	if scopeStr, ok := mc["scopes"].(string); ok && scopeStr != "" {
		fields := strings.Fields(scopeStr)
		scopes = make([]domain.Scope, len(fields))
		for i, s := range fields {
			scopes[i] = domain.Scope(s)
		}
	}

	return domain.Principal{
		ID:     sub,
		Type:   ptype,
		Scopes: scopes,
	}, nil
}

func writeAuthError(w http.ResponseWriter, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(domain.ErrorResponse{
		Error:   errCode,
		Message: msg,
	}); err != nil {
		slog.Error("encoding error response", "error", err)
	}
}
