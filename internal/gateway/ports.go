package gateway

import (
	"context"
	"crypto/rsa"
	"net/http"

	"gateway/internal/domain"
)

// JWKSProvider fetches and caches public keys from the Identity Service's JWKS endpoint.
type JWKSProvider interface {
	// GetKey returns the public key for the given key ID.
	GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// RateLimiter decides whether a request identified by key should be allowed.
type RateLimiter interface {
	Allow(key string) RateLimitResult
}

// RateLimitResult holds the outcome of a rate limit check.
type RateLimitResult struct {
	Allowed    bool
	RetryAfter int // seconds until next token available; 0 if allowed
}

// StatusWriter wraps http.ResponseWriter to capture the status code.
type StatusWriter struct {
	http.ResponseWriter
	Code int
}

func (sw *StatusWriter) WriteHeader(code int) {
	sw.Code = code
	sw.ResponseWriter.WriteHeader(code)
}

// PrincipalFromContext extracts the authenticated principal from a request context.
func PrincipalFromContext(ctx context.Context) (domain.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(domain.Principal)
	return p, ok
}

// ContextWithPrincipal stores the authenticated principal in the context.
func ContextWithPrincipal(ctx context.Context, p domain.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

type principalKey struct{}

// RequestIDFromContext extracts the request ID from the context.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// ContextWithRequestID stores the request ID in the context.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

type requestIDKey struct{}
