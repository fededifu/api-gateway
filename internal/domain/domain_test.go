package domain_test

import (
	"errors"
	"testing"

	"gateway/internal/domain"
)

func TestPrincipalType(t *testing.T) {
	if domain.PrincipalUser.String() != "user" {
		t.Errorf("expected 'user', got %q", domain.PrincipalUser.String())
	}
	if domain.PrincipalService.String() != "service" {
		t.Errorf("expected 'service', got %q", domain.PrincipalService.String())
	}
}

func TestPrincipalHasScope(t *testing.T) {
	p := domain.Principal{
		ID:     "user-1",
		Type:   domain.PrincipalUser,
		Scopes: []domain.Scope{"vectors:read", "files:read"},
	}

	if !p.HasScope("vectors:read") {
		t.Error("expected principal to have scope vectors:read")
	}
	if !p.HasScope("files:read") {
		t.Error("expected principal to have scope files:read")
	}
	if p.HasScope("vectors:write") {
		t.Error("expected principal to NOT have scope vectors:write")
	}
	if p.HasScope("") {
		t.Error("expected principal to NOT have empty scope")
	}
}

func TestPrincipalHasAnyScopeEmptyScopes(t *testing.T) {
	p := domain.Principal{ID: "user-1", Type: domain.PrincipalUser}

	if p.HasScope("anything") {
		t.Error("principal with no scopes should not have any scope")
	}
}

func TestTokenPairFields(t *testing.T) {
	tp := domain.TokenPair{
		AccessToken: "access",
		ExpiresIn:   900,
		TokenType:   "Bearer",
	}
	if tp.AccessToken != "access" {
		t.Errorf("unexpected access token: %q", tp.AccessToken)
	}
	if tp.ExpiresIn != 900 {
		t.Errorf("unexpected expires_in: %d", tp.ExpiresIn)
	}
	if tp.TokenType != "Bearer" {
		t.Errorf("unexpected token type: %q", tp.TokenType)
	}
}

func TestErrorResponseFields(t *testing.T) {
	e := domain.ErrorResponse{
		Error:   "unauthorized",
		Message: "invalid or expired token",
	}
	if e.Error != "unauthorized" {
		t.Errorf("unexpected error: %q", e.Error)
	}
	if e.Message != "invalid or expired token" {
		t.Errorf("unexpected message: %q", e.Message)
	}
}

func TestDomainErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrUnauthorized", domain.ErrUnauthorized, "unauthorized"},
		{"ErrForbidden", domain.ErrForbidden, "forbidden"},
		{"ErrNotFound", domain.ErrNotFound, "not found"},
		{"ErrRateLimited", domain.ErrRateLimited, "rate limited"},
		{"ErrInvalidCredentials", domain.ErrInvalidCredentials, "invalid credentials"},
		{"ErrTokenExpired", domain.ErrTokenExpired, "token expired"},
		{"ErrInvalidToken", domain.ErrInvalidToken, "invalid token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.msg {
				t.Errorf("expected %q, got %q", tt.msg, tt.err.Error())
			}
		})
	}

	// Verify error wrapping works
	wrapped := errors.Is(domain.ErrInvalidCredentials, domain.ErrUnauthorized)
	if wrapped {
		t.Error("ErrInvalidCredentials should not be ErrUnauthorized (they are separate sentinels)")
	}
}
