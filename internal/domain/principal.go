package domain

import "slices"

// Scope represents an authorization scope (e.g. "vectors:read", "files:write").
type Scope string

// PrincipalType distinguishes between human users and service accounts.
type PrincipalType int

const (
	PrincipalUnknown PrincipalType = iota
	PrincipalUser
	PrincipalService
)

func (pt PrincipalType) String() string {
	switch pt {
	case PrincipalUser:
		return "user"
	case PrincipalService:
		return "service"
	default:
		return "unknown"
	}
}

// Principal represents an authenticated entity (user or service account).
type Principal struct {
	ID     string
	Type   PrincipalType
	Scopes []Scope
}

// HasScope reports whether the principal has the given scope.
func (p Principal) HasScope(s Scope) bool {
	return slices.Contains(p.Scopes, s)
}
