# Gateway Project Code Review

**Date:** 2026-02-14
**Reviewers:** 8 parallel agents (Security, Performance, Architecture, Simplicity, Silent Failures, Test Quality, Go Idioms, Data Safety)
**Scope:** All Go source files in `/home/fdf/go/gateway/` (~19 implementation files, ~15 test files)

---

## Executive Summary

The gateway project demonstrates strong software engineering fundamentals: clean hexagonal architecture, good domain separation, and thoughtful auth design (Option C hybrid JWT). The codebase is well-organized and mostly idiomatic Go.

**However, several cross-cutting issues were identified by multiple reviewers independently**, lending high confidence to these findings. The most critical involve silently ignored errors that can cause startup-time misconfigurations to manifest as runtime crashes, and a rate limiter memory leak.

| Severity | Count | Description |
|----------|-------|-------------|
| **P1** | 5 | Must fix before production |
| **P2** | 12 | Should fix within sprint |
| **P3** | 8 | Consider fixing |

---

## P1 Findings (Must Fix)

### P1-1: URL parsing errors silently ignored in router initialization

**File:** `internal/gateway/adapter/proxy/proxy.go:45-46`
**Flagged by:** Security, Silent Failures, Go Idioms, Data Safety (4/8 reviewers)
**Confidence:** 98

Invalid backend URLs (from env vars) cause nil pointer dereference on first proxied request. Gateway starts successfully but crashes in production.

```go
// Current (broken)
vectorDB, _ := url.Parse(vectorDBURL)
fileSvc, _ := url.Parse(fileServiceURL)

// Fix: return error from NewRouter
func NewRouter(vectorDBURL, fileServiceURL string, m *telemetry.GatewayMetrics) (*Router, error) {
    vectorDB, err := url.Parse(vectorDBURL)
    if err != nil {
        return nil, fmt.Errorf("parse vector DB URL: %w", err)
    }
    // ...
}
```

### P1-2: Unbounded rate limiter memory growth

**File:** `internal/gateway/adapter/inmem/ratelimiter.go`
**Flagged by:** Performance, Simplicity, Data Safety (3/8 reviewers)
**Confidence:** 98

`Cleanup()` method exists but is never called in production. The `buckets` map grows indefinitely with unique IPs. At 10K unique IPs/day, memory leaks ~320KB/day permanently.

```go
// Fix: start cleanup goroutine in main.go
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            rl.Cleanup()
        }
    }
}()
```

### P1-3: X-Forwarded-For header spoofable for rate limit bypass

**File:** `internal/gateway/middleware/ratelimit.go`
**Flagged by:** Security, Test Quality, Data Safety (3/8 reviewers)
**Confidence:** 90

Rate limiter keys on client IP, but if `X-Forwarded-For` is trusted without validation, attackers can rotate IPs to bypass rate limits entirely. The `clientIP()` function should only trust `X-Forwarded-For` when behind a known proxy.

### P1-4: JSON encoding errors silently ignored in error handlers

**File:** `middleware/recovery.go:26`, `middleware/auth.go:141`, `middleware/ratelimit.go:56`, `proxy/proxy.go:120`
**Flagged by:** Silent Failures, Go Idioms (2/8 reviewers)
**Confidence:** 95

All HTTP error responses ignore `json.NewEncoder(w).Encode()` errors. When encoding fails, clients get headers but no body, making debugging impossible.

```go
// Fix: log encoding failures
if err := json.NewEncoder(w).Encode(resp); err != nil {
    slog.Error("encoding error response", "error", err)
}
```

### P1-5: Missing concurrent rate limiter tests

**File:** `internal/gateway/adapter/inmem/ratelimiter_test.go`
**Flagged by:** Test Quality
**Confidence:** 90

Rate limiter uses `sync.Mutex` but has zero concurrent access tests. Given this is on the hot path of every request, concurrent safety must be verified.

---

## P2 Findings (Should Fix)

### P2-1: OTel metric registration errors silently ignored

**File:** `internal/platform/telemetry/telemetry.go:52-65`
**Flagged by:** Silent Failures, Go Idioms (2/8 reviewers)

7 metric creation errors ignored with `_`. If metrics fail to register, operators lose all observability.

### P2-2: Unwrapped errors (missing `%w` context)

**Files:** `jwks/client.go:52`, `telemetry/telemetry.go:22`, `server/server.go:43`
**Flagged by:** Go Idioms

Errors returned without wrapping lose context for debugging.

### P2-3: PrincipalType enum starts at zero without Unknown value

**File:** `internal/domain/principal.go:11-14`
**Flagged by:** Go Idioms
**Confidence:** 85

Uninitialized `PrincipalType` (zero value) is indistinguishable from `PrincipalUser`, risking accidental privilege assignment.

### P2-4: O(n) public path check on every request

**File:** `internal/gateway/middleware/auth.go:28`
**Flagged by:** Performance

`slices.Contains(publicPaths, r.URL.Path)` should be `map[string]struct{}` for O(1) lookup.

### P2-5: Proxy authorization allows requests when principal is missing

**File:** `internal/gateway/adapter/proxy/proxy.go:116-117`
**Flagged by:** Silent Failures
**Confidence:** 80

```go
if ok && !principal.HasScope(requiredScope) { // only checks if principal exists
```

If principal is missing (`!ok`), request proceeds without authorization check. Auth middleware should prevent this, but defense-in-depth requires explicit handling.

### P2-6: JWKS key parsing failures silently skipped

**File:** `internal/gateway/adapter/jwks/client.go:98-101`
**Flagged by:** Silent Failures, Data Safety

Malformed keys are skipped without logging. If all keys are invalid, auth fails with "key not found" errors that don't explain the root cause.

### P2-7: Environment variable parsing errors silently fall back to defaults

**File:** `internal/platform/config/config.go:55-71`
**Flagged by:** Silent Failures

Setting `RATE_LIMIT_RATE=abc` silently uses default 100. Should log a warning.

### P2-8: `statusWriter` duplicated in 3 files

**Files:** `middleware/logging.go:12-20`, `middleware/metrics.go`, `proxy/proxy.go:16-25`
**Flagged by:** Simplicity, Performance

Three copies of the same type. Extract to shared package.

### P2-9: Dead code: `TokenValidator` interface, `TokenClaims` struct

**Files:** `ports.go:18-20`, `domain/token.go:11-17`
**Flagged by:** Simplicity

Neither is implemented or used. YAGNI violations.

### P2-10: Missing request size limits

**Flagged by:** Security

No `http.MaxBytesReader` or body size enforcement. Design doc specifies 10MB for files, 1MB for API calls, but this is not implemented.

### P2-11: Scopes slice allocation in proxy hot path

**File:** `internal/gateway/adapter/proxy/proxy.go:87-91`
**Flagged by:** Performance

Allocates new string slice for every proxied request. Could cache serialized scopes at auth time.

### P2-12: Missing JWKS client error path tests

**Flagged by:** Test Quality

No tests for JWKS 4xx/5xx responses, malformed JSON, or network timeouts.

---

## P3 Findings (Consider)

| # | Finding | File | Source |
|---|---------|------|--------|
| 1 | Unnecessary `Router` interface (just aliases `http.Handler`) | `ports.go:60-62` | Simplicity |
| 2 | Over-abstracted telemetry attribute helpers (6 one-liner functions) | `telemetry/attrs.go` | Simplicity |
| 3 | Unused config fields: `VectorDBAddr`, `FileServiceAddr`, `IdentityAddr` | `config/config.go` | Simplicity |
| 4 | `RefreshToken` field never populated in production | `domain/token.go:6` | Simplicity |
| 5 | `envOr` helper duplicated in 3 cmd files | `cmd/*/main.go` | Simplicity |
| 6 | No memory profiling in load tests | `test/loadtest/` | Performance |
| 7 | P99 threshold too loose (500ms target for local proxy) | `test/loadtest/` | Performance |
| 8 | Slice append without preallocation in scope parsing | `auth.go:124-129` | Go Idioms |

---

## Requirements Checklist

| Requirement | Status | Evidence |
|------------|--------|----------|
| API Gateway as single entry point | :white_check_mark: Implemented | `cmd/gateway/main.go`, all traffic flows through middleware chain |
| Authentication (API keys + JWTs) | :warning: Partial | JWT auth fully implemented. API key exchange not implemented (design doc acknowledges this) |
| Rate limiting | :white_check_mark: Implemented | Token bucket per-IP via `inmem.RateLimiter`, `middleware/ratelimit.go` |
| Request routing to internal services | :white_check_mark: Implemented | `proxy/proxy.go` routes `/v1/vectors/*` and `/v1/files/*` |
| Identity Service (separate boundary) | :white_check_mark: Implemented | `cmd/mockidentity/main.go` - separate process, JWKS + token issuance |
| Vector DB Service (provider-agnostic) | :white_check_mark: Stubbed | Mock backend, routed through gateway. Interface allows swapping. |
| File Service (CRUD operations) | :white_check_mark: Stubbed | Mock backend, routed through gateway. Interface allows swapping. |
| Design document | :white_check_mark: Excellent | `plans/20260212-identity-service-separation.md` - thorough analysis of 4 options |
| Architecture & request flow | :white_check_mark: Documented | Detailed flow diagrams, trust boundaries, scaling tiers |
| Tradeoffs & assumptions | :white_check_mark: Documented | Comparison matrix, explicit assumptions, non-goals |
| Failure modes & scaling | :white_check_mark: Documented | 4-tier scaling model, failure mode table, graceful degradation |
| Diagrams | :white_check_mark: Present | ASCII diagrams for all 4 options, trust boundaries, scaling tiers |
| Improvements with more time | :white_check_mark: Documented | 9 items including token revocation, OIDC, distributed rate limiting |
| Clear system boundaries | :white_check_mark: Implemented | Domain has zero outward deps, clean port/adapter separation |
| Understandable/extensible/operable | :white_check_mark: Strong | Hexagonal architecture, `cmd/` per service, configurable via env vars |

**Overall: 13/14 requirements met. API key auth is the only gap (acknowledged in design).**

---

## Architecture Assessment (Grade: A-)

The architecture reviewer confirmed:

- **Hexagonal architecture correctly applied.** Domain layer (`internal/domain/`) has zero dependencies on infrastructure. All external concerns are behind port interfaces (`ports.go`).
- **Dependency direction is correct.** Adapters depend on domain, never the reverse. Infrastructure (`platform/`) is properly separated.
- **Clean middleware chain pattern.** `middleware.Chain()` composes handlers in correct order. Each middleware is a single-responsibility function.
- **Scaling story is convincing.** Design doc shows 4-tier evolution from in-memory to distributed, where each step is an adapter swap behind stable interfaces.

**Weakness:** Middleware ordering is convention-based (not enforced at compile time). Misorderings (e.g., auth before recovery) would cause subtle bugs.

---

## Test Assessment

**Strengths:**
- Integration tests cover full request lifecycle (auth, routing, rate limiting, request ID propagation)
- Load tests with vegeta (baseline, ramp-up, mixed traffic)
- Unit tests for middleware chain, logging, recovery, rate limiter, JWKS client, proxy

**Gaps (P1/P2):**
- No concurrent rate limiter tests
- No JWT edge case tests (empty kid, missing sub, tampered claims)
- No JWKS error path tests (network failures, malformed responses)
- No proxy backend failure tests (timeout, 5xx from backend)
- No `X-Forwarded-For` parsing tests

---

## Recommendations

### Immediate (before any deployment)
1. Fix URL parsing in `NewRouter` to return error
2. Start rate limiter cleanup goroutine
3. Validate/restrict `X-Forwarded-For` trust
4. Handle JSON encoding errors in error handlers

### This sprint
5. Add `%w` wrapping to all returned errors
6. Add `PrincipalUnknown` zero value to enum
7. Extract shared `statusWriter`
8. Delete dead code (`TokenValidator`, `TokenClaims`, unused config fields)
9. Add concurrent rate limiter tests
10. Add JWKS error path tests

### Next sprint
11. Implement request body size limits
12. Add memory profiling to load tests
13. Consider caching serialized scopes in Principal
14. Tighten load test P99 thresholds

---

## Review Methodology

8 specialized review agents ran in parallel, each examining all project files from their domain perspective:

| Agent | Files Reviewed | Findings | Grade |
|-------|---------------|----------|-------|
| Security | 18 | 8 (2 P1, 4 P2, 2 P3) | B |
| Performance | 18 | 5 (3 P1, 2 P2) | B |
| Architecture | 20 | 2 (informational) | A- |
| Simplicity | 24 | 10 (3 P1, 4 P2, 3 P3) | B |
| Silent Failures | 18 | 10 (3 P1, 6 P2, 1 P3) | B- |
| Test Quality | 15 | 12 (7 P1, 3 P2, 2 P3) | B- |
| Go Idioms | 24 | 10 (0 P1, 6 P2, 4 P3) | B+ |
| Data Safety | 18 | 7 (2 P1, 4 P2, 1 P3) | B |

**Cross-cutting findings** (flagged by 3+ reviewers independently) receive highest confidence:
- URL parsing errors (4 reviewers)
- X-Forwarded-For spoofing (3 reviewers)
- Rate limiter cleanup (3 reviewers)
