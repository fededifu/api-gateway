# API Gateway System — Design Document

**Date:** 2026-02-16
**Status:** Tier 0 implementation complete (API Gateway component)

---

## 1. High-Level Architecture and Request Flow

### System Overview

The system is composed of four services, one of which (the API Gateway) is fully implemented. The other three are stubbed as mock services with well-defined interfaces.

```
                           ┌──────────────────────────────────────────────┐
                           │              UNTRUSTED ZONE                  │
                           │                                              │
                           │   Client (curl, SDK, browser)                │
                           │      │                                       │
                           └──────┼───────────────────────────────────────┘
                                  │  HTTPS (TLS terminated upstream)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DMZ — API Gateway (:8080)                                              │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Middleware Chain (outermost → innermost)                       │    │
│  │                                                                 │    │
│  │  Metrics → RequestID → Logging → Recovery → BodyLimit →        │    │
│  │  RateLimit (per-IP) → Auth (JWT validation) → Router           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  Ports:                    Adapters:                                     │
│  ┌──────────────┐         ┌──────────────────────────────────┐         │
│  │ JWKSProvider │ ◀──────▶│ jwks.Client (HTTP + cache)       │         │
│  │ RateLimiter  │ ◀──────▶│ inmem.RateLimiter (token bucket) │         │
│  └──────────────┘         └──────────────────────────────────┘         │
│                                                                         │
└───────────────┬────────────────┬────────────────┬───────────────────────┘
                │                │                │
          HTTP reverse      HTTP reverse      HTTP reverse
          proxy             proxy             proxy
                │                │                │
        ┌───────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
        │  Identity    │ │  Vector DB   │ │    File      │
        │  Service     │ │  Service     │ │   Service    │
        │  :8081       │ │  :8082       │ │   :8083      │
        │  (mock)      │ │  (mock)      │ │   (mock)     │
        └──────────────┘ └──────────────┘ └──────────────┘
```

### Request Flow: Authenticated API Call

A request to `POST /v1/vectors/ns1` with a valid JWT follows this path:

```
1. Client sends request with Authorization: Bearer <JWT>
        │
2. Metrics middleware records start time
        │
3. RequestID middleware assigns UUID (or preserves X-Request-ID header)
        │
4. Logging middleware wraps ResponseWriter to capture status code
        │
5. Recovery middleware installs panic handler (defers recover())
        │
6. BodyLimit middleware wraps Body with http.MaxBytesReader (1 MB)
        │
7. RateLimit middleware extracts client IP from RemoteAddr,
   checks per-IP token bucket → if exhausted, returns 429 + Retry-After
        │
8. Auth middleware:
   a. Checks if path is public (/healthz, /readyz, /metrics, /auth/token, /.well-known/jwks.json)
   b. Extracts Bearer token from Authorization header
   c. Parses JWT, enforces RS256-only (prevents algorithm confusion)
   d. Looks up public key by kid via JWKSProvider (cached, min 5-min refresh)
   e. Validates signature, exp, iat with 30-second clock skew tolerance
   f. Extracts Principal (sub, type, scopes) from claims
   g. Stores Principal in request context
        │
9. Router:
   a. Matches path prefix → backend (/v1/vectors → Vector DB, /v1/files → File Service)
   b. Checks scope: read methods need {resource}:read, write methods need {resource}:write
   c. Strips Authorization header (backends don't see client tokens)
   d. Injects X-Principal-ID, X-Principal-Scopes, X-Request-ID headers
   e. Reverse-proxies to backend service
        │
10. Logging middleware logs: method, path, status, duration_ms, request_id, principal_id, remote_addr
```

### Request Flow: Token Issuance

```
1. Client sends POST /auth/token with {"username": "...", "password": "..."}
   or {"api_key": "..."}
        │
2. Middleware chain runs (Metrics, RequestID, Logging, Recovery, BodyLimit, RateLimit)
        │
3. Auth middleware skips /auth/token (public path)
        │
4. Router proxies to Identity Service as a public route
   (no scope check, no principal injection, preserves original headers)
        │
5. Identity Service validates credentials, issues JWT signed with RS256 private key
        │
6. Client receives {"access_token": "...", "expires_in": 900, "token_type": "Bearer"}
```

---

## 2. Component Responsibilities and Boundaries

### API Gateway (fully implemented)

**Responsibility:** Single entry point for all client traffic. Enforces authentication, authorization, rate limiting, and observability. Routes to internal services.

**Owns:**
- Middleware pipeline orchestration
- JWT signature validation (using cached public key from Identity Service)
- Per-IP rate limiting (token bucket algorithm)
- Scope-based authorization enforcement
- Request/response logging and metrics collection
- Principal propagation to backend services via headers
- Health check endpoints (`/healthz`, `/readyz`)

**Does not own:**
- Token issuance or credential storage (Identity Service's job)
- Business logic for vectors or files (backend services' job)
- TLS termination (assumed upstream reverse proxy)

**Package structure:**
```
internal/
├── domain/           # Shared domain types: Principal, Scope, TokenPair, ErrorResponse, sentinel errors
├── gateway/
│   ├── ports.go      # Port interfaces: JWKSProvider, RateLimiter
│   ├── middleware/    # Auth, RateLimit, Logging, Metrics, Recovery, RequestID, BodyLimit, Chain
│   └── adapter/
│       ├── jwks/     # JWKS HTTP client with caching
│       ├── inmem/    # In-memory token bucket rate limiter
│       └── proxy/    # HTTP reverse proxy router with scope enforcement
├── platform/
│   ├── config/       # Environment-based configuration
│   ├── server/       # Graceful shutdown HTTP server
│   └── telemetry/    # OpenTelemetry + Prometheus metrics
└── testutil/         # Shared test helpers (key generation, mock handlers, token issuance)
```

### Identity Service (mock implementation)

**Responsibility:** Authenticates credentials and issues JWTs. Publishes public keys for token verification.

**Owns:**
- Credential validation (username/password, API keys)
- JWT creation and signing (RS256 private key)
- JWKS endpoint (publishes public keys for gateway verification)
- User and API key storage

**Current mock implementation:**
- In-memory user store (admin:admin, user:password)
- In-memory API key store (test-api-key-1 → service-account-1)
- RSA 2048-bit key pair generated on startup
- All authenticated principals receive full scopes
- 15-minute token TTL

**Boundary with Gateway:** The gateway never sees the private key. It only fetches public keys from `GET /.well-known/jwks.json` and validates JWT signatures locally. The only other interaction is proxying client `POST /auth/token` requests.

### Vector Database Service (mock implementation)

**Responsibility:** Provider-agnostic interface for vector storage and search. Hides vendor-specific APIs (Qdrant, Weaviate, Pinecone).

**Boundary with Gateway:** The gateway routes `/v1/vectors/*` requests and enforces `vectors:read` / `vectors:write` scopes. The gateway knows nothing about vector operations — it passes through the request body and path unchanged, injecting only principal headers.

**Current mock:** Echoes request details (method, path, principal_id, scopes, request_id) as JSON. Supports configurable simulated latency via `LATENCY_BASE` / `LATENCY_JITTER` environment variables.

### File Service (mock implementation)

**Responsibility:** CRUD operations for file objects. Abstracts storage backends (S3, GCS, local filesystem).

**Boundary with Gateway:** Identical to Vector DB — the gateway routes `/v1/files/*` with `files:read` / `files:write` scope enforcement.

**Current mock:** Same echo-style mock backend as Vector DB.

### Trust Boundaries

| Boundary | Trust Model |
|----------|------------|
| Client → Gateway | Zero trust. All input validated. JWTs verified cryptographically. |
| Gateway → Backend Services | Full trust. Backend services accept `X-Principal-ID` and `X-Principal-Scopes` headers injected by the gateway without re-verification. |
| Gateway → Identity Service (JWKS) | Trust the public key response. Gateway only accepts RS256 keys. Caches with min-refresh interval to prevent abuse. |

---

## 3. Key Tradeoffs and Assumptions

### Tradeoffs

| Decision | Chosen | Alternative | Why |
|----------|--------|-------------|-----|
| **Auth pattern** | Hybrid JWT: Identity issues tokens, Gateway validates locally | Per-request auth call to Identity Service | Eliminates network call on the hot path. JWT validation is a local CPU operation (~microseconds). See [identity-service-separation.md](./20260212-identity-service-separation.md) Option C analysis. |
| **Rate limiting** | Per-IP token bucket, in-memory | Per-principal, Redis-backed | Per-IP runs before auth (cheap, protects system). In-memory is correct for single-instance Tier 0. The `RateLimiter` interface allows Redis swap without code changes. |
| **Communication protocol** | HTTP/REST + JSON everywhere | gRPC for internal services | At Tier 0, debuggability with curl and zero infrastructure trumps serialization efficiency. See [Communication Protocol Evolution](./20260212-identity-service-separation.md#communication-protocol-evolution). |
| **Scope enforcement** | In the proxy router, after auth | In a separate authorization middleware | Scopes are per-route (vectors:read, files:write). Checking in the router co-locates the scope requirement with the route definition, reducing indirection. |
| **Principal propagation** | HTTP headers (X-Principal-ID, X-Principal-Scopes) | Forwarding the original JWT to backends | Stripping the JWT and injecting headers means backends don't need JWT libraries. The gateway is the single point of token validation. |
| **Logging** | slog with JSON handler | zerolog or zap | slog is stdlib (Go 1.21+), zero external dependencies, sufficient for structured JSON logging. The interface is standard — swapping implementations is trivial. |
| **Metrics** | OpenTelemetry + Prometheus exporter | Custom metrics or StatsD | OTel is the vendor-neutral standard. Prometheus exporter gives scrape-ready `/metrics` endpoint with no additional infrastructure. |
| **Configuration** | Environment variables with defaults | YAML/TOML config file | Environment variables are the 12-factor standard and work in every deployment model. Defaults allow `go run ./cmd/gateway` with zero config. |

### Assumptions

- **Single machine deployment** at Tier 0. All services run on localhost with different ports.
- **No TLS at the gateway.** A reverse proxy or load balancer handles TLS termination in production.
- **No token revocation** beyond expiry. Short TTLs (15 minutes) limit the damage window. A JTI blacklist would be the first addition for production.
- **No refresh tokens** in the current mock. The mock Identity Service issues access tokens only. A real implementation would support refresh token rotation.
- **X-Forwarded-For is untrusted.** Rate limiting uses `RemoteAddr` directly. A production deployment behind a load balancer would need a trusted proxy list.
- **Backend services are always available.** No circuit breaking is implemented. The proxy passes through errors from backends. The `ServiceProxy` interface supports adding circuit breaking as a wrapper.
- **Reviewers will run this.** The system must start with `go run` and be testable with `curl`. This assumption drove every simplicity-over-performance decision.

---

## 4. Failure Modes and Scaling Considerations

### Failure Modes

| Component Down | Impact | Gateway Behavior |
|----------------|--------|-----------------|
| **Identity Service** | Cannot issue new tokens or exchange API keys. JWKS endpoint unreachable. | Existing JWTs continue to work — the gateway validates locally with cached public keys. New logins fail. JWKS cache persists indefinitely. The system degrades gracefully. |
| **Vector DB Service** | Vector operations unavailable | Gateway proxies request, receives connection error, returns 502 to client. File operations unaffected. |
| **File Service** | File operations unavailable | Same as Vector DB — 502 for `/v1/files/*`, other routes unaffected. |
| **Gateway panic** | Request fails for that single request | Recovery middleware catches the panic, logs full stack trace with request ID, returns 500 JSON error. The process continues serving subsequent requests. |
| **Rate limiter memory growth** | Unbounded bucket map | Cleanup goroutine runs every 5 minutes, evicting buckets not seen in 10 minutes. Bounds memory to O(active_IPs_in_last_10_min). |
| **JWKS key rotation** | Gateway has stale public keys | The JWKS client re-fetches when a `kid` is not found in cache (with min 5-minute cooldown). New keys are picked up within one refresh cycle. Old tokens signed with the previous key fail if the JWKS response no longer includes that key. |

### What the Design Gets Right for Resilience

1. **Stateless JWT validation** — the gateway's core function (authenticate requests) survives Identity Service outages.
2. **Independent failure domains** — Vector DB going down doesn't affect File Service routing and vice versa.
3. **Panic isolation** — Recovery middleware prevents a single bad request from crashing the process.
4. **Graceful shutdown** — The server listens for SIGINT/SIGTERM, stops accepting new connections, and drains in-flight requests with a 10-second timeout.

### Scaling Considerations

The scaling path is documented in detail in the [Evolutionary Scaling Tiers](./20260212-identity-service-separation.md#evolutionary-scaling-tiers) and [Communication Protocol Evolution](./20260212-identity-service-separation.md#communication-protocol-evolution) sections. Summary:

**Tier 0 → Tier 1 (multiple gateway instances):**
- Swap `inmem.RateLimiter` for a Redis-backed implementation behind the same `RateLimiter` interface.
- Add a load balancer in front of gateway instances.
- JWKS cache is per-instance and works unchanged — each instance fetches independently.
- gRPC adapters for Vector DB and File Service internal communication (adapter swap, no domain changes).

**Tier 1 → Tier 2 (high traffic):**
- Event-driven async for audit logging, file processing pipelines, and vector batch indexing (NATS).
- SSE for client-facing async status updates.
- In-memory stores in Identity Service swap for Postgres/Redis.

**Tier 2 → Tier 3 (global scale):**
- Service mesh (Istio/Linkerd) with mTLS for all internal communication.
- Kafka replaces NATS for cross-region event replication.
- Regional gateway and Identity Service deployments.

**The hexagonal architecture ensures each tier is an adapter swap, not a rewrite.** The port interfaces (`JWKSProvider`, `RateLimiter`) and the middleware chain remain stable across all tiers.

---

## 5. What We Would Improve or Extend With More Time

### High Priority

1. **Token revocation** — Redis-backed JTI blacklist checked in the auth middleware. Short TTLs (15 min) mitigate but don't eliminate the risk window.

2. **Circuit breaking for backend proxies** — Wrap `httputil.ReverseProxy` with a circuit breaker (closed → open after N failures → half-open on timeout). The proxy router already isolates backends — adding a per-backend breaker is a wrapper around the existing reverse proxy.

3. **Per-principal rate limiting** — The current per-IP limiter runs before auth. A second layer after auth would enforce fair usage per authenticated identity. The `RateLimiter` interface already supports arbitrary keys.

4. **Real Identity Service implementation** — Replace the mock with: persistent user/key store, refresh token rotation, configurable scopes per user, password hashing (bcrypt/argon2).

5. **Audit logging** — Record all auth events (login, token refresh, failed attempts, rate limit hits) to a structured log or event bus. Currently, these are in the general request log but not in a dedicated audit trail.

### Medium Priority

6. **OIDC provider integration** — Allow login via Google, GitHub, etc. The hybrid JWT model supports this naturally — the Identity Service becomes an OIDC facade.

7. **Content-Type enforcement** — Require `application/json` for API endpoints. Currently, the gateway passes through any Content-Type.

8. **Request validation** — Validate request bodies against schemas before proxying. Currently, backends receive whatever the client sends.

9. **Distributed tracing** — OpenTelemetry trace propagation across gateway → backend. The request ID propagation is a foundation, but real tracing needs span context and trace IDs.

10. **Load testing in CI** — The `test/loadtest/` package exists but isn't integrated into a CI pipeline with performance regression detection.

### Lower Priority

11. **Key rotation automation** — Scheduled RSA key rotation in the Identity Service with JWKS versioning (N and N-1 keys active).

12. **Request throttling by cost** — Vector search is more expensive than file metadata retrieval. Weight rate limits by endpoint cost, not just request count.

13. **Response caching** — Cache idempotent GET responses at the gateway for backends that support ETag/Last-Modified.

14. **Admin API** — Endpoints for managing rate limits, viewing active principals, and triggering JWKS refresh.

15. **WebSocket / SSE support** — See [Communication Protocol Evolution](./20260212-identity-service-separation.md#communication-protocol-evolution) Tier 2 for when streaming earns its complexity cost.
