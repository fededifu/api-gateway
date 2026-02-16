# Identity Service Separation: Design Options

**Date:** 2026-02-12
**Status:** Option C Approved - Expanding Design

## Problem

The API Gateway needs to authenticate every incoming request. The question is: where does authentication logic live and how does the gateway communicate with it?

The CLAUDE.md spec already hints at the answer: the Identity Service "is treated as a separate service or logical boundary." We need to decide what "separate" means concretely and what tradeoffs each option carries.

## Driving Principles

- **Single Responsibility:** The gateway routes and enforces policy. It should not own auth logic.
- **Scalability:** Auth is on the hot path of every request. It must not become a bottleneck.
- **Extensibility:** Adding OAuth2, OIDC, or mTLS later should not require rewriting the gateway.
- **Showcase clarity:** This is a portfolio piece. The separation must be visible and instructive.

---

## Option A: Embedded Library (Separate Go Module, Same Process)

The Identity Service is a separate Go module (`identity/`) imported by the gateway as a dependency. Auth logic runs in-process.

```
┌──────────────────────────────────────────┐
│              Gateway Process              │
│                                          │
│  HTTP Handler → Auth Middleware → Router  │
│                    │                     │
│            ┌──────────────┐              │
│            │  identity/   │              │
│            │  (Go module) │              │
│            └──────────────┘              │
└──────────────────────────────────────────┘
```

**Pros:**
- Zero network latency for auth checks
- Simplest to implement, test, and debug
- No serialization/deserialization overhead
- Single binary deployment
- Easy to refactor into a separate service later (interfaces stay the same)

**Cons:**
- Not truly separate at runtime — scales only with the gateway
- A bug or panic in auth logic can crash the gateway
- Cannot be deployed, versioned, or scaled independently
- Doesn't demonstrate service-to-service communication patterns
- Updating auth logic requires redeploying the gateway

**Best for:** Prototypes, monoliths, or when auth is simple and unlikely to change independently.

---

## Option B: Separate HTTP Microservice

The Identity Service runs as its own HTTP server. The gateway calls it over HTTP on every request (or on cache miss).

```
┌────────────────────┐         HTTP         ┌────────────────────┐
│   API Gateway      │ ──────────────────▶  │  Identity Service  │
│   :8080            │ ◀──────────────────  │  :8081             │
│                    │    POST /auth/verify  │                    │
│  middleware calls  │    200 {principal}    │  validates tokens  │
│  identity client   │                      │  manages keys      │
└────────────────────┘                      └────────────────────┘
```

**Pros:**
- True runtime separation — deploy, scale, version independently
- Clear service boundary visible in the architecture
- Can be written in a different language if needed
- Fault isolation: identity crash doesn't take down the gateway
- Demonstrates real microservice communication patterns

**Cons:**
- Network latency on every auth call (mitigated with caching)
- Requires service discovery or hardcoded addresses
- More complex error handling (timeouts, retries, circuit breaking)
- HTTP overhead for internal service calls (serialization, headers)
- Operational burden: two processes to run, monitor, deploy

**Best for:** Production systems where auth evolves independently or handles complex flows (OAuth2, federation).

---

## Option C: Hybrid — JWT Validation at Gateway + Identity as Token Issuer

The Identity Service is a separate service responsible for **issuing** tokens (login, API key exchange, token refresh). The gateway validates JWTs **locally** using the Identity Service's public key — no per-request call.

```
                    ┌──────────────────┐
  Login/Token ─────▶│ Identity Service │──── Issues JWT (signed with private key)
  Refresh           │ :8081            │──── Publishes public key (JWKS)
                    └──────────────────┘
                              │
                         JWKS endpoint
                         (fetched once,
                          cached)
                              │
                    ┌─────────▼────────┐
  API Requests ───▶ │   API Gateway    │──── Validates JWT locally (public key)
                    │   :8080          │──── Extracts principal from claims
                    │                  │──── No per-request call to Identity
                    └──────────────────┘
```

**Request flow:**

1. Client authenticates once via Identity Service (`POST /auth/token`) — gets a JWT
2. Client sends JWT in `Authorization` header on all subsequent API requests
3. Gateway validates the JWT signature locally using a cached public key
4. Gateway extracts the principal (user ID, scopes) from JWT claims
5. No network call to Identity Service on the hot path

**For API key auth:** Gateway makes a single call to Identity Service to exchange the API key for a short-lived JWT or principal. This can be cached with a TTL.

**Pros:**
- Best of both worlds: true service separation + near-zero auth latency
- The most common production pattern (used by Auth0, Keycloak, AWS Cognito, etc.)
- Gateway stays stateless — JWT carries all the context it needs
- Identity Service can evolve independently (new auth methods, OIDC, federation)
- Scales naturally: gateway instances don't contend on a shared auth service
- Clear separation of concerns: Identity **issues**, Gateway **enforces**
- Demonstrates understanding of real-world auth architecture

**Cons:**
- Token revocation requires extra work (short TTLs, or optional revocation list in Redis)
- Key rotation needs a JWKS endpoint and graceful rollover (support N and N-1 keys)
- Slightly more complex initial implementation than Option A
- JWT size grows with claims — large tokens add request overhead

**Best for:** Systems that need both clean separation and high performance. The industry standard approach.

---

## Option D: Sidecar / External Auth (Envoy ext_authz pattern)

Auth logic runs as a sidecar process alongside the gateway. The gateway delegates auth decisions to the sidecar via a local socket or localhost HTTP.

```
┌─────────────────────────────────────────┐
│            Pod / Host                    │
│                                         │
│  ┌──────────────┐    ┌───────────────┐  │
│  │ API Gateway  │───▶│ Auth Sidecar  │  │
│  │ :8080        │◀───│ :9090 (local) │  │
│  └──────────────┘    └───────────────┘  │
│                                         │
└─────────────────────────────────────────┘
```

**Pros:**
- Language-agnostic auth sidecar
- Follows service mesh patterns (Envoy, Istio)
- Gateway is completely auth-unaware — pure routing

**Cons:**
- Overkill for a 4-service showcase system
- Adds infrastructure complexity (sidecar lifecycle, health checks)
- Still has local network latency (though minimal via Unix socket)
- Harder to understand for reviewers unfamiliar with service mesh patterns
- Doesn't align well with "demonstrate Go design quality" goal

**Best for:** Kubernetes/service mesh environments where auth policy is managed at the infrastructure layer.

---

## Comparison Matrix

| Criteria                     | A: Library | B: HTTP Service | C: Hybrid JWT | D: Sidecar |
|------------------------------|:----------:|:---------------:|:-------------:|:----------:|
| Runtime separation           |     No     |       Yes       |      Yes      |    Yes     |
| Auth latency per request     |    ~0      |    1-5ms        |     ~0        |   <1ms     |
| Independent scaling          |     No     |       Yes       |      Yes      |    Yes     |
| Implementation complexity    |    Low     |     Medium      |    Medium     |   High     |
| Fault isolation              |     No     |       Yes       |      Yes      |    Yes     |
| Demonstrates service design  |   Weak     |     Strong      |   Strongest   |   Strong   |
| Production realism           |    Low     |     High        |    Highest    |   Medium   |
| Showcase value               |    Low     |     Medium      |     High      |   Medium   |

---

## Recommendation: Option C — Hybrid JWT

**Why:**

1. **It's how the industry does it.** Auth0, Firebase, Keycloak, AWS Cognito all follow this pattern. Choosing it shows you understand real auth architecture, not just textbook microservices.

2. **SRP is properly applied.** Identity Service owns credential validation and token issuance. Gateway owns token verification and policy enforcement. Neither does the other's job.

3. **Scalability comes for free.** Adding more gateway instances doesn't increase load on Identity Service — JWT validation is local. The only calls to Identity Service are login/refresh, which are low-frequency compared to API calls.

4. **It's the right level of complexity for a showcase.** Option A is too simple to demonstrate anything. Option B adds network overhead for no architectural gain (you're calling auth on every request). Option D is infrastructure theatre for a 4-service system.

5. **It naturally handles the dual auth model** the spec requires (API keys + JWTs). API keys get exchanged for JWTs once. JWTs are self-contained after that.

### What we'd implement:

- **Identity Service:** Token issuance endpoint (`POST /auth/token`), JWKS endpoint (`GET /.well-known/jwks.json`), in-memory user/key store
- **Gateway auth middleware:** JWT signature validation using cached JWKS, principal extraction from claims, API key → JWT exchange (call to Identity Service, cached)
- **Shared domain types:** `Principal`, `AuthError`, `TokenClaims` — defined in a shared `domain/` package

---

## Scaling Considerations

### Evolutionary Scaling Tiers

The hybrid JWT architecture (Option C) combined with hexagonal design means scaling is an adapter-swap problem, not a rewrite problem. The domain logic — token validation, principal extraction, scope checking — never changes. What changes is which adapters are plugged in.

#### Tier 0: Showcase (Current Implementation)

```
Client → Gateway (single instance) → Backend Services
              │
         In-memory stores
         Local rate limiter
         Local JWKS cache
```

- All state lives in-memory within a single process
- Rate limiting uses local token bucket counters
- Identity Service is a separate process on the same machine
- **Ceiling:** Single machine resources. Sufficient for demonstration and development.
- **What limits us:** Memory (in-memory stores), single process (no horizontal scaling)

#### Tier 1: Multiple Gateway Instances

```
Client → Load Balancer → Gateway #1, #2, #N → Backend Services
                              │
                         Shared rate limit state (Redis)
                         Local JWKS cache (per instance)
```

- Gateway scales horizontally with zero domain code changes — JWT validation is stateless
- **Adapter swap:** Rate limiter moves from local token bucket → Redis-backed token bucket
- Identity Service stays single-instance (token issuance is low-frequency)
- JWKS cache is per-gateway-instance (each fetches independently, public keys are identical)
- **What changes in code:** One adapter (rate limiter interface gets a Redis implementation)

#### Tier 2: High Traffic

```
Client → Load Balancer → Gateway cluster → Backend Services
                              │                    │
                         Redis (rate limits)   Database (persistent storage)
                              │
                         Identity Service (multiple instances)
                              │
                         Shared refresh token store
```

- In-memory user/key stores hit memory limits → swap for Postgres/Redis adapters
- Identity Service needs multiple instances → refresh token rotation needs shared storage
- JWKS cache switches from fetch-on-miss to background refresh goroutine
- **What changes in code:** Storage adapters (user store, API key store, refresh token store). Core logic untouched.

#### Tier 3: Global Scale

- Regional gateway deployments, each with cached JWKS
- Identity Service behind its own load balancer with database-backed stores
- Distributed rate limiting with approximate counters (accept some inaccuracy for availability)
- Add mTLS between services, distributed tracing, metrics collection
- **What changes in code:** Infrastructure and operational concerns. Domain logic still untouched.

### What Never Changes Across Tiers

| Component | Why It's Stable |
|-----------|----------------|
| JWT validation logic | Stateless signature check against cached public key — works identically at any scale |
| Principal extraction | Reads JWT claims — no external dependencies |
| Scope-based authorization | Pure function: does principal have required scope? |
| Auth middleware chain | Same pipeline regardless of backing infrastructure |
| Service routing | Path-based dispatch doesn't change with scale |

### What Changes (And How The Architecture Supports It)

| Scaling Need | Interface (Port) | Showcase Adapter | Scaled Adapter |
|---|---|---|---|
| Rate limiting | `RateLimiter` | In-memory token bucket | Redis-backed token bucket |
| User/key storage | `UserStore`, `APIKeyStore` | In-memory map | Postgres / DynamoDB |
| Refresh token tracking | `RefreshTokenStore` | In-memory map | Redis with TTL |
| JWKS fetching | `JWKSProvider` | HTTP fetch with in-memory cache | Background refresh goroutine + cache |
| Health checks | `HealthChecker` | Direct service ping | Service mesh / readiness probes |

The hexagonal architecture guarantees that every row in this table is an adapter swap behind a stable port interface. No domain logic changes, no service contract changes, no API changes.

### Rate Limiting Strategy

**Algorithm: Token Bucket** — the industry standard for API gateways (used by AWS API Gateway, Kong, Envoy). Allows controlled bursts while enforcing long-term rate limits.

**Keying strategy (layered):**

| Layer | Key | Purpose | Runs |
|-------|-----|---------|------|
| Global | (none) | Protect the system from total overload | Before auth |
| Per-IP | Client IP | Stop unauthenticated abuse | Before auth |
| Per-Principal | User ID from JWT | Fair usage enforcement | After auth |

Per-IP limiting happens **before** auth (cheap, protects the system). Per-principal limiting happens **after** auth (requires a valid token).

The `RateLimiter` port defines the interface. The initial implementation uses in-memory counters. The same interface accepts a Redis-backed implementation when horizontal scaling requires shared state.

### Communication Protocol Evolution

The system has two distinct communication boundaries with different requirements:

1. **External:** Client → Gateway (public API, consumer-facing)
2. **Internal:** Gateway → Identity / Vector DB / File Service (service-to-service)

These boundaries should not necessarily use the same protocol. The current tier analysis covers infrastructure scaling (storage, rate limiting); this section covers the protocol dimension.

#### Why HTTP/REST Everywhere at Tier 0

All communication — external and internal — uses JSON over HTTP at Tier 0. This is a deliberate choice, not a default:

- **Debuggable with curl, browser, Postman.** Portfolio reviewers will run this system. They should be able to `curl localhost:8080/v1/vectors` and get readable JSON back. That matters more than serialization efficiency.
- **Zero infrastructure beyond Go binaries.** No protobuf compiler, no schema registry, no message broker. `go run ./cmd/gateway` and you're done.
- **One protocol, one way things break.** At showcase scale, cognitive load is the bottleneck, not network throughput.
- **JSON is human-readable in logs.** Structured logging with readable payloads makes debugging trivial.

Introducing gRPC or Kafka at Tier 0 would be resume-driven development — it signals "I know these tools exist" but not "I know when to use them."

#### Tier 1: gRPC for Internal Services

When multiple gateway instances sit behind a load balancer, internal traffic scales linearly with gateway count. gRPC earns its complexity here.

**Gateway → Vector DB Service** is the strongest candidate:
- Vector search carries float arrays (embeddings). JSON serialization of 1536 floats (OpenAI dimension) is ~12KB; protobuf is ~6KB. That's a 2x reduction on every search request across every gateway instance.
- Proto files enforce the contract at compile time: embedding dimension, distance metric, top-k parameter. A typo in a JSON field name fails at runtime; a wrong type in a proto fails at compile time.
- HTTP/2 multiplexing: a single connection handles concurrent requests without head-of-line blocking.

**Gateway → File Service** is the second candidate:
- Binary framing avoids Base64 encoding overhead (33%) for file content.
- gRPC client-streaming for uploads and server-streaming for downloads provide clean backpressure semantics that HTTP/REST lacks.

**Gateway → Identity Service stays HTTP:**
- Token issuance is low-frequency (login/refresh). JSON overhead is irrelevant.
- JWKS is a standard HTTP endpoint. Any identity provider you'd swap in later (Keycloak, Auth0) speaks HTTP.

**External API stays REST.** Clients expect REST. The gateway becomes a protocol translator: REST on the outside, gRPC on the inside — the Backend-for-Frontend (BFF) pattern.

```
Client ──REST/JSON──▶ Gateway ──gRPC──▶ Vector DB Service
                          │──gRPC──▶ File Service
                          │──HTTP───▶ Identity Service
```

**Hexagonal impact:** The `ServiceProxy` port gets a gRPC adapter alongside the HTTP reverse proxy adapter. Domain logic doesn't change. The routing decision lives in the adapter layer.

#### Tier 2: Event-Driven for Async Pipelines

At high traffic, synchronous processing creates bottlenecks for operations that don't need immediate results. An event bus (NATS — lightweight, Go-native, no JVM dependency) earns its place for:

1. **Audit logging:** Every auth event published to a topic, consumed asynchronously. The gateway never blocks on audit persistence. Fire-and-forget with local buffering on broker unavailability.
2. **File processing pipeline:** Upload → 202 Accepted → async pipeline (virus scan, thumbnail generation, metadata extraction) → notify client when ready. Decouples upload latency from processing latency.
3. **Vector indexing pipeline:** Batch ingestion via events rather than synchronous insert-per-request. Vector DB Service consumes in batches, optimizes index updates.

**SSE (Server-Sent Events)** earns its place client-facing for async status updates:
- File processing progress: `GET /v1/files/{id}/status` as SSE stream.
- Streaming partial vector search results.
- Simpler than WebSocket (unidirectional, works through proxies, auto-reconnect in browser API). WebSocket only if the client needs to send messages back on the same connection.

```
Client ──REST──▶ Gateway ──gRPC──▶ Vector DB Service
       ◀──SSE───     │──gRPC──▶ File Service
                     │──HTTP───▶ Identity Service
                     │──NATS───▶ Audit / File Processing / Vector Indexing
```

#### Tier 3: gRPC Everywhere + Event Mesh

Multi-region deployment. All internal communication becomes gRPC with mTLS via service mesh (Istio/Linkerd). Identity Service moves to gRPC (token exchange volume justifies it at regional scale). NATS may be replaced by Kafka for cross-region event replication and long-term audit retention (compliance). CQRS may split read-heavy vector search from write-heavy vector ingestion with event-driven synchronization.

#### Protocol Adoption Summary

| Protocol | Tier 0 | Tier 1 | Tier 2 | Tier 3 |
|----------|--------|--------|--------|--------|
| HTTP/REST (external) | All communication | Client → Gateway | Client → Gateway | Client → Gateway |
| HTTP/REST (internal) | All internal | Identity only | Identity only | — |
| gRPC (internal) | — | Vector DB, File Svc | Vector DB, File Svc | All internal |
| SSE (client-facing) | — | — | Async status updates | Streaming search |
| Event bus (NATS) | — | — | Audit, file pipeline, vector indexing | — |
| Event bus (Kafka) | — | — | — | Cross-region, compliance |
| WebSocket | — | — | Only if bidirectional client need | Real-time collaboration |

#### Why Hexagonal Architecture Makes This Cheap

Each row in the table above is an adapter swap behind a stable port interface. The domain logic — JWT validation, scope checking, rate limiting decisions, vector search routing — never changes regardless of whether bytes move as JSON over HTTP, protobuf over gRPC, or events over NATS. The hexagonal architecture is not just about code organization; it's about protocol evolution without rewrites. This is the same principle demonstrated in the [Scaling Tiers](#evolutionary-scaling-tiers) infrastructure table — just applied to the communication layer instead of the storage layer.

---

## Security Considerations

### Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE                                              │
│  (Internet, clients, anything outside the gateway)           │
│                                                              │
│  Client ──── TLS ────▶ [Load Balancer / Reverse Proxy]       │
│                               │                              │
└───────────────────────────────┼──────────────────────────────┘
                                │
┌───────────────────────────────┼──────────────────────────────┐
│  DMZ (Gateway)                ▼                              │
│                        ┌─────────────┐                       │
│  All input is suspect  │ API Gateway │  Validates, sanitizes │
│                        └──────┬──────┘  rate limits, authn   │
│                               │                              │
└───────────────────────────────┼──────────────────────────────┘
                                │
┌───────────────────────────────┼──────────────────────────────┐
│  TRUSTED ZONE (internal services)                            │
│                               ▼                              │
│        ┌──────────┐  ┌──────────────┐  ┌──────────────┐     │
│        │ Identity │  │  Vector DB   │  │    File      │     │
│        │ Service  │  │  Service     │  │   Service    │     │
│        └──────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  Services trust the gateway's principal injection.           │
│  No re-authentication. Requests without a principal          │
│  from the gateway are rejected.                              │
└──────────────────────────────────────────────────────────────┘
```

**Rules:**
- The gateway trusts **nothing** from the client: headers, tokens, and payloads are all validated.
- Internal services trust the gateway. The principal is passed as an internal header (e.g., `X-Principal-ID`, `X-Principal-Scopes`) or via context in the in-process model.
- Internal services **reject** requests that don't originate from the gateway (in production: network policies or mTLS; in showcase: convention and interface design).

### JWT Security

| Threat | Mitigation |
|--------|-----------|
| **Algorithm confusion** (attacker sends HS256 signed with public key) | Gateway hardcodes expected algorithm (RS256). Never read `alg` from the token header to decide validation strategy. |
| **Token replay** | Short TTL (15 min). `iat` (issued-at) claim validated. Optional: `jti` claim for one-time use tokens in sensitive operations. |
| **Token theft** | Short TTL limits damage window. Refresh tokens are long-lived but single-use (rotation on each refresh). |
| **Key compromise** | JWKS endpoint supports multiple keys (current + previous). Key rotation replaces the signing key without invalidating in-flight tokens. |
| **Expired token reuse** | `exp` claim validated on every request. No grace period. Clock skew tolerance of max 30 seconds. |
| **Claim tampering** | RS256 signature makes claims tamper-proof. Gateway validates signature before reading claims. |
| **None algorithm attack** | Explicitly reject tokens with `alg: none`. |

### Input Validation at the Gateway

- **Request size limits:** Max body size enforced (e.g., 10 MB for file uploads, 1 MB for API calls).
- **Header validation:** Reject requests with malformed `Authorization` headers before attempting token parsing.
- **Path validation:** Reject unknown routes early (404) rather than forwarding to backend services.
- **Content-Type enforcement:** Require `application/json` for API endpoints. Reject unexpected content types.

### Error Handling: What Clients See vs. What We Log

| Scenario | Client Response | Internal Log |
|----------|----------------|-------------|
| Invalid/expired JWT | `401 {"error": "unauthorized", "message": "invalid or expired token"}` | Token details, expiry time, issuer mismatch details |
| Valid JWT, insufficient scopes | `403 {"error": "forbidden", "message": "insufficient permissions"}` | Principal ID, requested resource, missing scopes |
| Rate limited | `429 {"error": "rate_limited", "message": "too many requests", "retry_after": 30}` | Client IP, principal, current rate, limit |
| Internal service failure | `502 {"error": "service_unavailable", "message": "please try again later"}` | Full error, stack trace, which service failed, latency |
| Malformed request | `400 {"error": "bad_request", "message": "<specific validation error>"}` | Raw request details for debugging |

**Principle:** Never leak internal details (service names, stack traces, infrastructure info) to clients. Log everything internally.

---

## Reliability Considerations

### Failure Modes and Responses

| Component Down | Impact | Gateway Response |
|----------------|--------|-----------------|
| **Identity Service** | Cannot issue new tokens or exchange API keys | Existing JWTs still work (validated locally). New logins fail. API key exchange fails. Gateway returns `503` for auth endpoints only. |
| **Vector DB Service** | Vector operations unavailable | Gateway returns `502` for `/v1/vectors/*` routes. Other routes unaffected. |
| **File Service** | File operations unavailable | Gateway returns `502` for `/v1/files/*` routes. Other routes unaffected. |
| **JWKS endpoint unreachable** | Cannot refresh signing keys | Gateway uses cached keys. Logs warning. Only a problem if keys have rotated. |
| **Gateway itself** | Complete outage | Load balancer routes to other instances (horizontal scaling). Health check endpoint (`/healthz`) detects failure. |

### Key Design Principle: Graceful Degradation

The hybrid JWT model (Option C) gives us a critical reliability advantage: **the gateway can authenticate requests even when the Identity Service is down.** As long as the gateway has a cached public key and the client has a valid JWT, the system keeps working. This is a direct consequence of choosing stateless token validation.

### Circuit Breaking (Design, Not Initial Implementation)

For calls the gateway makes to backend services (Vector DB, File Service, and Identity Service for API key exchange):

- **Closed:** Requests flow normally.
- **Open:** After N consecutive failures, stop calling the failing service. Return `503` immediately. Check again after a timeout.
- **Half-Open:** Allow one test request through. If it succeeds, close the circuit. If it fails, reopen.

For the showcase, we implement the **interface** for circuit breaking (the backend service abstraction supports it) but use a simple pass-through implementation. The design doc explains what a production circuit breaker would look like.

### Health Checks

```
GET /healthz          → 200 if gateway process is alive (liveness)
GET /readyz           → 200 if gateway can serve traffic (readiness)
                        Checks: JWKS cache populated, backend services reachable
```

### Structured Logging

Every request gets a log line with:
- Request ID (generated at the gateway, propagated to all services)
- Timestamp, method, path, status code, latency
- Principal ID (if authenticated)
- Client IP
- Error details (if any, internal only)

This gives us basic observability without introducing distributed tracing infrastructure.

---

## Assumptions

### System Scope
- This is a portfolio/showcase project, not a production system. Design quality matters more than operational completeness.
- The system will be evaluated by engineers reviewing code and design documents, not by end users.
- All four services (Gateway, Identity, Vector DB, File) run on a single machine during development and demonstration.

### Authentication & Authorization
- Two auth methods are supported: API keys (static, pre-provisioned) and JWTs (issued by Identity Service).
- API keys are suitable for service-to-service communication. JWTs are suitable for user sessions.
- Authorization is scope-based (e.g., `vectors:read`, `files:write`). Scopes are embedded in JWT claims.
- No OAuth2/OIDC integration is needed for the initial implementation. The design should allow adding it later.
- Token expiry is the primary revocation mechanism. No revocation list is implemented initially.
- JWT signing uses RS256 (asymmetric). The Identity Service holds the private key; the gateway only needs the public key.

### Infrastructure
- No external dependencies (no Redis, no Postgres, no message queues) for the initial implementation.
- All persistent state (users, API keys, files, vectors) uses in-memory stores with well-defined interfaces that can be swapped for real storage.
- Configuration is loaded from environment variables or a config file. No external config service.
- No containerization required for the initial build, but the project structure should be container-friendly (separate `cmd/` entrypoints per service).

### API Design
- All external APIs use JSON over HTTP.
- The gateway is the only externally-exposed service. Identity, Vector DB, and File services are internal.
- API versioning via URL path prefix (`/v1/`).
- Standard HTTP status codes for errors. Error responses use a consistent JSON envelope.

### Non-Goals (Explicit)
- No TLS termination at the gateway (assume a reverse proxy or load balancer handles this).
- No database migrations or schema management.
- No CI/CD pipeline or deployment automation.
- No distributed tracing or metrics collection (structured logging is sufficient).
- No WebSocket or streaming support at Tier 0. See [Communication Protocol Evolution](#communication-protocol-evolution) for the upgrade path where SSE, gRPC streaming, and event-driven patterns earn their complexity cost.
- No multi-tenancy beyond what scopes provide.

---

## What We Would Improve With More Time

1. **Token revocation list** — Redis-backed JTI blacklist for immediate revocation
2. **OIDC provider integration** — Allow login via Google, GitHub, etc.
3. **Distributed rate limiting** — Redis-backed sliding window counters shared across gateway instances
4. **mTLS between services** — For when services move to separate hosts
5. **Observability** — OpenTelemetry traces, Prometheus metrics, per-endpoint latency histograms
6. **Key rotation automation** — Scheduled key rotation with JWKS versioning
7. **Circuit breaker implementation** — Real state machine with configurable thresholds and recovery
8. **Request throttling by cost** — Vector search is more expensive than file metadata; weight rate limits accordingly
9. **Audit logging** — Immutable log of all auth events (login, token refresh, failed auth attempts) for compliance
