# API Gateway

A backend system demonstrating clean separation between an API gateway, identity/authentication, and backend services. The gateway handles JWT authentication, per-IP rate limiting, request routing, and observability, while backend implementations remain abstracted behind stable HTTP APIs.

## Architecture

```
Client
  |
  v
+------------------+
|   API Gateway    |  :8080  — auth, rate limiting, routing, metrics
+------------------+
  |         |         |
  v         v         v
+--------+ +--------+ +------------------+
|VectorDB| |FileSvc | | Identity Service |  :8081 (internal)
+--------+ +--------+ +------------------+
  :8082      :8083       JWKS + token issuing
```

All client traffic flows through the gateway, including token issuance (`/auth/token`) and JWKS (`/.well-known/jwks.json`). The identity service is internal and should not be directly exposed to clients in production.

**Request flow:** Client -> Gateway (metrics -> request-id -> logging -> recovery -> rate-limit -> auth -> proxy) -> Backend

## Prerequisites

- Go 1.25+
- [jq](https://jqlang.github.io/jq/) (used by traffic scripts)
- Docker & Docker Compose (for the full stack with monitoring)

## Quick Start

### Option A: Docker Compose (recommended)

Brings up all services plus Prometheus and Grafana:

```sh
docker compose up --build
```

| Service           | URL                        | Notes                    |
|-------------------|----------------------------|--------------------------|
| Gateway           | http://localhost:8080       | Single client entry point |
| Identity (internal) | http://localhost:8081     | Proxied via gateway      |
| VectorDB mock     | http://localhost:8082       |                          |
| File Service mock | http://localhost:8083       |                          |
| Prometheus        | http://localhost:9090       |                          |
| Grafana           | http://localhost:3000       |                          |

### Option B: Run locally without Docker

Start each component in a separate terminal:

```sh
go run ./cmd/mockidentity
go run ./cmd/mockbackend
go run ./cmd/gateway
```

## Trying It Out

### 1. Get a token

```sh
TOKEN=$(curl -s http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')
```

### 2. Make authenticated requests

```sh
# Vector DB
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/vectors/ns1

# File Service
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/files/doc-1

# Write operation
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vector": [0.1, 0.2, 0.3]}' \
  http://localhost:8080/v1/vectors/ns1
```

### 3. Unauthenticated / health checks

```sh
curl http://localhost:8080/healthz     # 200 — no auth required
curl http://localhost:8080/v1/vectors   # 401 — auth required
```

### 4. Generate mixed traffic for dashboards

```sh
bash scripts/generate_traffic.sh
```

## Running Tests

```sh
# Unit + integration tests
go test ./...

# Unit tests only (skip integration and load)
go test $(go list ./... | grep -v test/)

# Load tests (runs ~25s by default)
go test ./test/loadtest/ -v
```

## Observability

With Docker Compose running, Grafana is available at http://localhost:3000 (no login required). Open the **Gateway** dashboard to see:

- Request rate by HTTP status
- Request duration percentiles (p50 / p95 / p99)
- Rate limit allow/deny decisions
- Auth validation results
- Proxy request rate and latency per backend

Raw Prometheus metrics are exposed at http://localhost:8080/metrics.

## Configuration

All configuration is via environment variables with sensible defaults:

| Variable            | Default                                        | Description                     |
|---------------------|------------------------------------------------|---------------------------------|
| `GATEWAY_ADDR`      | `:8080`                                        | Gateway listen address          |
| `JWKS_ENDPOINT`     | `http://localhost:8081/.well-known/jwks.json`  | Identity service JWKS URL       |
| `VECTORDB_URL`      | `http://localhost:8082`                        | Vector DB backend URL           |
| `FILESERVICE_URL`   | `http://localhost:8083`                        | File Service backend URL        |
| `IDENTITY_URL`      | `http://localhost:8081`                        | Identity service proxy target   |
| `LOG_LEVEL`         | `info`                                         | Log level (debug/info/warn/error) |
| `RATE_LIMIT_RATE`   | `100`                                          | Token bucket refill rate (req/s)  |
| `RATE_LIMIT_BURST`  | `20`                                           | Token bucket burst size           |

## Project Structure

```
cmd/
  gateway/          — API gateway entry point
  mockidentity/     — Mock identity service (JWKS + token issuing)
  mockbackend/      — Generic mock backend (used for vectordb & fileservice)
internal/
  domain/           — Core types (Principal, Scope, ErrorResponse)
  gateway/
    adapter/
      inmem/        — In-memory rate limiter (token bucket)
      jwks/         — JWKS client with caching
      proxy/        — Reverse proxy router with scope enforcement
    middleware/     — HTTP middleware chain (auth, rate-limit, metrics, logging, recovery, request-id)
    ports.go       — Port interfaces (Authenticator, RateLimiter)
  identity/         — Identity service logic
  platform/
    config/         — Environment-based configuration
    server/         — Graceful HTTP server
    telemetry/      — OpenTelemetry + Prometheus metrics
  testutil/         — Shared test helpers (JWT issuing)
test/
  integration/      — Full-stack integration tests
  loadtest/         — Vegeta-based load tests
docs/               — Design documents
plans/              — Architecture decision records
grafana/            — Provisioned dashboards and datasources
```

## Design Documents

- [Auth Flow](docs/auth-flow.md) — end-to-end authentication and authorization sequence
- [Identity Service Separation](plans/20260212-identity-service-separation.md) — architecture options for extracting identity as a standalone service
