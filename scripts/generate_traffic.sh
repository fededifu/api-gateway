#!/usr/bin/env bash
set -euo pipefail

GATEWAY="http://localhost:8080"

echo "=== Getting valid token ==="
TOKEN=$(curl -s "$GATEWAY/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')
echo "Token: ${TOKEN:0:40}..."

# Scenario 1: Successful authenticated requests to vectordb
echo ""
echo "=== Scenario 1: Authenticated vector requests (20 requests) ==="
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/vectors/ns1" \
    -H "Authorization: Bearer $TOKEN")
  echo -n "$STATUS "
done
echo ""

# Scenario 2: Successful authenticated requests to fileservice
echo ""
echo "=== Scenario 2: Authenticated file requests (20 requests) ==="
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/files/doc-$i" \
    -H "Authorization: Bearer $TOKEN")
  echo -n "$STATUS "
done
echo ""

# Scenario 3: Unauthenticated requests (should get 401)
echo ""
echo "=== Scenario 3: Unauthenticated requests (10 requests) ==="
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/vectors/ns1")
  echo -n "$STATUS "
done
echo ""

# Scenario 4: Invalid token (should get 401)
echo ""
echo "=== Scenario 4: Invalid token requests (10 requests) ==="
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/vectors/ns1" \
    -H "Authorization: Bearer invalid.token.here")
  echo -n "$STATUS "
done
echo ""

# Scenario 5: Write operations
echo ""
echo "=== Scenario 5: Write operations (POST) (10 requests) ==="
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY/v1/vectors/ns1" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"vector": [0.1, 0.2, 0.3]}')
  echo -n "$STATUS "
done
echo ""

# Scenario 6: Health checks (no auth)
echo ""
echo "=== Scenario 6: Health check requests (10 requests) ==="
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/healthz")
  echo -n "$STATUS "
done
echo ""

# Scenario 7: 404 requests
echo ""
echo "=== Scenario 7: Unknown paths (10 requests) ==="
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/unknown" \
    -H "Authorization: Bearer $TOKEN")
  echo -n "$STATUS "
done
echo ""

echo ""
echo "=== Traffic generation complete ==="
echo "Check metrics at: http://localhost:8080/metrics"
echo "Check Grafana at: http://localhost:3000 (Dashboard: Gateway)"
