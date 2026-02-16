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
for i in $(seq 1 1000); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/vectors/ns1" \
    -H "Authorization: Bearer $TOKEN")
  echo -n "$STATUS "
done
echo ""

# Scenario 2: Successful authenticated requests to fileservice
echo ""
echo "=== Scenario 2: Authenticated file requests (20 requests) ==="
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/v1/files/doc-$i" \
    -H "Authorization: Bearer $TOKEN")
  echo -n "$STATUS "
done
echo ""

echo ""
echo "=== Traffic generation complete ==="
echo "Check metrics at: http://localhost:8080/metrics"
echo "Check Grafana at: http://localhost:3000 (Dashboard: Gateway)"
