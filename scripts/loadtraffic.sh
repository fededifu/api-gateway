#!/usr/bin/env bash
#
# Sustained load generator for the gateway using vegeta.
# Sends requests at a precise rate across a weighted traffic mix.
#
# Usage:
#   bash scripts/loadtraffic.sh                     # defaults: 100 req/s, 60s
#   RATE=500 DURATION=30 bash scripts/loadtraffic.sh
#   RATE=1000 DURATION=120 bash scripts/loadtraffic.sh
#
set -euo pipefail

GATEWAY="${GATEWAY:-http://localhost:8080}"
RATE="${RATE:-100}"
DURATION="${DURATION:-60}"

# Colors (if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[loadtraffic]${NC} $*"; }

# ── Validate rate range ──────────────────────────────────────────────
if [ "$RATE" -lt 100 ] || [ "$RATE" -gt 1000 ]; then
  echo -e "${RED}RATE must be between 100 and 1000 (got $RATE)${NC}"
  exit 1
fi

# ── Check for vegeta ─────────────────────────────────────────────────
if ! command -v vegeta &> /dev/null; then
  echo -e "${YELLOW}vegeta not found, installing...${NC}"
  go install github.com/tsenart/vegeta/v12@latest
  export PATH="$(go env GOPATH)/bin:$PATH"
fi

log "Gateway:  $GATEWAY"
log "Rate:     $RATE req/s"
log "Duration: ${DURATION}s"
echo ""

# ── Get a valid token ────────────────────────────────────────────────
log "Fetching auth token..."
TOKEN=$(curl -sf "$GATEWAY/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo -e "${RED}Failed to obtain token. Is the identity service running?${NC}"
  exit 1
fi
log "Token obtained: ${TOKEN:0:30}..."
echo ""

# ── Build vegeta targets ─────────────────────────────────────────────
# Weighted traffic mix (same proportions as before):
#   40% vector reads, 15% vector writes, 20% file reads, 10% file writes,
#    5% unauth, 3% bad token, 5% health, 2% 404
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

TARGETS="$TMPDIR/targets.txt"

# Vector reads (40 entries)
for i in $(seq 1 40); do
  ns=$((i % 10))
  cat >> "$TARGETS" <<EOF
GET ${GATEWAY}/v1/vectors/ns-${ns}
Authorization: Bearer ${TOKEN}

EOF
done

# Vector writes (15 entries)
for i in $(seq 1 15); do
  ns=$((i % 10))
  cat >> "$TARGETS" <<EOF
POST ${GATEWAY}/v1/vectors/ns-${ns}
Authorization: Bearer ${TOKEN}
Content-Type: application/json
@${TMPDIR}/vector-body.json

EOF
done
echo '{"vector": [0.1, 0.2, 0.3]}' > "$TMPDIR/vector-body.json"

# File reads (20 entries)
for i in $(seq 1 20); do
  doc=$((i % 50))
  cat >> "$TARGETS" <<EOF
GET ${GATEWAY}/v1/files/doc-${doc}
Authorization: Bearer ${TOKEN}

EOF
done

# File writes (10 entries)
for i in $(seq 1 10); do
  doc=$((i % 50))
  cat >> "$TARGETS" <<EOF
PUT ${GATEWAY}/v1/files/doc-${doc}
Authorization: Bearer ${TOKEN}
Content-Type: application/json
@${TMPDIR}/file-body.json

EOF
done
echo '{"metadata": {"tag": "test"}}' > "$TMPDIR/file-body.json"

# Unauthenticated (5 entries)
for _ in $(seq 1 5); do
  cat >> "$TARGETS" <<EOF
GET ${GATEWAY}/v1/vectors/ns1

EOF
done

# Bad token (3 entries)
for _ in $(seq 1 3); do
  cat >> "$TARGETS" <<EOF
GET ${GATEWAY}/v1/vectors/ns1
Authorization: Bearer invalid.token.value

EOF
done

# Health checks (5 entries)
for _ in $(seq 1 5); do
  cat >> "$TARGETS" <<EOF
GET ${GATEWAY}/healthz

EOF
done

# 404 (2 entries)
for _ in $(seq 1 2); do
  cat >> "$TARGETS" <<EOF
GET ${GATEWAY}/v1/unknown/path
Authorization: Bearer ${TOKEN}

EOF
done

# ── Run vegeta ───────────────────────────────────────────────────────
log "Attacking at $RATE req/s for ${DURATION}s..."
echo ""

vegeta attack \
  -targets="$TARGETS" \
  -rate="$RATE" \
  -duration="${DURATION}s" \
  -workers=64 \
  > "$TMPDIR/results.bin"

# ── Report ───────────────────────────────────────────────────────────
echo ""
log "Results:"
echo ""
vegeta report "$TMPDIR/results.bin"

echo ""
log "Check dashboards:"
echo "  Metrics:    $GATEWAY/metrics"
echo "  Grafana:    http://localhost:3000  (Dashboard: Gateway)"
echo "  Prometheus: http://localhost:9090"
