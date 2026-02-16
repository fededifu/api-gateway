Let me explain each of the 6 panels in the Grafana dashboard and what they tell you about your gateway's behavior.

  ---
  1. Request Rate by Status

  Query: sum by (status) (rate(gateway_http_requests_total[1m]))

  Shows how many requests per second the gateway handles, split by HTTP status code. You'll see separate lines for 200, 401, 404, 429, etc. This is your primary "is the system healthy?" panel. If the 429 line
  spikes, you're rate-limiting too aggressively. If 401 spikes, someone might be hitting the API with bad credentials. A sudden drop in 200 means traffic stopped or something broke.

  2. Request Duration Percentiles (P50/P95/P99)

  Query: histogram_quantile(0.50|0.95|0.99, ...gateway_http_request_duration_seconds_bucket...)

  Shows how fast the gateway responds, at three percentile levels:
  - P50 — the median. Half of requests are faster than this.
  - P95 — 95th percentile. Only 5% of requests are slower. This is your "typical worst case."
  - P99 — 99th percentile. The tail latency — 1 in 100 requests is this slow or worse.

  If P50 is fine but P99 is spiking, you have an occasional slow path (maybe a cold JWKS cache miss, or one backend being slow).

  3. Rate Limit Decisions

  Query: sum by (result) (rate(gateway_ratelimit_decisions_total[1m]))

  Two lines: allowed and denied. Shows the rate limiter in action. Under normal traffic, allowed dominates. When an IP hits the burst limit, denied climbs. Useful for tuning your rate limit configuration — if
  denied is too high under legitimate traffic, your burst/rate settings are too strict.

  4. Auth Validation Results

  Query: sum by (result) (rate(gateway_auth_validations_total[1m]))

  Two lines: success and failure. Shows JWT validation outcomes. failure includes: missing tokens, expired tokens, invalid signatures, bad claims. If failure suddenly spikes while success stays flat, either someone
   is probing your API or a client has stale credentials. If both drop to zero, no one is hitting authenticated endpoints.

  5. Proxy Request Rate by Backend

  Query: sum by (backend) (rate(gateway_proxy_requests_total[1m]))

  Two lines: vectordb and fileservice. Shows how much traffic each backend receives after auth and rate limiting pass. This tells you the actual load on your backends. If one backend gets much more traffic than
  expected, it helps with capacity planning.

  6. Proxy Duration by Backend (P95)

  Query: histogram_quantile(0.95, ...gateway_proxy_duration_seconds_bucket...)

  Shows the 95th percentile latency of the reverse proxy to each backend, separately. This measures how long it takes the backend to respond (not the full request lifecycle — that's panel 2). If vectordb P95 climbs
   while fileservice stays flat, you know the vector DB is the bottleneck, not the gateway itself.

  ---
  In short: panels 1-2 are the overall gateway health. Panels 3-4 show the middleware doing its job (rate limiting, auth). Panels 5-6 show what's happening downstream at the backends.