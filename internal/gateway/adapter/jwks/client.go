package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Client fetches and caches public keys from a JWKS endpoint.
type Client struct {
	endpoint       string
	minRefresh     time.Duration
	httpClient     *http.Client

	mu             sync.RWMutex
	keys           map[string]*rsa.PublicKey
	lastFetch      time.Time
}

// NewClient creates a JWKS client that caches keys and won't re-fetch
// more often than minRefresh.
func NewClient(endpoint string, minRefresh time.Duration) *Client {
	return &Client{
		endpoint:   endpoint,
		minRefresh: minRefresh,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
	}
}

// GetKey returns the public key for the given key ID.
// Fetches from the JWKS endpoint on first call and caches the result.
// If the kid is not found in cache and enough time has passed since the last fetch,
// it re-fetches to pick up key rotations.
func (c *Client) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Try cached first
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return key, nil
	}

	// Not in cache — fetch if we haven't yet or enough time has passed
	if err := c.refresh(ctx); err != nil {
		return nil, fmt.Errorf("fetching key %q: %w", kid, err)
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key ID %q not found in JWKS", kid)
	}
	return key, nil
}

func (c *Client) refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if another goroutine already refreshed
	if !c.lastFetch.IsZero() && time.Since(c.lastFetch) < c.minRefresh {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" {
			slog.Debug("skipping non-RS256 JWKS key", "kid", k.Kid, "kty", k.Kty, "alg", k.Alg)
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			slog.Warn("failed to parse JWKS key", "kid", k.Kid, "error", err)
			continue
		}
		keys[k.Kid] = pub
	}

	c.keys = keys
	c.lastFetch = time.Now()
	return nil
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
