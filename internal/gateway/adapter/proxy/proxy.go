package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"gateway/internal/domain"
	gw "gateway/internal/gateway"
	"gateway/internal/platform/telemetry"
)

// route defines a path prefix → backend mapping with required scope.
type route struct {
	prefix       string
	backendURL   *url.URL
	readScope    domain.Scope
	writeScope   domain.Scope
}

// publicRoute defines a path → backend mapping that requires no authentication.
type publicRoute struct {
	path       string
	backendURL *url.URL
	backend    string // metrics label
}

// Router routes authenticated requests to backend services.
type Router struct {
	mux     *http.ServeMux
	routes  []route
	metrics *telemetry.GatewayMetrics
}

// NewRouter creates a router that dispatches to the given backend URLs.
// The identityURL is used for public auth routes (/auth/token, /.well-known/jwks.json).
// The metrics parameter is optional; pass nil to skip metric recording.
func NewRouter(vectorDBURL, fileServiceURL, identityURL string, m *telemetry.GatewayMetrics) (*Router, error) {
	vectorDB, err := url.Parse(vectorDBURL)
	if err != nil {
		return nil, fmt.Errorf("parse vector DB URL: %w", err)
	}
	fileSvc, err := url.Parse(fileServiceURL)
	if err != nil {
		return nil, fmt.Errorf("parse file service URL: %w", err)
	}
	identity, err := url.Parse(identityURL)
	if err != nil {
		return nil, fmt.Errorf("parse identity URL: %w", err)
	}

	r := &Router{
		mux: http.NewServeMux(),
		routes: []route{
			{prefix: "/v1/vectors", backendURL: vectorDB, readScope: "vectors:read", writeScope: "vectors:write"},
			{prefix: "/v1/files", backendURL: fileSvc, readScope: "files:read", writeScope: "files:write"},
		},
		metrics: m,
	}

	// Health check endpoints
	r.mux.HandleFunc("GET /healthz", r.healthz)
	r.mux.HandleFunc("GET /readyz", r.readyz)

	// Public routes — proxied to the identity service without auth or scope checks
	publicRoutes := []publicRoute{
		{path: "/auth/token", backendURL: identity, backend: "identity"},
		{path: "/.well-known/jwks.json", backendURL: identity, backend: "identity"},
	}
	for _, pr := range publicRoutes {
		r.mux.HandleFunc(pr.path, r.makePublicHandler(pr))
	}

	// Register routes for each backend
	for _, rt := range r.routes {
		r.mux.HandleFunc(rt.prefix+"/{rest...}", r.makeHandler(rt))
		r.mux.HandleFunc(rt.prefix, r.makeHandler(rt))
	}

	return r, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// makePublicHandler creates a reverse proxy handler for routes that do not
// require authentication or scope checks (e.g. token issuance, JWKS).
func (r *Router) makePublicHandler(pr publicRoute) http.HandlerFunc {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = pr.backendURL.Scheme
			req.URL.Host = pr.backendURL.Host
			req.Host = pr.backendURL.Host

			// Propagate request ID
			if reqID := gw.RequestIDFromContext(req.Context()); reqID != "" {
				req.Header.Set("X-Request-ID", reqID)
			}
		},
	}

	return func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		sw := &gw.StatusWriter{ResponseWriter: w, Code: http.StatusOK}
		rp.ServeHTTP(sw, req)

		if r.metrics != nil {
			duration := time.Since(start).Seconds()
			r.metrics.RecordProxyRequest(req.Context(), pr.backend, sw.Code, duration)
		}
	}
}

func (r *Router) makeHandler(rt route) http.HandlerFunc {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = rt.backendURL.Scheme
			req.URL.Host = rt.backendURL.Host
			req.Host = rt.backendURL.Host

			// Strip Authorization — backends trust principal headers
			req.Header.Del("Authorization")

			// Inject principal headers from context
			if principal, ok := gw.PrincipalFromContext(req.Context()); ok {
				req.Header.Set("X-Principal-ID", principal.ID)
				var b strings.Builder
				for i, s := range principal.Scopes {
					if i > 0 {
						b.WriteByte(' ')
					}
					b.WriteString(string(s))
				}
				req.Header.Set("X-Principal-Scopes", b.String())
			}

			// Propagate request ID
			if reqID := gw.RequestIDFromContext(req.Context()); reqID != "" {
				req.Header.Set("X-Request-ID", reqID)
			}
		},
	}

	// Derive backend name from route prefix (e.g. "/v1/vectors" -> "vectordb", "/v1/files" -> "fileservice")
	backend := strings.TrimPrefix(rt.prefix, "/v1/")
	if backend == "vectors" {
		backend = "vectordb"
	} else if backend == "files" {
		backend = "fileservice"
	}

	return func(w http.ResponseWriter, req *http.Request) {
		// Check scope authorization
		requiredScope := rt.readScope
		if isWriteMethod(req.Method) {
			requiredScope = rt.writeScope
		}

		principal, ok := gw.PrincipalFromContext(req.Context())
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(domain.ErrorResponse{
				Error:   "unauthorized",
				Message: "authentication required",
			}); err != nil {
				slog.Error("encoding error response", "error", err)
			}
			return
		}
		if !principal.HasScope(requiredScope) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			if err := json.NewEncoder(w).Encode(domain.ErrorResponse{
				Error:   "forbidden",
				Message: "insufficient permissions",
			}); err != nil {
				slog.Error("encoding error response", "error", err)
			}
			return
		}

		start := time.Now()
		sw := &gw.StatusWriter{ResponseWriter: w, Code: http.StatusOK}
		proxy.ServeHTTP(sw, req)

		if r.metrics != nil {
			duration := time.Since(start).Seconds()
			r.metrics.RecordProxyRequest(req.Context(), backend, sw.Code, duration)
		}
	}
}

func (r *Router) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Error("encoding healthz response", "error", err)
	}
}

func (r *Router) readyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ready"}); err != nil {
		slog.Error("encoding readyz response", "error", err)
	}
}

func isWriteMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete
}
