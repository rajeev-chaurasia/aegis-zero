package handler

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ProxyHandler handles reverse proxying to the upstream service
type ProxyHandler struct {
	proxy *httputil.ReverseProxy
}

// NewProxyHandler creates a new reverse proxy handler
func NewProxyHandler(upstreamURL string) (*ProxyHandler, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the director to modify requests before forwarding
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host

		// Add custom headers
		req.Header.Set("X-Forwarded-By", "aegis-zero")

		// Forward client certificate info if available
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			cert := req.TLS.PeerCertificates[0]
			req.Header.Set("X-Client-Cert-CN", cert.Subject.CommonName)
			req.Header.Set("X-Client-Cert-Fingerprint", certFingerprint(cert))
		}
	}

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[Proxy] Error forwarding request to %s: %v", upstreamURL, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	log.Printf("[Proxy] Configured upstream: %s", upstreamURL)
	return &ProxyHandler{proxy: proxy}, nil
}

// ServeHTTP implements http.Handler
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// certFingerprint generates a simple fingerprint of the certificate
func certFingerprint(cert interface{}) string {
	// In production, use crypto/sha256 to hash the certificate
	// For now, return a placeholder
	return "fingerprint"
}
