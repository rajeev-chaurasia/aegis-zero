package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rajeev-chaurasia/aegis-zero/proxy/config"
	"github.com/rajeev-chaurasia/aegis-zero/proxy/handler"
	"github.com/rajeev-chaurasia/aegis-zero/proxy/middleware"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("============================================")
	log.Println("  Aegis Zero - AI-Powered Zero Trust Proxy")
	log.Println("============================================")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize middleware components
	blocklistMiddleware, err := middleware.NewBlocklistMiddleware(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to initialize blocklist middleware: %v", err)
	}
	defer blocklistMiddleware.Close()

	jwtMiddleware := middleware.NewJWTMiddleware(cfg.JWTPublicKey)

	loggerMiddleware, err := middleware.NewLoggerMiddleware(cfg.KafkaBrokers, cfg.KafkaTopic)
	if err != nil {
		log.Fatalf("Failed to initialize logger middleware: %v", err)
	}
	defer loggerMiddleware.Close()

	// Initialize proxy handler
	proxyHandler, err := handler.NewProxyHandler(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("Failed to initialize proxy handler: %v", err)
	}

	// Build middleware chain
	// Order: Blocklist -> JWT -> Logger -> Proxy
	var finalHandler http.Handler = proxyHandler
	finalHandler = loggerMiddleware.Handler(finalHandler)
	finalHandler = jwtMiddleware.Handler(finalHandler)
	finalHandler = blocklistMiddleware.Handler(finalHandler)

	// Add health check endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthCheckHandler)
	mux.Handle("/", finalHandler)

	// Load CA certificate for mTLS
	caCert, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to parse CA certificate")
	}

	// Configure TLS with mTLS required
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Create HTTPS server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown handling
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Starting HTTPS server on :%d", cfg.Port)
		log.Printf("Upstream: %s", cfg.UpstreamURL)
		log.Printf("mTLS: REQUIRED")

		if err := server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-shutdown
	log.Println("Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Server stopped")
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy", "service": "aegis-zero-proxy"}`))
}
