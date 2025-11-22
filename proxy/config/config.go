package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all configuration for the edge proxy
type Config struct {
	// Server
	Port     int
	LogLevel string

	// Upstream
	UpstreamURL string

	// TLS/mTLS
	TLSCertPath string
	TLSKeyPath  string
	CACertPath  string

	// JWT
	JWTPublicKeyPath string
	JWTPublicKey     *rsa.PublicKey

	// Kafka
	KafkaBrokers []string
	KafkaTopic   string

	// Redis
	RedisURL string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:             getEnvInt("PORT", 8443),
		LogLevel:         getEnv("LOG_LEVEL", "info"),
		UpstreamURL:      getEnv("UPSTREAM_URL", ""),
		TLSCertPath:      getEnv("TLS_CERT_PATH", "/certs/server.crt"),
		TLSKeyPath:       getEnv("TLS_KEY_PATH", "/certs/server.key"),
		CACertPath:       getEnv("CA_CERT_PATH", "/certs/ca.crt"),
		JWTPublicKeyPath: getEnv("JWT_PUBLIC_KEY_PATH", "/certs/jwt_public.pem"),
		KafkaBrokers:     strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		KafkaTopic:       getEnv("KAFKA_TOPIC", "request-logs"),
		RedisURL:         getEnv("REDIS_URL", "localhost:6379"),
	}

	// Validate required fields
	if cfg.UpstreamURL == "" {
		return nil, fmt.Errorf("UPSTREAM_URL is required")
	}

	// Load JWT public key
	if err := cfg.loadJWTPublicKey(); err != nil {
		return nil, fmt.Errorf("failed to load JWT public key: %w", err)
	}

	return cfg, nil
}

// loadJWTPublicKey reads and parses the RSA public key for JWT verification
func (c *Config) loadJWTPublicKey() error {
	keyData, err := os.ReadFile(c.JWTPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	c.JWTPublicKey = rsaPub
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
