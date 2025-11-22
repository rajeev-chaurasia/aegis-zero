package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"
)

// BlocklistMiddleware checks if the client IP is in the Redis blocklist
type BlocklistMiddleware struct {
	client *redis.Client
}

// NewBlocklistMiddleware creates a new blocklist checker
func NewBlocklistMiddleware(redisURL string) (*BlocklistMiddleware, error) {
	client := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	log.Printf("[Blocklist] Connected to Redis at %s", redisURL)
	return &BlocklistMiddleware{client: client}, nil
}

// Handler returns the middleware handler
func (b *BlocklistMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := extractClientIP(r)

		// Check blocklist: GET blocklist:ip:<IP>
		key := "blocklist:ip:" + clientIP
		ctx := r.Context()

		exists, err := b.client.Exists(ctx, key).Result()
		if err != nil {
			log.Printf("[Blocklist] Redis error for IP %s: %v", clientIP, err)
			// Fail open - don't block on Redis errors
			next.ServeHTTP(w, r)
			return
		}

		if exists > 0 {
			log.Printf("[Blocklist] BLOCKED IP: %s", clientIP)
			http.Error(w, "Forbidden - IP Blocked", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractClientIP gets the real client IP from headers or RemoteAddr
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For first (for load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Remove brackets for IPv6
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")

	return ip
}

// Close closes the Redis connection
func (b *BlocklistMiddleware) Close() error {
	return b.client.Close()
}
