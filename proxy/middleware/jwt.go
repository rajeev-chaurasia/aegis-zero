package middleware

import (
	"crypto/rsa"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTMiddleware validates JWT tokens using RS256
type JWTMiddleware struct {
	publicKey *rsa.PublicKey
}

// NewJWTMiddleware creates a new JWT validator with the given RSA public key
func NewJWTMiddleware(publicKey *rsa.PublicKey) *JWTMiddleware {
	return &JWTMiddleware{publicKey: publicKey}
}

// Handler returns the middleware handler
func (j *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip health check endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("[JWT] Missing Authorization header from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized - Missing token", http.StatusUnauthorized)
			return
		}

		// Expect "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			log.Printf("[JWT] Invalid Authorization header format from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized - Invalid token format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method is RS256
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return j.publicKey, nil
		})

		if err != nil {
			log.Printf("[JWT] Token validation failed from %s: %v", r.RemoteAddr, err)
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			log.Printf("[JWT] Invalid token from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims for logging/context
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if sub, exists := claims["sub"]; exists {
				log.Printf("[JWT] Authenticated user: %v", sub)
			}
		}

		next.ServeHTTP(w, r)
	})
}
