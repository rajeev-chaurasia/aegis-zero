# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /aegis-proxy .

# Runtime stage - minimal image
FROM scratch

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /aegis-proxy /aegis-proxy

# Expose HTTPS port
EXPOSE 8443

# Run the proxy
ENTRYPOINT ["/aegis-proxy"]
