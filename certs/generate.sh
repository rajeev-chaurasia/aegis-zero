#!/bin/bash
# =============================================================================
# Aegis Zero Certificate Generator
# Generates CA, Server, Client certificates for mTLS + JWT RS256 keys
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "  Aegis Zero Certificate Generator"
echo "=============================================="

# =============================================================================
# 1. Certificate Authority (CA)
# =============================================================================
echo ""
echo "[1/5] Generating Certificate Authority..."

openssl genrsa -out ca.key 4096

openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=California/L=San Jose/O=Aegis Zero/OU=Security/CN=Aegis-Zero-CA"

echo "  ✓ CA certificate: ca.crt"
echo "  ✓ CA private key: ca.key"

# =============================================================================
# 2. Server Certificate (for TLS termination)
# =============================================================================
echo ""
echo "[2/5] Generating Server Certificate..."

openssl genrsa -out server.key 2048

openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=California/L=San Jose/O=Aegis Zero/OU=Proxy/CN=aegis-zero-proxy"

# Create extension file for SAN (Subject Alternative Names)
cat > server_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = aegis-zero-proxy
DNS.3 = proxy
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extfile server_ext.cnf

rm server.csr server_ext.cnf

echo "  ✓ Server certificate: server.crt"
echo "  ✓ Server private key: server.key"

# =============================================================================
# 3. Client Certificate (for mTLS authentication)
# =============================================================================
echo ""
echo "[3/5] Generating Client Certificate..."

openssl genrsa -out client.key 2048

openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=California/L=San Jose/O=Aegis Zero/OU=Client/CN=test-client"

# Create extension file for client cert
cat > client_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -extfile client_ext.cnf

rm client.csr client_ext.cnf

echo "  ✓ Client certificate: client.crt"
echo "  ✓ Client private key: client.key"

# =============================================================================
# 4. Additional Client Certificate (for testing different identities)
# =============================================================================
echo ""
echo "[4/5] Generating Additional Test Client Certificate..."

openssl genrsa -out client2.key 2048

openssl req -new -key client2.key -out client2.csr \
    -subj "/C=US/ST=California/L=San Jose/O=Aegis Zero/OU=Client/CN=attacker-client"

cat > client2_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days 365 -in client2.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client2.crt -extfile client2_ext.cnf

rm client2.csr client2_ext.cnf

echo "  ✓ Attacker client certificate: client2.crt"
echo "  ✓ Attacker client private key: client2.key"

# =============================================================================
# 5. JWT RS256 Key Pair
# =============================================================================
echo ""
echo "[5/5] Generating JWT RS256 Key Pair..."

openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem

echo "  ✓ JWT private key: jwt_private.pem"
echo "  ✓ JWT public key: jwt_public.pem"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  Certificate Generation Complete!"
echo "=============================================="
echo ""
echo "Generated files:"
echo "  CA:      ca.crt, ca.key"
echo "  Server:  server.crt, server.key"
echo "  Client:  client.crt, client.key"
echo "  Client2: client2.crt, client2.key (for attack simulation)"
echo "  JWT:     jwt_private.pem, jwt_public.pem"
echo ""
echo "Usage:"
echo "  # Test with curl (mTLS):"
echo "  curl --cert client.crt --key client.key --cacert ca.crt https://localhost:8443/health"
echo ""
echo "  # Generate JWT token:"
echo "  python tests/generate_jwt.py"
echo ""
