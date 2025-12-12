"""
Aegis Zero - JWT Token Generator

Generates RS256-signed JWT tokens for testing the proxy.
"""

import jwt
import datetime
import sys
from pathlib import Path


def generate_token(
    private_key_path: str = "certs/jwt_private.pem",
    subject: str = "test-user",
    issuer: str = "aegis-zero",
    audience: str = "aegis-proxy",
    expires_hours: int = 24,
) -> str:
    """
    Generate a JWT token signed with RS256.
    
    Args:
        private_key_path: Path to the RSA private key
        subject: Token subject (user ID)
        issuer: Token issuer
        audience: Token audience
        expires_hours: Token validity in hours
    
    Returns:
        Signed JWT token string
    """
    # Read private key
    key_path = Path(private_key_path)
    if not key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    
    private_key = key_path.read_text()
    
    # Build claims
    now = datetime.datetime.utcnow()
    claims = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + datetime.timedelta(hours=expires_hours),
        "roles": ["user"],
    }
    
    # Sign with RS256
    token = jwt.encode(claims, private_key, algorithm="RS256")
    
    return token


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate JWT tokens for Aegis Zero")
    parser.add_argument(
        "--key", "-k",
        default="certs/jwt_private.pem",
        help="Path to RSA private key",
    )
    parser.add_argument(
        "--subject", "-s",
        default="test-user",
        help="Token subject (user ID)",
    )
    parser.add_argument(
        "--expires", "-e",
        type=int,
        default=24,
        help="Token validity in hours",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print token details",
    )
    
    args = parser.parse_args()
    
    try:
        token = generate_token(
            private_key_path=args.key,
            subject=args.subject,
            expires_hours=args.expires,
        )
        
        if args.verbose:
            print("=" * 60, file=sys.stderr)
            print("Aegis Zero JWT Token Generator", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Subject: {args.subject}", file=sys.stderr)
            print(f"Expires: {args.expires} hours", file=sys.stderr)
            print(f"Algorithm: RS256", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print("Token:", file=sys.stderr)
        
        print(token)
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Run './certs/generate.sh' first to create keys.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error generating token: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
