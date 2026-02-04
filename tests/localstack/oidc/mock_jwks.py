#!/usr/bin/env python3
"""
Mock OIDC server for LocalStack testing.
Provides JWKS endpoint and test token generation.
"""

import os
import time
from datetime import datetime, timedelta
from flask import Flask, jsonify
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Configuration
ISSUER_URL = os.getenv('ISSUER_URL', 'http://mock-oidc:8080/realms/sre-ops')
CLIENT_ID = os.getenv('CLIENT_ID', 'aws-sre-access')
KEYS_DIR = '/keys'

# Load RSA keys
def load_private_key():
    """Load RSA private key for signing tokens"""
    with open(f'{KEYS_DIR}/private.pem', 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key():
    """Load RSA public key for JWKS"""
    with open(f'{KEYS_DIR}/public.pem', 'rb') as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

private_key = load_private_key()
public_key = load_public_key()

# Extract public key components for JWKS
public_numbers = public_key.public_numbers()

@app.route('/.well-known/openid-configuration')
def openid_configuration():
    """OpenID Connect discovery endpoint"""
    return jsonify({
        'issuer': ISSUER_URL,
        'authorization_endpoint': f'{ISSUER_URL}/protocol/openid-connect/auth',
        'token_endpoint': f'{ISSUER_URL}/protocol/openid-connect/token',
        'jwks_uri': f'{ISSUER_URL}/protocol/openid-connect/certs',
        'response_types_supported': ['code', 'id_token', 'token id_token'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
    })

@app.route('/realms/sre-ops/protocol/openid-connect/certs')
def jwks():
    """JWKS endpoint with test public key"""
    # Convert public key to JWK format
    n = public_numbers.n
    e = public_numbers.e

    # Convert to base64url encoding
    import base64
    def int_to_base64url(num):
        num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
        return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode('utf-8')

    return jsonify({
        'keys': [{
            'kty': 'RSA',
            'use': 'sig',
            'kid': 'test-key-1',
            'alg': 'RS256',
            'n': int_to_base64url(n),
            'e': int_to_base64url(e),
        }]
    })

def create_test_token(sub='test-user', groups=None, email='test@example.com',
                     exp_minutes=60, extra_claims=None):
    """
    Create a test JWT token for Lambda testing.

    Args:
        sub: Subject claim (OIDC user ID)
        groups: List of groups (default: ['sre-team'])
        email: Email address
        exp_minutes: Expiration time in minutes
        extra_claims: Additional claims to include

    Returns:
        Signed JWT token string
    """
    if groups is None:
        groups = ['sre-team']

    now = datetime.utcnow()

    claims = {
        'iss': ISSUER_URL,
        'sub': sub,
        'aud': CLIENT_ID,
        'exp': int((now + timedelta(minutes=exp_minutes)).timestamp()),
        'iat': int(now.timestamp()),
        'email': email,
        'email_verified': True,
        'groups': groups,
    }

    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(claims, private_key, algorithm='RS256', headers={'kid': 'test-key-1'})

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
