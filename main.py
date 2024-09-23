import json
import time
import jwt
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

# Initialize Flask app
app = Flask(__name__)

# Dictionary to hold keys with kid, expiry, and RSA key pairs
keys = []

# Utility function to generate RSA key pairs and return kid, public key, and private key
def generate_key_pair(expiry_minutes=60):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Generate Key ID (kid)
    kid = str(int(time.time()))  # Simplistic key ID based on current timestamp
    
    # Serialize the public key to JWK format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Use timezone-aware datetime object
    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    
    key_data = {
        'kid': kid,
        'expiry': expiry_time,
        'private_key': private_key,
        'public_key': public_pem
    }
    
    keys.append(key_data)
    return key_data

# Utility function to serve JWKS with non-expired keys
def get_jwks():
    jwks = {
        "keys": []
    }
    
    # Filter out expired keys
    for key in keys:
        if key['expiry'] > datetime.now(timezone.utc):
            jwk = {
                "kid": key['kid'],
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": "",  # RSA modulus (base64 encoded)
                "e": "AQAB"  # RSA public exponent
            }
            jwks['keys'].append(jwk)
    
    return jwks

# JWKS Endpoint
@app.route('/jwks', methods=['GET'])
def jwks():
    return jsonify(get_jwks())

# JWKS Endpoint at .well-known
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_well_known():
    return jsonify(get_jwks())

# Auth Endpoint for JWT issuance
@app.route('/auth', methods=['POST'])
def auth():
    data = request.get_json()  # Get the JSON payload
    username = data.get('username')
    password = data.get('password')
    expired = request.args.get('expired')

    if not username or not password:
        return jsonify({"error": "Invalid username or password"}), 401

    if expired:
        expired_key = next((key for key in keys if key['expiry'] <= datetime.now(timezone.utc)), None)
        if not expired_key:
            return jsonify({"error": "No expired keys available"}), 400
        key = expired_key
        exp = key['expiry']
    else:
        key = next((key for key in keys if key['expiry'] > datetime.now(timezone.utc)), None)
        if not key:
            return jsonify({"error": "No valid keys available"}), 500
        exp = datetime.now(timezone.utc) + timedelta(minutes=10)

    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": exp,
    }

    headers = {
        "kid": key['kid']
    }
    
    private_key = key['private_key']
    jwt_token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)

    # Log the issued JWT's kid
    app.logger.debug(f"Issued JWT with kid: {headers['kid']}")
    app.logger.debug(f"Current JWKS keys: {[key['kid'] for key in keys]}")

    return jsonify({"token": jwt_token})

# Generate initial keys
generate_key_pair(expiry_minutes=60)
generate_key_pair(expiry_minutes=-10)  # Expired key for testing

# Start the server
if __name__ == '__main__':
    app.run(port=8080)
