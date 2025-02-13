'''
Basic API for demonstrating a JWT that uses x509 certificates. 

There are two endpoints:
    /login - POST request that takes {"username":"testuser","password":"password123"} to return the access token
    /verify - GET request to parse the Authorization header 

'''


from flask import Flask, request, jsonify
import jwt
import datetime
import hashlib
import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import load_der_x509_certificate

app = Flask(__name__, static_folder='content/')

# URL for the public X.509 certificate (assuming it's hosted at this URL)
x5u_url = "http://127.0.0.1:5000/content/cert.pem"

# Load the private key for signing JWTs
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load the X.509 certificate for x5c calculation
with open("content/cert.pem", "rb") as cert_file:
    cert = load_pem_x509_certificate(cert_file.read(), default_backend())
    public_key = cert.public_key()  # Extract the public key for local verification

    # Generate x5c, x5t, and x5t#S256 values
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode('utf-8')]

# credentials for demon
users = {
    "testuser": "password123"
}

@app.route('/login', methods=['POST'])
def login():
    auth_data = request.get_json()
    username = auth_data.get('username')
    password = auth_data.get('password')

    if users.get(username) == password:
        payload = {
            "sub": username,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }
        
        # JWT headers with x5c, x5t, x5t#S256, and x5u
        headers = {
            #"x5c": x5c,            # Certificate chain as PEM strings
            #"x5u": x5u_url         # URL pointing to the certificate
        }

        # Sign the JWT with the private key and custom headers
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

#@app.route('/cert.pem', methods=['GET'])
#def pub_key():
#    return send_from_directory

@app.route('/verify', methods=['GET'])
def verify():
    token = request.headers.get('Authorization').split(" ")[1]
    
    # Extract headers without verifying the token
    headers = jwt.get_unverified_header(token)

    # Verify x5u header and retrieve the certificate from the URL if provided
    if "x5u" in headers:
        try:
            # Fetch the certificate from the URL specified in x5u
            response = requests.get(headers["x5u"], verify=False)
            response.raise_for_status()
            cert_pem = response.content
            cert = load_pem_x509_certificate(cert_pem, default_backend())
            public_key = cert.public_key()
        except Exception:
            return jsonify({"error": f"Could not retrieve certificate"}), 400
    elif "x5c" in headers:
        try:
            # Fetch the certificate from JWT headers
            cert_der = base64.b64decode(headers["x5c"][0])
            cert = load_der_x509_certificate(cert_der, default_backend())
            public_key = cert.public_key()
        except Exception:
            return jsonify({"error": f"Could not retrieve certificate"}), 400
    else:
        try:
            # Fetch the certificate locally
            with open("content/cert.pem", "rb") as cert_file:
                cert = load_pem_x509_certificate(cert_file.read(), default_backend())
                public_key = cert.public_key()  # Extract the public key for local verification
            public_key = cert.public_key()
        except Exception:
            return jsonify({"error": f"Could not retrieve certificate"}), 400
    try:
        # Decode and verify the token using the public key (or local public key)
        decoded = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})
        
        return jsonify({"decoded": decoded}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(debug=True)
