from flask import Flask, session, request
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
import os
import hashlib
import hmac
import requests
import base64
import json

auth_app = Flask(__name__)
auth_app.secret_key = os.urandom(16)

client_id = "test_client"
with open("registered_clients.json", "r") as file:
    registered_clients = json.loads(file.read())
client_secret = registered_clients[client_id]["client_secret"]

@auth_app.route("/")
def index():
    global client_id
    state = os.urandom(16).hex()
    challenge_verifier = os.urandom(16)
    challenge = hashlib.sha256(challenge_verifier).hexdigest()
    nonce = os.urandom(16).hex()

    session["state"] = state
    session["challenge_verifier"] = challenge_verifier.hex()
    session["nonce"] = nonce

    oauth_params = f"response_type=code&client_id={client_id}&redirect_uri=http://127.0.0.2:5001/oauth&scope=openid&state={state}\
&code_challenge={challenge}&code_challenge_method=S256&nonce={nonce}"
    return f"<p>Log in at <a href='http://localhost:5000/login?{oauth_params}'>http://localhost:5000/login</a></p>"

@auth_app.route("/oauth")
def oauth():
    global client_id
    global client_secret
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return "Error: must include code and state", 400

    if not hmac.compare_digest(bytes.fromhex(state), bytes.fromhex(session.pop("state", ""))):
        return "Error: state does not match", 403

    verifier = session["challenge_verifier"]

    token_res = requests.post("http://localhost:5000/token", json={
        "code": code,
        "verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret
    })

    token, signature = token_res.json().get("token").split(".")

    if not token or not signature:
        return "Failed to get token or signature", 403
    
    decoded_token = base64.urlsafe_b64decode(token)
    decoded_signature = base64.urlsafe_b64decode(signature)

    keys_res = requests.get("http://localhost:5000/keys")
    key_json = keys_res.json()["keys"][0]

    pub_key = RSAPublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(key_json["e"])),
        int.from_bytes(base64.urlsafe_b64decode(key_json["n"]))
    ).public_key()

    try:
        pub_key.verify(
            decoded_signature,
            decoded_token,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
    except InvalidSignature:
        return "Error: token signature was not verified"

    token_json = json.loads(decoded_token.decode())

    if token_json["iss"] != "http://localhost:5000":
        return "Error: token issuer is invalid"

    if token_json["aud"] != "http://127.0.0.2:5001":
        return "Error: token audience is invalid"

    if datetime.fromtimestamp(token_json["exp"], tz=timezone.utc) < datetime.now(timezone.utc):
        return "Error: token is expired"

    return f"""
Success!
<br>
OIDC token:\n{decoded_token.decode()}.{signature}
<br>
Signature verified
<br>
Issuer is valid
<br>
Audience is valid
<br>
Token is not expired
"""

if __name__ == "__main__":
    auth_app.run(host="127.0.0.2", port="5001")
