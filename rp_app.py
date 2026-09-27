from flask import Flask, session, request
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

    if not token:
        return "Failed to get token", 403

    return f"Success!<br>OIDC token:\n{base64.urlsafe_b64decode(token)}.{signature}"

if __name__ == "__main__":
    auth_app.run(host="127.0.0.2", port="5001")
