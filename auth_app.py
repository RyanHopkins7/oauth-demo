from flask import Flask, render_template, request, redirect, session
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
import json
import hashlib
import hmac
import base64
import os

auth_app = Flask(__name__, static_folder="static", static_url_path="/static")
auth_app.secret_key = os.urandom(32)

oidc_flows = {}
registered_clients = {
    "test_client": {
        "redirect_uris": ["http://localhost:5001"],
    }
}

@auth_app.route("/")
def index():
    return redirect("/login")

@auth_app.route("/login", methods=["GET", "POST"])
def login():
    global oidc_flows, registered_clients
    if request.method == "GET":
        is_oauth_request = all(param in request.args for param in ("response_type", "client_id", "redirect_uri"))

        if is_oauth_request:
            oauth_params = {
                "response_type": request.args.get("response_type"),
                "client_id": request.args.get("client_id"),
                "redirect_uri": request.args.get("redirect_uri"),
                "scope": request.args.get("scope"),
                "state": request.args.get("state"),
                "code_challenge": request.args.get("code_challenge"),
                "code_challenge_method": request.args.get("code_challenge_method"),
                "nonce": request.args.get("nonce"),
            }

            client_id = oauth_params["client_id"]
            redirect_uri = oauth_params["redirect_uri"]
            allowed_redirect_uris = registered_clients.get(client_id, {}).get("redirect_uris", [])

            if redirect_uri not in allowed_redirect_uris:
                return "Invalid redirect URI", 403

            session["pending_oauth"] = oauth_params

        return render_template("login.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with open("account.json", "r") as file:
            account_data = json.loads(file.read())

        candidate_hash = hashlib.scrypt(
            password.encode("utf-8"), 
            salt=bytes.fromhex(account_data["salt"]), 
            n=account_data["n"],
            r=account_data["r"],
            p=account_data["p"],
            dklen=account_data["dklen"]
        )

        username_correct = hmac.compare_digest(username.encode("utf-8"), account_data["username"].encode("utf-8"))
        password_correct = hmac.compare_digest(candidate_hash, bytes.fromhex(account_data["password"]))

        if username_correct and password_correct:
            if "pending_oauth" in session:
                oauth_params = session["pending_oauth"]
                code = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
                now_utc = datetime.now(timezone.utc)
                future_time_utc = now_utc + timedelta(minutes=5)
                oidc_flows[code] = oauth_params
                oidc_flows[code]["expires_at"] = future_time_utc
                oidc_flows[code]["subject"] = username
                redirect_uri = oauth_params["redirect_uri"]
                return redirect(f"{redirect_uri}?code={code}")

            return "Success"

        return "Username or password incorrect", 403

@auth_app.route("/.well-known/openid-configuration")
def oidc_conf():
    return {
        "issuer": "http://localhost:5000",
        "authorization_endpoint": "http://localhost:5000/login",
        "token_endpoint": "http://localhost:5000/token",
        "userinfo_endpoint": "http://localhost:5000/userinfo",
        "jwks_uri": "http://localhost:5000/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"]
    }

@auth_app.route("/keys")
def jwks():
    with open("pubkey.json", "r") as file:
        public_jwk = json.loads(file.read())
    return {"keys": [public_jwk]}

@auth_app.route("/token", methods=["POST"])
def token():
    global oidc_flows, registered_clients
    data = request.get_json()

    code = data.get("code")
    verifier = data.get("verifier")

    if not code or not verifier:
        return {"error": "Must include code and verifier"}, 400

    flow = oidc_flows.pop(code)

    if not flow:
        return {"error": "Code is invalid"}, 403

    candidate_challenge = hashlib.sha256(bytes.fromhex(verifier))
    challenge = bytes.fromhex(flow["code_challenge"])
    if not hmac.compare_digest(candidate_challenge, challenge):
        return {"error": "Verifier is invalid"}, 403

    now_utc = datetime.now(timezone.utc)
    future_time_utc = now_utc + timedelta(minutes=5)

    token = json.dumps({
        "sub": flow["subject"],
        "iss": "http://localhost:5000",
        "aud": "http://localhost:5001",
        "exp": future_time_utc.timestamp(),
        "iat": now_utc.timestamp()
    })

    with open("privkey.pem", "r") as file:
        privkey = load_pem_private_key(file.read().encode("utf-8"), password=None)

    signature = privkey.sign(
        token.encode("utf-8"),
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    signed_token = base64.urlsafe_b64encode(token.encode("utf-8")).decode("utf-8") + "." + base64.urlsafe_b64encode(signature).decode("utf-8")

    return {"token": signed_token}

if __name__ == "__main__":
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_numbers = private_key.private_numbers()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    public_jwk = json.dumps({
        "kty": "RSA",
        "use": "sig",
        "kid": "key1",
        "alg": "RS256",
        "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, byteorder="big")).decode("utf-8"),
        "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(2048//8, byteorder="big")).decode("utf-8")
    })

    print(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))

    with open("pubkey.json", "w") as file:
        file.write(public_jwk)

    with open("privkey.pem", "w") as file:
        file.write(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()).decode("utf-8"))

    auth_app.run(host="localhost", port="5000")
