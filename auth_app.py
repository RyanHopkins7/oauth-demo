from flask import Flask, render_template, request, redirect
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import hashlib
import hmac
import base64

auth_app = Flask(__name__, static_folder="static", static_url_path="/static")

@auth_app.route("/")
def index():
    return redirect("/login")

@auth_app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
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
        "scopes_supported": ["openid"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name"],
        "code_challenge_methods_supported": ["S256"]
    }

@auth_app.route("/keys")
def jwks():
    with open("pubkey.json", "r") as file:
        public_jwk = json.loads(file.read())
    return {"keys": [public_jwk]}

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

    private_jwk = json.dumps({
        "kty": "RSA",
        "use": "sig",
        "kid": "key1",
        "alg": "RS256",
        "d": base64.urlsafe_b64encode(private_numbers.d.to_bytes(2048//8, byteorder="big")).decode("utf-8")
    })

    with open("pubkey.json", "w") as file:
        file.write(public_jwk)

    with open("privkey.json", "w") as file:
        file.write(private_jwk)

    auth_app.run(host="localhost", port="5000")
