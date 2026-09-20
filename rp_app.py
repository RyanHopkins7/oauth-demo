from flask import Flask
import os
import hashlib

auth_app = Flask(__name__)

@auth_app.route("/")
def index():
    state = os.urandom(16).hex()
    challenge_verifier = os.urandom(16)
    challenge = hashlib.sha256(challenge_verifier).hexdigest()
    nonce = os.urandom(16).hex()

    oauth_params = f"response_type=code&client_id=test_client&redirect_uri=http://127.0.0.2:5001&scope=openid&state={state}\
&code_challenge={challenge}&code_challenge_method=S256&nonce={nonce}"
    return f"<p>Log in at <a href='http://localhost:5000/login'>http://localhost:5000/login?{oauth_params}</a></p>"

if __name__ == "__main__":
    auth_app.run(host="127.0.0.2", port="5001")
