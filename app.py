from flask import Flask, render_template, request
import json
import hashlib
import hmac

app = Flask(__name__, static_folder="static", static_url_path="/static")

@app.route("/")
def hello_world():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
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

    if username == account_data["username"] and hmac.compare_digest(candidate_hash, bytes.fromhex(account_data["password"])):
        return "Success"

    return "Username or password incorrect", 403

if __name__ == "__main__":
    app.run(debug=True)
