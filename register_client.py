import json
import os
import base64

registered_clients = json.dumps({
    "test_client": {
        "redirect_uris": ["http://127.0.0.2:5001/oauth"],
        "client_secret": base64.urlsafe_b64encode(os.urandom(32)).decode()
    }
})

with open("registered_clients.json", "w") as file:
    file.write(registered_clients)
