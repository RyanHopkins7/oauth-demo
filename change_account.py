import argparse
import hashlib
import os
import json

parser = argparse.ArgumentParser(description="Set user account details")

parser.add_argument("-u", "--username", type=str, help="Account username")

parser.add_argument("-p", "--password", type=str, help="Account password")

args = parser.parse_args()

n = 1<<14
r = 8
p = 5
dklen = 32

salt = os.urandom(16)
pw_hash = hashlib.scrypt(args.password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)

account = json.dumps({
    "username": args.username,
    "password": pw_hash.hex(),
    "salt": salt.hex(),
    "n": n,
    "r": r,
    "p": p,
    "dklen": dklen
})

with open("account.json", "w") as file:
    file.write(account)
