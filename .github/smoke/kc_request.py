#!/usr/bin/env python3
"""image-smoke only: send one GET to the gateway, signed per #6's scheme, using only cryptography + stdlib.

Scheme (gateway/auth.py): Ed25519 over
    METHOD \\n raw_path[?query] \\n timestamp \\n nonce \\n sha256(body) hex \\n key_id
sent as X-KC-Key-Id / X-KC-Timestamp / X-KC-Nonce / X-KC-Content-SHA256 / X-KC-Signature (hex).

    kc_request.py --mode signed|unsigned|forged|replay --key-id ID --private-key-file FILE URL

Prints the HTTP status code(s) only (never headers, keys or signatures). replay sends the same
signed request twice and prints both codes. forged signs with a fresh, unregistered key.
"""
import argparse
import base64
import hashlib
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path) as f:
        text = f.read().strip()
    return Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


def signed_headers(key: Ed25519PrivateKey, key_id: str, method: str, url: str, body: bytes = b"") -> dict[str, str]:
    parts = urllib.parse.urlsplit(url)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    timestamp, nonce = str(int(time.time())), secrets.token_urlsafe(24)
    body_sha = hashlib.sha256(body).hexdigest()
    message = b"\n".join(x.encode() for x in (method, target, timestamp, nonce, body_sha, key_id))
    return {"X-KC-Key-Id": key_id, "X-KC-Timestamp": timestamp, "X-KC-Nonce": nonce,
            "X-KC-Content-SHA256": body_sha, "X-KC-Signature": key.sign(message).hex()}


def status(url: str, headers: dict[str, str]) -> int:
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


ap = argparse.ArgumentParser()
ap.add_argument("--mode", required=True, choices=("signed", "unsigned", "forged", "replay"))
ap.add_argument("--key-id", required=True)
ap.add_argument("--private-key-file", required=True)
ap.add_argument("url")
a = ap.parse_args()
if a.mode == "unsigned":
    print(status(a.url, {}))
elif a.mode == "forged":
    print(status(a.url, signed_headers(Ed25519PrivateKey.generate(), a.key_id, "GET", a.url)))
else:
    h = signed_headers(load_private_key(a.private_key_file), a.key_id, "GET", a.url)
    print(status(a.url, h))
    if a.mode == "replay":
        print(status(a.url, h))
