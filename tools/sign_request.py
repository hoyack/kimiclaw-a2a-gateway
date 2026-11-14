#!/usr/bin/env python3
"""Sign requests to the kimiclaw gateway with the caller's Ed25519 private key (README "Request signing").

Library:  httpx.Client(base_url=URL, auth=Signer(key_id, private_key))  signs every request it sends;
          private_key is the unpadded base64url line tools/new_keypair.py wrote (or tools/new_api_key.py --mint printed).
CLI:      python tools/sign_request.py --key-id ID (--private-key-file FILE | env KC_PRIVATE_KEY) URL ['{"jsonrpc": ...}']
          GET without a body, POST (application/json) with one; prints the status line and the response body.
          The key comes from a file or the environment, so it never lands in argv or shell history.
"""
import argparse
import base64
import hashlib
import os
import secrets
import sys
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(method: str, raw_path: bytes, query: bytes, timestamp: str, nonce: str, body: bytes, key_id: str) -> bytes:
    target = raw_path + (b"?" + query if query else b"")
    return b"\n".join([method.encode(), target, timestamp.encode(), nonce.encode(),
                       hashlib.sha256(body).hexdigest().encode(), key_id.encode()])


def load_private_key(text: str) -> Ed25519PrivateKey:
    text = text.strip()
    return Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


def signed_headers(key_id: str, private_key: str, method: str, raw_path: bytes, query: bytes, body: bytes,
                   timestamp: str | None = None, nonce: str | None = None) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or secrets.token_urlsafe(24)
    message = canonical(method.upper(), raw_path, query, timestamp, nonce, body, key_id)
    return {"X-KC-Key-Id": key_id, "X-KC-Timestamp": timestamp, "X-KC-Nonce": nonce,
            "X-KC-Signature": load_private_key(private_key).sign(message).hex()}


class Signer(httpx.Auth):
    requires_request_body = True

    def __init__(self, key_id: str, private_key: str):
        self.key_id, self.private_key = key_id, private_key

    def auth_flow(self, request: httpx.Request):
        raw_path, _, query = request.url.raw_path.partition(b"?")
        request.headers.update(signed_headers(self.key_id, self.private_key, request.method, raw_path, query,
                                              request.content))
        yield request


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Send one signed request to the kimiclaw gateway.")
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--private-key-file", help="file holding the private key line (else env KC_PRIVATE_KEY)")
    ap.add_argument("url")
    ap.add_argument("body", nargs="?")
    a = ap.parse_args()
    if a.private_key_file:
        with open(a.private_key_file) as f:
            private_key = f.read()
    else:
        private_key = os.environ.get("KC_PRIVATE_KEY", "")
    if not private_key.strip():
        sys.exit("no private key: pass --private-key-file or set KC_PRIVATE_KEY")
    kw = {"content": a.body.encode(), "headers": {"Content-Type": "application/json"}} if a.body else {}
    r = httpx.request("POST" if a.body else "GET", a.url, auth=Signer(a.key_id, private_key), timeout=600, **kw)
    print(r.status_code, r.reason_phrase)
    print(r.text)
    sys.exit(0 if r.is_success else 1)
