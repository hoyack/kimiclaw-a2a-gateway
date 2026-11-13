#!/usr/bin/env python3
"""Sign requests to the kimiclaw gateway (README "Request signing").

Library:  httpx.Client(base_url=URL, auth=Signer(key_id, secret))  signs every request it sends.
CLI:      python tools/sign_request.py --key-id ID --secret-file FILE URL ['{"jsonrpc": ...}']
          GET without a body, POST (application/json) with one; prints the status line and the response body.
          The secret file holds only the secret, so it never lands in argv or shell history.
"""
import argparse
import hashlib
import hmac
import secrets
import sys
import time

import httpx


def canonical(method: str, raw_path: bytes, query: bytes, timestamp: str, nonce: str, body: bytes) -> bytes:
    sorted_query = b"&".join(sorted(p for p in query.split(b"&") if p))
    target = raw_path + (b"?" + sorted_query if sorted_query else b"")
    return b"\n".join([method.encode(), target, timestamp.encode(), nonce.encode(), hashlib.sha256(body).hexdigest().encode()])


def signed_headers(key_id: str, secret: str, method: str, raw_path: bytes, query: bytes, body: bytes,
                   timestamp: str | None = None, nonce: str | None = None) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or secrets.token_urlsafe(24)
    message = canonical(method.upper(), raw_path, query, timestamp, nonce, body)
    return {"X-KC-Key-Id": key_id, "X-KC-Timestamp": timestamp, "X-KC-Nonce": nonce,
            "X-KC-Signature": hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()}


class Signer(httpx.Auth):
    requires_request_body = True

    def __init__(self, key_id: str, secret: str):
        self.key_id, self.secret = key_id, secret

    def auth_flow(self, request: httpx.Request):
        raw_path, _, query = request.url.raw_path.partition(b"?")
        request.headers.update(signed_headers(self.key_id, self.secret, request.method, raw_path, query, request.content))
        yield request


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Send one signed request to the kimiclaw gateway.")
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--secret-file", required=True)
    ap.add_argument("url")
    ap.add_argument("body", nargs="?")
    a = ap.parse_args()
    with open(a.secret_file) as f:
        secret = f.read().strip()
    kw = {"content": a.body.encode(), "headers": {"Content-Type": "application/json"}} if a.body else {}
    r = httpx.request("POST" if a.body else "GET", a.url, auth=Signer(a.key_id, secret), timeout=600, **kw)
    print(r.status_code, r.reason_phrase)
    print(r.text)
    sys.exit(0 if r.is_success else 1)
