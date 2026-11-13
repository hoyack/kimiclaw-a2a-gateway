#!/usr/bin/env python3
"""Mint a caller's key_id and signing secret. stdout: the line to append to the GATEWAY_SIGNING_KEYS_FILE (it holds the
secret, so append it straight into the secret store's copy). stderr: what to hand the caller.

    python tools/new_api_key.py <caller> >> keys.txt
"""
import re
import secrets
import sys

if len(sys.argv) != 2 or not re.fullmatch(r"[A-Za-z0-9_]{1,32}", sys.argv[1]):
    sys.exit("usage: new_api_key.py <caller>   (up to 32 of A-Z a-z 0-9 _; reuse the same caller to rotate)")
key_id = secrets.token_hex(5)
print(f"{key_id} {sys.argv[1]} {secrets.token_urlsafe(32)}")  # 32 bytes from the OS CSPRNG, base64url
print(f"Give {sys.argv[1]} key_id {key_id} and the secret (last field of the stdout line) over a secure channel.",
      file=sys.stderr)
