#!/usr/bin/env python3
"""Mint a caller key. stdout: the line to append to the GATEWAY_KEYS_FILE. stderr: the key, shown once, never stored.

    python tools/new_api_key.py <caller> >> keys.txt
"""
import hashlib
import secrets
import sys

if len(sys.argv) != 2 or not sys.argv[1].strip() or len(sys.argv[1].split()) != 1:
    sys.exit("usage: new_api_key.py <caller-name-without-spaces>")
key_id = secrets.token_hex(5)
key = f"kc_{key_id}_{secrets.token_urlsafe(32)}"
print(f"{key_id} {hashlib.sha256(key.encode()).hexdigest()} {sys.argv[1]}")
print(f"API key for {sys.argv[1]} (give it to the caller once; it is not stored anywhere): {key}", file=sys.stderr)
