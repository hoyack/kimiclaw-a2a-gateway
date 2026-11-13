#!/usr/bin/env python3
"""Mint a caller's key_id and signing secret. stdout: the line to append to the GATEWAY_SIGNING_KEYS_FILE (it holds the
secret, so append it straight into the secret store's copy). stderr: what to hand the caller.

    python tools/new_api_key.py <caller> >> keys.txt
"""
import secrets
import sys

if len(sys.argv) != 2 or not sys.argv[1].strip() or len(sys.argv[1].split()) != 1:
    sys.exit("usage: new_api_key.py <caller-name-without-spaces>")
key_id = secrets.token_hex(5)
print(f"{key_id} {sys.argv[1]} {secrets.token_urlsafe(32)}")
print(f"Give {sys.argv[1]} key_id {key_id} and the secret (last field of the stdout line) over a secure channel.",
      file=sys.stderr)
