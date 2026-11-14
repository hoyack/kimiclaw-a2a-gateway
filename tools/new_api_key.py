#!/usr/bin/env python3
"""Mint a caller's key_id and Ed25519 keypair.

    python tools/new_api_key.py <caller>

stdout, once: the PRIVATE key (hand it to the caller over a secure channel; it is not stored anywhere), then the
public line to append to GATEWAY_PUBLIC_KEYS_FILE. The gateway only ever holds the public line.
"""
import base64
import re
import secrets
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


if len(sys.argv) != 2 or not re.fullmatch(r"[A-Za-z0-9_]{1,32}", sys.argv[1]):
    sys.exit("usage: new_api_key.py <caller>   caller: up to 32 of A-Z a-z 0-9 _; reuse the same caller to rotate")
caller, key_id = sys.argv[1], secrets.token_hex(5)  # key_id: 40 bits from the OS CSPRNG, so it can't be guessed
private = Ed25519PrivateKey.generate()
raw = serialization.Encoding.Raw
print(f"# WARNING: the next line is the PRIVATE key for {caller} (key_id {key_id}). It is shown once and stored nowhere.")
print("# Give it to the caller over a secure channel; anyone holding it can sign as them. Never put it in the keys file.")
print(b64url(private.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())))
print("# Public line for GATEWAY_PUBLIC_KEYS_FILE (not secret):")
print(f"{key_id} {caller} {b64url(private.public_key().public_bytes(raw, serialization.PublicFormat.Raw))}")
