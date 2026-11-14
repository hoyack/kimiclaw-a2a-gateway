#!/usr/bin/env python3
"""Mint an Ed25519 keypair on the caller side. The private key is written to a 0600 file and never printed.

    python tools/new_keypair.py --private-key-file a2a.key

stdout: the public key only (unpadded base64url of the 32-byte Ed25519 public key). Give that, and only that, to
the operator with `python tools/new_api_key.py --caller NAME --public-key-file` (or `--public-key`).
"""
import argparse
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


ap = argparse.ArgumentParser(description="Generate an Ed25519 keypair; write the private key to a 0600 file, print only the public key.")
ap.add_argument("--private-key-file", required=True, help="new file to write the private key into (must not already exist)")
a = ap.parse_args()
if os.path.exists(a.private_key_file):
    sys.exit(f"{a.private_key_file} already exists")
private = Ed25519PrivateKey.generate()
raw = serialization.Encoding.Raw
priv = b64url(private.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
pub = b64url(private.public_key().public_bytes(raw, serialization.PublicFormat.Raw))
fd = os.open(a.private_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(fd, "w") as f:
        f.write(priv + "\n")
except Exception:
    os.unlink(a.private_key_file)
    raise
os.chmod(a.private_key_file, 0o600)
print(pub)
