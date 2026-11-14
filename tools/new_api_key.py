#!/usr/bin/env python3
"""Issue a key_id and record a caller's Ed25519 public key.

Caller-generated (default; the private key never leaves the caller):

    python tools/new_keypair.py --private-key-file a2a.key          # caller: writes 0600 private key, prints public key
    python tools/new_api_key.py --caller NAME --public-key-file pub.b64
    python tools/new_api_key.py --caller NAME --public-key=PUBLIC

stdout is the public line to append to GATEWAY_PUBLIC_KEYS_FILE (which must start with `# kimiclaw-public-keys v1`).

Operator-generated (the operator sees the private key; use only when the caller cannot mint):

    python tools/new_api_key.py --caller NAME --mint
"""
import argparse
import base64
import os
import re
import secrets
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.pubkey import public_key  # noqa: E402

CALLER_RE = re.compile(r"[A-Za-z0-9_]{1,32}")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def load_public(text: str) -> str:
    text = text.strip()
    if public_key(text) is None:
        sys.exit("public key must be a canonical, on-curve Ed25519 key of order > 8, unpadded base64url")
    return text


ap = argparse.ArgumentParser(description="Issue a key_id and the public line for GATEWAY_PUBLIC_KEYS_FILE.")
ap.add_argument("--caller", help="caller name: up to 32 of A-Z a-z 0-9 _; reuse the same caller to rotate")
ap.add_argument("--public-key-file", help="file holding the caller's public key (from tools/new_keypair.py)")
ap.add_argument("--public-key", help="the caller's public key, unpadded base64url")
ap.add_argument("--mint", action="store_true",
                help="operator generates the keypair (prints the private key; prefer caller-generated)")
ap.add_argument("caller_pos", nargs="?", help="same as --caller; does not imply --mint")
# a public key is unpadded base64url and may start with '-', which argparse would take as a flag
argv, i, out = sys.argv[1:], 0, []
while i < len(argv):
    if argv[i] == "--public-key" and i + 1 < len(argv):
        out.append("--public-key=" + argv[i + 1]); i += 2; continue
    out.append(argv[i]); i += 1
a = ap.parse_args(out)
caller = a.caller or a.caller_pos
if not caller or not CALLER_RE.fullmatch(caller) or (a.caller and a.caller_pos and a.caller != a.caller_pos):
    sys.exit("usage: new_api_key.py --caller NAME --public-key-file FILE | --public-key KEY\n"
             "       new_api_key.py --caller NAME --mint          (operator-generated; avoid if the caller can mint)")
if a.public_key and a.public_key_file:
    sys.exit("pass only one of --public-key or --public-key-file")
if (a.public_key or a.public_key_file) and a.mint:
    sys.exit("--mint cannot be combined with --public-key or --public-key-file")
register = a.public_key or a.public_key_file
if not register and not a.mint:
    sys.exit("caller-generated is the default: pass --public-key-file or --public-key "
             "(the caller runs tools/new_keypair.py). To have the operator mint, pass --mint.")
if a.public_key_file:
    try:
        with open(a.public_key_file) as f:
            public = load_public(f.read())
    except OSError as e:
        sys.exit(f"public key file unreadable: {type(e).__name__}")
elif a.public_key:
    public = load_public(a.public_key)
else:
    public = None

key_id = secrets.token_hex(5)  # key_id: 40 bits from the OS CSPRNG, so it can't be guessed
if public is None:
    private = Ed25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    print(f"# WARNING: the next line is the PRIVATE key for {caller} (key_id {key_id}). It is shown once and stored nowhere.")
    print("# Give it to the caller over a secure channel; anyone holding it can sign as them. Never put it in the keys file.")
    print("# Prefer tools/new_keypair.py on the caller so the operator never sees the private key.")
    print(b64url(private.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())))
    public = b64url(private.public_key().public_bytes(raw, serialization.PublicFormat.Raw))
    print("# Public line for GATEWAY_PUBLIC_KEYS_FILE (not secret). The file must start with `# kimiclaw-public-keys v1`:")
print(f"{key_id} {caller} {public}")
