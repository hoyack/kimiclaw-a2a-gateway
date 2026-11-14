"""Regenerate openapi.yaml from the app. Needs any valid public keys file, e.g.:
    python tools/new_api_key.py dev | tail -1 > /tmp/k && GATEWAY_PUBLIC_KEYS_FILE=/tmp/k python tools/freeze_openapi.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from gateway.main import app  # noqa: E402

with open(os.path.join(ROOT, "openapi.yaml"), "w") as f:
    yaml.safe_dump(app.openapi(), f, sort_keys=False, allow_unicode=True)
