"""Regenerate openapi.yaml from the app. Needs any valid public keys file, e.g.:
    { echo '# kimiclaw-public-keys v1'; python tools/new_api_key.py --caller dev --mint | tail -1; } > /tmp/k && GATEWAY_PUBLIC_KEYS_FILE=/tmp/k python tools/freeze_openapi.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from gateway.launcher_guard import mark_launched  # noqa: E402

mark_launched()
from gateway.main import create_app  # noqa: E402

app = create_app()

with open(os.path.join(ROOT, "openapi.yaml"), "w") as f:
    yaml.safe_dump(app.openapi(), f, sort_keys=False, allow_unicode=True)
