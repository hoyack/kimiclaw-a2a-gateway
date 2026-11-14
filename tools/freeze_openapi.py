"""Regenerate openapi.yaml from the app. Needs any valid public keys file, e.g.:
    { echo '# kimiclaw-public-keys v1'; python tools/new_api_key.py --caller dev --mint | tail -1; } > /tmp/k && GATEWAY_PUBLIC_KEYS_FILE=/tmp/k python tools/freeze_openapi.py

Optional argument: output path (default: openapi.yaml in the repo root).

Importing this module does not write openapi.yaml and does not mark the process launched.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def app(*_a, **_k):
    """Not a live ASGI app. `uvicorn tools.freeze_openapi:app` is not supported."""
    sys.path.insert(0, ROOT)
    from gateway.launcher_guard import APP_REFUSAL, refuse_launcher
    refuse_launcher(APP_REFUSAL)


def main() -> None:
    sys.path.insert(0, ROOT)
    from gateway.launcher_guard import mark_launched
    mark_launched()
    import yaml
    from gateway.main import create_app

    application = create_app()
    dest = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "openapi.yaml")
    with open(dest, "w") as f:
        yaml.safe_dump(application.openapi(), f, sort_keys=False, allow_unicode=True)


if __name__ == "__main__":
    main()
