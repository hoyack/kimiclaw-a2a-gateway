"""Refuse any start that is not `python -m gateway`. One line, one nonzero exit, no crash-loop."""
from __future__ import annotations

import os
import signal
import sys

_LAUNCHED = False

APP_REFUSAL = "start with `python -m gateway`; `uvicorn app:app` is not supported"
FACTORY_REFUSAL = "start with `python -m gateway`; `uvicorn gateway.main:create_app --factory` is not supported"


def mark_launched() -> None:
    global _LAUNCHED
    _LAUNCHED = True


def launched() -> bool:
    return _LAUNCHED


def _workers_from_argv() -> int | None:
    argv = sys.argv
    for i, a in enumerate(argv):
        if a in ("--workers", "-w") and i + 1 < len(argv):
            try:
                return int(argv[i + 1], 10)
            except ValueError:
                return None
        if a.startswith("--workers="):
            try:
                return int(a.split("=", 1)[1], 10)
            except ValueError:
                return None
    return None


def refuse_launcher(message: str) -> None:
    """Log one refusal and exit nonzero once. Stops a uvicorn --workers supervisor if present."""
    workers = _workers_from_argv()
    if workers is not None and workers != 1:
        path = f"/tmp/kimiclaw-launcher-refuse-{os.getppid()}.flag"
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            os._exit(1)
        try:
            os.write(fd, b"1")
        finally:
            os.close(fd)
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
        try:
            os.kill(os.getppid(), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        os._exit(1)
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    os._exit(1)
