"""Refuse any start that is not `python -m gateway`. One line, one nonzero exit, no crash-loop."""
from __future__ import annotations

import multiprocessing
import os
import resource
import signal
import sys
from pathlib import Path

_LAUNCHED = False

APP_REFUSAL = "start with `python -m gateway`; `uvicorn app:app` is not supported"
FACTORY_REFUSAL = "start with `python -m gateway`; `uvicorn gateway.main:create_app --factory` is not supported"


def mark_launched() -> None:
    global _LAUNCHED
    _LAUNCHED = True


def launched() -> bool:
    return _LAUNCHED


def _uvicorn_supervisor_pid() -> int | None:
    """Only the uvicorn supervisor: a multiprocessing parent whose argv names uvicorn."""
    parent = multiprocessing.parent_process()
    if parent is None or parent.pid is None or parent.pid != os.getppid():
        return None
    try:
        parts = [p.decode("utf-8", "replace") for p in Path(f"/proc/{parent.pid}/cmdline").read_bytes().split(b"\0") if p]
    except OSError:
        return None
    for i, part in enumerate(parts):
        if os.path.basename(part) == "uvicorn":
            return parent.pid
        if part == "-m" and i + 1 < len(parts) and parts[i + 1] == "uvicorn":
            return parent.pid
        if part.replace("\\", "/").endswith("/uvicorn/__main__.py"):
            return parent.pid
    return None


def _stop_supervisor(pid: int) -> None:
    # SIGALRM: uvicorn does not handle it, default action is a non-zero exit and no core dump;
    # prlimit RLIMIT_CORE=0 is belt and braces if a core-dumping signal is ever used.
    try:
        resource.prlimit(pid, resource.RLIMIT_CORE, (0, 0))
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGALRM)
    except (ProcessLookupError, PermissionError):
        pass


def refuse_launcher(message: str) -> None:
    """Log one refusal and exit 2. Signal the parent only when it is uvicorn's supervisor."""
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    pid = _uvicorn_supervisor_pid()
    if pid is not None:
        _stop_supervisor(pid)
    os._exit(2)


def refuse_unsupported_import() -> None:
    """Run before importing gateway.config, so WEB_CONCURRENCY cannot raise first."""
    if not launched():
        refuse_launcher(FACTORY_REFUSAL)
