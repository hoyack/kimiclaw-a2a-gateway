"""Refuse any start that is not `python -m gateway`. One line, one nonzero exit, no crash-loop."""
from __future__ import annotations

import os
import signal
import socket
import sys
import time

_LAUNCHED = False
_hold = None  # keep the abstract socket bound until this process exits

APP_REFUSAL = "start with `python -m gateway`; `uvicorn app:app` is not supported"
FACTORY_REFUSAL = "start with `python -m gateway`; `uvicorn gateway.main:create_app --factory` is not supported"


def mark_launched() -> None:
    global _LAUNCHED
    _LAUNCHED = True


def launched() -> bool:
    return _LAUNCHED


def _int_or_none(raw) -> int | None:
    try:
        return int(raw, 10)
    except (TypeError, ValueError):
        return None


def _argv_flag(*names: str) -> str | None:
    argv = sys.argv
    for i, a in enumerate(argv):
        for name in names:
            if a == name and i + 1 < len(argv):
                return argv[i + 1]
            if a.startswith(name + "="):
                return a.split("=", 1)[1]
    return None


def _cli_workers() -> int | None:
    raw = _argv_flag("--workers", "-w")
    return None if raw is None else _int_or_none(raw)


def _supervised() -> bool:
    """True when uvicorn will restart this process if it only os._exit(1)."""
    workers = _cli_workers()
    if workers is not None and workers != 1:
        return True
    web = _int_or_none(os.environ.get("WEB_CONCURRENCY"))
    if web is not None and web != 1:
        return True
    if any(a == "--reload" or a.startswith("--reload=") or a.startswith("--reload-") for a in sys.argv):
        return True
    return False


def _looks_like_uvicorn() -> bool:
    argv = sys.argv
    if any(a == "--factory" or a.startswith("--factory=") for a in argv):
        return True
    if "-m" in argv:
        i = argv.index("-m")
        if i + 1 < len(argv) and argv[i + 1] == "uvicorn":
            return True
    return any("uvicorn" in os.path.basename(a) for a in argv[:2])


def _first_refusal() -> bool:
    """First worker of this uvicorn start wins. Abstract socket: nothing on disk.

    The name is the listen port (shared by every worker via argv), not the parent
    pid, because spawn workers can briefly see different ppids. The socket is
    held until this process exits so a late worker cannot print a second line.
    """
    global _hold
    port = _argv_flag("--port", "-p") or "8000"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind("\0kimiclaw-launcher-" + port)
    except OSError:
        return False
    _hold = sock
    return True


def _abort_supervisor() -> None:
    # uvicorn's Multiprocess/Reload treat SIGTERM as a clean exit 0 and restart a
    # child that only os._exit(1). SIGKILL of the supervisor is PermissionError here
    # (including multiprocessing.parent_process()); SIGABRT is unhandled, so it exits non-zero.
    try:
        os.kill(os.getppid(), signal.SIGABRT)
    except (ProcessLookupError, PermissionError):
        pass


def refuse_launcher(message: str) -> None:
    """Log one refusal and exit nonzero once."""
    if _supervised():
        if not _first_refusal():
            os._exit(1)
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
        _abort_supervisor()
        time.sleep(0.2)  # hold the exclusive socket so a late worker cannot print
        os._exit(1)
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    os._exit(1)


def refuse_unsupported_import() -> None:
    """Run before importing gateway.config, so WEB_CONCURRENCY cannot raise first."""
    if launched() or not _looks_like_uvicorn():
        return
    refuse_launcher(FACTORY_REFUSAL)
