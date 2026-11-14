"""Refuse any start that is not `python -m gateway`. One line, one nonzero exit, no crash-loop."""
from __future__ import annotations

import multiprocessing
import os
import resource
import shutil
import signal
import sys
from pathlib import Path

_LAUNCHED = False

APP_REFUSAL = "start with `python -m gateway`; `uvicorn app:app` is not supported"
FACTORY_REFUSAL = "start with `python -m gateway`; `uvicorn gateway.main:create_app --factory` is not supported"

# Interpreter options that consume the following argument.
_PY_VALUE_OPTS = {"-W", "-X", "-Q", "--check-hash-based-pycs"}


def mark_launched() -> None:
    global _LAUNCHED
    _LAUNCHED = True


def launched() -> bool:
    return _LAUNCHED


def _skip_python_options(parts: list[str]) -> list[str]:
    """Return argv after the interpreter and its options (-u, -I, -X dev, -W, -Q, ...)."""
    i = 1
    while i < len(parts):
        a = parts[i]
        if a == "-m" or a == "-c" or a == "-":
            return parts[i:]
        if a.startswith("--") and "=" in a:
            i += 1
            continue
        key = a.split("=", 1)[0]
        if key in _PY_VALUE_OPTS:
            if a == key or a.startswith(key + "=") and a != key:
                # `-X dev` / `--check-hash-based-pycs never` vs `-Xdev` / `-Werror`
                if a == key:
                    i += 2
                else:
                    i += 1
                continue
        if a.startswith("-"):
            i += 1
            continue
        return parts[i:]
    return []


def _installed_scripts(name: str) -> set[str]:
    found: set[str] = set()
    for candidate in (shutil.which(name), os.path.join(sys.prefix, "bin", name)):
        if candidate and os.path.isfile(candidate):
            try:
                found.add(os.path.realpath(candidate))
            except OSError:
                pass
    return found


def _is_installed_script(path: str, name: str) -> bool:
    if os.path.basename(path.replace("\\", "/")) != name:
        return False
    try:
        return os.path.realpath(path) in _installed_scripts(name)
    except OSError:
        return False


def _cmdline_is(parts: list[str], name: str) -> bool:
    """True if argv is that server's console script, `python [opts] -m name`, or `python [opts] <console-script>`."""
    if not parts:
        return False
    argv0 = parts[0].replace("\\", "/")
    if os.path.basename(argv0).startswith("python"):
        rest = _skip_python_options(parts)
        if not rest:
            return False
        if rest[0] == "-m" and len(rest) > 1 and rest[1] == name:
            return True
        return _is_installed_script(rest[0], name)
    if argv0.endswith(f"/{name}/__main__.py"):
        return True
    return _is_installed_script(argv0, name)


def _uvicorn_supervisor_pid() -> int | None:
    """The uvicorn (or hypercorn) supervisor: a multiprocessing parent whose argv is that server.

    Hypercorn clobbers a worker exit 3 to 0 after join, so the arbiter must be signalled.
    Signals to PID 1 are dropped by the kernel, so a refused uvicorn/hypercorn PID-1
    supervisor cannot be made to exit non-zero this way.
    """
    parent = multiprocessing.parent_process()
    if parent is None or parent.pid is None or parent.pid != os.getppid():
        return None
    try:
        parts = [p.decode("utf-8", "replace") for p in Path(f"/proc/{parent.pid}/cmdline").read_bytes().split(b"\0") if p]
    except OSError:
        return None
    if not parts:
        return None
    if _cmdline_is(parts, "uvicorn") or _cmdline_is(parts, "hypercorn"):
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
    """Log one refusal and exit 3. Signal the parent only when it is uvicorn's supervisor."""
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    pid = _uvicorn_supervisor_pid()
    if pid is not None:
        _stop_supervisor(pid)
    os._exit(3)


def refuse_unsupported_import() -> None:
    """Run before importing gateway.config, so WEB_CONCURRENCY cannot raise first."""
    if not launched():
        refuse_launcher(FACTORY_REFUSAL)
