"""Only supported entrypoint: `python -m gateway`. Pins one worker, the concurrency cap, and the probe port."""
import argparse
import asyncio
import signal
import time

from uvicorn import Config, Server

from gateway.config import LOG
from gateway.main import create_app, limit_concurrency, probe_port
from gateway.probe import probe_app
from gateway.routes.health import set_main_serving


def _config(app, host, port, *, cap=None):
    kwargs = dict(app=app, host=host, port=port, access_log=False, workers=1)
    if cap is not None:
        kwargs["limit_concurrency"] = cap
    return Config(**kwargs)


async def _wait_until(predicate, timeout=30, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False


async def serve(host: str, port: int, probe: int, cap: int):
    """Start the probe listener immediately, then the main app (whose lifespan holds ~31s)."""
    set_main_serving(False)
    probe_server = Server(_config(probe_app, host, probe))
    main_server = Server(_config(create_app(), host, port, cap=cap))
    LOG.warning("uvicorn limit_concurrency=%d probe_port=%d workers=1",
                cap, probe)

    async def run_probe():
        await probe_server._serve()

    async def run_main():
        try:
            await main_server._serve()
        finally:
            set_main_serving(False)
            probe_server.should_exit = True

    async def mark_serving():
        if await _wait_until(lambda: main_server.started or main_server.should_exit, timeout=180):
            if main_server.started:
                set_main_serving(True)
                LOG.warning("main port is serving on %s:%d", host, port)

    probe_task = asyncio.create_task(run_probe(), name="probe")
    if not await _wait_until(lambda: probe_server.started or probe_server.should_exit, timeout=15):
        raise RuntimeError("probe server failed to start")
    if not probe_server.started:
        raise RuntimeError("probe server exited before listening")
    LOG.warning("probe listening on %s:%d (GET /healthz, GET /readyz)", host, probe)

    loop = asyncio.get_running_loop()

    def stop():
        main_server.should_exit = True
        probe_server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop)
        except (NotImplementedError, RuntimeError):
            pass

    await asyncio.gather(probe_task, asyncio.create_task(run_main(), name="main"),
                         asyncio.create_task(mark_serving(), name="mark-serving"))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m gateway")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    cap = limit_concurrency()
    probe = probe_port()
    if args.port == probe:
        raise RuntimeError("GATEWAY_PROBE_PORT must differ from the main port")
    asyncio.run(serve(args.host, args.port, probe, cap))


if __name__ == "__main__":
    main()
