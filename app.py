"""Importing this module is refused. Start the gateway with `python -m gateway`."""
from gateway.launcher_guard import APP_REFUSAL, refuse_launcher

refuse_launcher(APP_REFUSAL)
