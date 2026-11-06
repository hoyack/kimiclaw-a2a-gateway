"""Writes one n8n workflow file per bot: python3 routing/n8n/build.py. Files only; import by hand."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from routing.router import BOTS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def workflow(bot):
    return {
        "name": f"A2A routing: {bot}",
        "active": False,
        "settings": {"executionOrder": "v1", "timezone": "America/Chicago", "saveDataSuccessExecution": "none"},
        "nodes": [
            {"id": f"{bot}-schedule", "name": "Every 5 minutes", "type": "n8n-nodes-base.scheduleTrigger",
             "typeVersion": 1.2, "position": [0, 0],
             "parameters": {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}]}}},
            {"id": f"{bot}-poll", "name": f"Poll owner_{bot}", "type": "n8n-nodes-base.executeCommand",
             "typeVersion": 1, "position": [240, 0],
             "parameters": {"command": f"cd \"$A2A_ROUTING_DIR\" && flock -n /tmp/a2a-routing-{bot}.lock python3 -m routing.cli poll --bot {bot}"}},
        ],
        "connections": {"Every 5 minutes": {"main": [[{"node": f"Poll owner_{bot}", "type": "main", "index": 0}]]}},
    }


if __name__ == "__main__":
    for bot in BOTS:
        with open(os.path.join(HERE, f"poller-{bot}.json"), "w") as f:
            json.dump(workflow(bot), f, indent=2)
            f.write("\n")
