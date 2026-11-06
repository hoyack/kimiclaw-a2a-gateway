"""Entry point n8n runs on a schedule: python3 -m routing.cli poll --bot rivet

Secrets come only from env (set on the n8n host from the n8n credentials, see RUNBOOK.md):
JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, A2A_GATEWAY_URL (or A2A_GATEWAY_URL_<BOT>), A2A_GATEWAY_TOKEN. Optional: ROUTING_BLOCKED_STATUS (default Blocked).
Prints a JSON summary of issue keys only.
"""
import argparse
import json
import logging
import os
import sys

from routing.gateway import Gateway
from routing.jira import Jira
from routing.router import BOTS, lint, poll_once

ENV = ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "A2A_GATEWAY_TOKEN")


def main(argv=None, env=os.environ):
    ap = argparse.ArgumentParser(prog="routing")
    ap.add_argument("cmd", choices=["poll", "lint"])
    ap.add_argument("--bot", choices=BOTS)
    a = ap.parse_args(argv)
    missing = [k for k in ENV if not env.get(k)]
    if missing:
        print(json.dumps({"error": "missing env", "vars": missing}))
        return 2
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    jira = Jira(env["JIRA_BASE_URL"], env["JIRA_EMAIL"], env["JIRA_API_TOKEN"])
    if a.cmd == "lint":
        bad = lint(jira.search("project=A2A AND issuetype != Epic"))
        print(json.dumps({"bad": bad}))
        return 1 if bad else 0
    if not a.bot:
        ap.error("--bot is required for poll")
    url = env.get(f"A2A_GATEWAY_URL_{a.bot.upper()}") or env.get("A2A_GATEWAY_URL")
    if not url:
        print(json.dumps({"error": "missing env", "vars": ["A2A_GATEWAY_URL"]}))
        return 2
    print(json.dumps(poll_once(a.bot, jira, Gateway(url, env["A2A_GATEWAY_TOKEN"]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
