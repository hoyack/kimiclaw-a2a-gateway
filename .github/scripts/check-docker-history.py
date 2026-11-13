#!/usr/bin/env python3
"""Fail if docker history ENV/ARG lines set a secret-like name to a non-empty value.

Prints a redacted history summary. Never prints ENV/ARG values.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIALS?|PASSPHRASE|PRIVATE_KEY|"
    r"PRIVATEKEY|API_KEY|APIKEY|ACCESS_KEY|ACCESSKEY|AUTH_TOKEN|"
    r"CLIENT_SECRET|CONNECTION_STRING|CONN_STR|BEARER|WEBHOOK)",
    re.IGNORECASE,
)

ENV_OR_ARG = re.compile(r"(?:^|\s|#\(nop\)\s*)(ENV|ARG)\s+(.+)$")


def tokenize_assignments(payload: str) -> list[tuple[str, str | None]]:
    """Parse KEY, KEY=, or KEY=VALUE tokens from an ENV/ARG payload."""
    items: list[tuple[str, str | None]] = []
    s = payload.strip()
    i = 0
    n = len(s)
    while i < n:
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break
        # KEY
        start = i
        while i < n and (s[i].isalnum() or s[i] in "_-."):
            i += 1
        if i == start:
            i += 1
            continue
        name = s[start:i]
        if i < n and s[i] == "=":
            i += 1
            if i < n and s[i] in ("'", '"'):
                quote = s[i]
                i += 1
                buf = []
                while i < n and s[i] != quote:
                    if s[i] == "\\" and i + 1 < n:
                        i += 1
                    buf.append(s[i])
                    i += 1
                if i < n and s[i] == quote:
                    i += 1
                items.append((name, "".join(buf)))
            else:
                val_start = i
                while i < n and not s[i].isspace():
                    i += 1
                items.append((name, s[val_start:i]))
        else:
            items.append((name, None))
    return items


def redact_payload(payload: str) -> str:
    def repl_quoted(m: re.Match[str]) -> str:
        return f"{m.group(1)}=<redacted>"

    def repl_plain(m: re.Match[str]) -> str:
        return f"{m.group(1)}=<redacted>"

    out = re.sub(r'([A-Za-z_][A-Za-z0-9_.-]*)=("[^"]*"|\'[^\']*\')', repl_quoted, payload)
    out = re.sub(r"([A-Za-z_][A-Za-z0-9_.-]*)=(\S+)", repl_plain, out)
    return out


def redact_line(line: str) -> str:
    m = ENV_OR_ARG.search(line)
    if not m:
        return line
    return line[: m.start(2)] + redact_payload(m.group(2))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-docker-history.py <image-ref>", file=sys.stderr)
        return 2
    image = sys.argv[1]
    proc = subprocess.run(
        ["docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        print(f"docker history failed for {image} (exit {proc.returncode})", file=sys.stderr)
        return proc.returncode or 2

    lines = [ln.rstrip("\n") for ln in proc.stdout.splitlines()]
    findings: list[str] = []
    env_arg_count = 0
    redacted_lines: list[str] = []
    for line in lines:
        redacted_lines.append(redact_line(line))
        m = ENV_OR_ARG.search(line)
        if not m:
            continue
        env_arg_count += 1
        for name, value in tokenize_assignments(m.group(2)):
            if value and SECRET_NAME.search(name):
                findings.append(f"{m.group(1)} {name}=<redacted>")

    summary = []
    summary.append("## docker history secret check")
    summary.append("")
    summary.append(f"- image: `{image}`")
    summary.append(f"- history lines: {len(lines)}")
    summary.append(f"- ENV/ARG instructions: {env_arg_count}")
    summary.append(f"- secret-like ENV/ARG with values: {len(findings)}")
    summary.append("")
    if findings:
        summary.append("**FAIL:** secret-like ENV/ARG names were set to a non-empty value:")
        for item in findings:
            summary.append(f"- `{item}`")
    else:
        summary.append("**PASS:** no secret-like ENV/ARG names were set to a non-empty value.")
    summary.append("")
    summary.append("<details><summary>docker history --no-trunc (ENV/ARG values redacted)</summary>")
    summary.append("")
    summary.append("```")
    summary.extend(redacted_lines)
    summary.append("```")
    summary.append("")
    summary.append("</details>")
    summary.append("")
    text = "\n".join(summary) + "\n"
    print(text, end="")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
