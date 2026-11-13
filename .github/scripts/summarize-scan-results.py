#!/usr/bin/env python3
"""Write redacted scanner results (counts and paths only) to stdout and the job summary."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size == 0:
        return None
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


def trufflehog_rows(data: Any) -> list[dict[str, str]]:
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if "DetectorName" not in item and "DetectorType" not in item:
            continue
        meta = item.get("SourceMetadata") or {}
        inner = ((meta.get("Data") or {}).get("Filesystem") or {})
        path = inner.get("file") or inner.get("File") or "(unknown path)"
        line = inner.get("line") or inner.get("Line") or ""
        rows.append(
            {
                "detector": str(item.get("DetectorName") or item.get("DetectorType") or "unknown"),
                "path": str(path),
                "line": str(line),
            }
        )
    return rows


def gitleaks_rows(data: Any) -> list[dict[str, str]]:
    if not data:
        return []
    if isinstance(data, dict):
        if "findings" in data:
            data = data["findings"]
        else:
            data = [data]
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "rule": str(item.get("RuleID") or item.get("Description") or "unknown"),
                "path": str(item.get("File") or item.get("FilePath") or "(unknown path)"),
                "line": str(item.get("StartLine") or item.get("Line") or ""),
            }
        )
    return rows


def fmt_row(kind: str, name: str, path: str, line: str) -> str:
    loc = path
    if line:
        loc = f"{path}:{line}"
    return f"- {kind} `{name}` in `{loc}`"


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: summarize-scan-results.py <trufflehog-json> <trufflehog-rc> <gitleaks-json> <gitleaks-rc>",
            file=sys.stderr,
        )
        return 2
    th_path = Path(sys.argv[1])
    th_rc = int(sys.argv[2])
    gl_path = Path(sys.argv[3])
    gl_rc = int(sys.argv[4])

    th_rows = trufflehog_rows(load_json(th_path))
    gl_rows = gitleaks_rows(load_json(gl_path))

    # trufflehog --fail exits 183 on findings; gitleaks --exit-code 1 on findings.
    th_tool_error = th_rc not in (0, 183)
    gl_tool_error = gl_rc not in (0, 1)
    th_findings = len(th_rows)
    gl_findings = len(gl_rows)

    lines = [
        "## Image layer secret scan",
        "",
        f"- trufflehog filesystem (exit {th_rc}): {th_findings} finding(s)",
        f"- gitleaks detect --no-git --redact (exit {gl_rc}): {gl_findings} finding(s)",
        "",
        "Values are omitted. Paths are from extracted image layers.",
        "",
    ]
    if th_tool_error:
        lines.append(f"**ERROR:** trufflehog exited {th_rc} without a findings status.")
        lines.append("")
    if gl_tool_error:
        lines.append(f"**ERROR:** gitleaks exited {gl_rc} without a findings status.")
        lines.append("")
    if th_rows:
        lines.append("trufflehog findings (detector and path only):")
        for row in th_rows:
            lines.append(fmt_row("detector", row["detector"], row["path"], row["line"]))
        lines.append("")
    if gl_rows:
        lines.append("gitleaks findings (rule and path only):")
        for row in gl_rows:
            lines.append(fmt_row("rule", row["rule"], row["path"], row["line"]))
        lines.append("")
    if not th_rows and not gl_rows and not th_tool_error and not gl_tool_error:
        lines.append("**PASS:** no secrets found in extracted image layers.")
        lines.append("")

    text = "\n".join(lines) + "\n"
    print(text, end="")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(text)

    if th_tool_error or gl_tool_error:
        return 2
    if th_findings or gl_findings or th_rc == 183 or gl_rc == 1:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
