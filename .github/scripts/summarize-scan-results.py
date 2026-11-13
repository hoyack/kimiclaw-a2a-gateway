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


def classify_trufflehog(item: dict[str, Any]) -> str:
    if item.get("Verified") is True:
        return "verified"
    status = str(item.get("Status") or item.get("verification_status") or "").lower()
    if item.get("VerificationError") or item.get("verification_error") or status == "unknown":
        return "unknown"
    return "unverified"


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
                "class": classify_trufflehog(item),
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

    # trufflehog exits 0 without --fail even when unverified results exist.
    # Exit 183 is still treated as a findings status if an older flag is used.
    th_tool_error = th_rc not in (0, 183)
    gl_tool_error = gl_rc not in (0, 1)
    th_verified = [r for r in th_rows if r.get("class") == "verified"]
    th_unknown = [r for r in th_rows if r.get("class") == "unknown"]
    th_unverified = [r for r in th_rows if r.get("class") not in {"verified", "unknown"}]
    gl_findings = len(gl_rows)

    lines = [
        "## Image layer secret scan",
        "",
        f"- trufflehog filesystem (exit {th_rc}): {len(th_verified)} verified, {len(th_unknown)} unknown, {len(th_unverified)} unverified",
        f"- gitleaks detect --no-git --redact (exit {gl_rc}): {gl_findings} finding(s)",
        "",
        "Values are omitted. Paths are from extracted image layers.",
        "The job fails on verified or unknown trufflehog results, or any gitleaks finding.",
        "Unverified results are listed for review and do not fail the job.",
        "",
    ]
    if th_tool_error:
        lines.append(f"**ERROR:** trufflehog exited {th_rc} without a findings status.")
        lines.append("")
    if gl_tool_error:
        lines.append(f"**ERROR:** gitleaks exited {gl_rc} without a findings status.")
        lines.append("")
    def emit(title: str, kind: str, key: str, rows: list[dict[str, str]]) -> None:
        if not rows:
            return
        lines.append(title)
        for row in rows:
            lines.append(fmt_row(kind, row[key], row["path"], row["line"]))
        lines.append("")

    emit("trufflehog verified findings (detector and path only):", "detector", "detector", th_verified)
    emit("trufflehog unknown findings (detector and path only):", "detector", "detector", th_unknown)
    emit("trufflehog unverified findings (informational, detector and path only):", "detector", "detector", th_unverified)
    emit("gitleaks findings (rule and path only):", "rule", "rule", gl_rows)

    blocking = bool(th_verified or th_unknown or gl_rows or gl_rc == 1)
    if not blocking and not th_tool_error and not gl_tool_error:
        if th_unverified:
            lines.append("**PASS:** no verified or unknown secrets in extracted image layers.")
        else:
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
    if blocking:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
