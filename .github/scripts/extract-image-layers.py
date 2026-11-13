#!/usr/bin/env python3
"""Extract docker-save layer archives into a flat directory tree for scanners."""
from __future__ import annotations

import json
import sys
import tarfile
from pathlib import Path


def extract_tar(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, mode="r:*") as tf:
        # Python 3.13 supports filter=; use it when available.
        kwargs = {}
        if hasattr(tarfile, "data_filter"):
            kwargs["filter"] = "data"
        tf.extractall(dest, **kwargs)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract-image-layers.py <raw-docker-save-dir> <out-dir>", file=sys.stderr)
        return 2
    raw = Path(sys.argv[1])
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    manifests = raw / "manifest.json"
    layers: list[Path] = []
    if manifests.is_file():
        data = json.loads(manifests.read_text(encoding="utf-8"))
        for entry in data:
            for rel in entry.get("Layers") or []:
                layers.append(raw / rel)
    if not layers:
        layers = list(raw.rglob("layer.tar"))
        layers.extend(p for p in raw.rglob("*.tar") if p.name != "layer.tar")
    if not layers:
        print("no image layers found in docker save output", file=sys.stderr)
        return 1
    seen: set[str] = set()
    extracted = 0
    for layer in layers:
        if not layer.is_file():
            print(f"missing layer archive: {layer}", file=sys.stderr)
            return 1
        key = str(layer.resolve())
        if key in seen:
            continue
        seen.add(key)
        dest = out / f"layer-{extracted:03d}-{layer.parent.name or layer.stem}"
        extract_tar(layer, dest)
        extracted += 1
    print(f"extracted {extracted} layer archive(s) into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
