#!/usr/bin/env python3
"""Package the real module WebUI with one isolated offline API injection."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
DEFAULT_WEBROOT = HERE.parents[2] / "module/webroot"
DEFAULT_OUTPUT = HERE.parents[3] / "build/susfs-guide-interactive-042-20261022/assets/guide"
INJECTION = b'<script src="../simulator.js"></script>\n'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare_simulator(output_dir: Path, webroot: Path | None = None) -> dict:
    """output_dir is assets/guide; return provenance for the parent asset builder."""
    source = (webroot or DEFAULT_WEBROOT).resolve(strict=True)
    output = output_dir.resolve()
    target = output / "simulator"
    if target == source or target.is_relative_to(source) or source.is_relative_to(target):
        raise ValueError("Simulator assets must be isolated from the production WebUI")
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if not files or not (source / "index.html").is_file():
        raise ValueError("Production WebUI index.html is missing")
    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("Do not package symlinked WebUI inputs")
    expected = {path.relative_to(source).as_posix() for path in files}
    if target.exists():
        existing = {path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()}
        if existing - expected:
            raise ValueError("Stale simulator assets; use a clean build output")
    source_hashes, packaged_hashes = {}, {}
    for path in files:
        name = path.relative_to(source).as_posix()
        original = path.read_bytes()
        packaged = original
        if name == "index.html":
            match = re.search(rb"<script\b", original, re.IGNORECASE)
            if not match or INJECTION in original:
                raise ValueError("Expected unmodified production HTML with scripts")
            packaged = original[:match.start()] + INJECTION + original[match.start():]
            if packaged.replace(INJECTION, b"", 1) != original:
                raise AssertionError("Injection must be the sole index.html change")
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(packaged)
        source_hashes[name] = digest(original)
        packaged_hashes[name] = digest(packaged)
    adapter = (HERE / "simulator.js").read_bytes()
    output.mkdir(parents=True, exist_ok=True)
    (output / "simulator.js").write_bytes(adapter)
    changed = [name for name in source_hashes if source_hashes[name] != packaged_hashes[name]]
    if changed != ["index.html"]:
        raise AssertionError("Only the simulator HTML may differ from production")
    return {
        "format": "susfs-guide-webui-simulator-v1",
        "webui_source_sha256": source_hashes,
        "webui_packaged_sha256": packaged_hashes,
        "webui_file_count": len(files),
        "simulator_js_sha256": digest(adapter),
        "webui_changed_files": changed,
        "webui_index_injection": INJECTION.decode("ascii").rstrip("\n"),
        "simulator_path": "simulator/index.html",
        "simulation": "offline in-memory API adapter; no device, root or network access",
    }


prepare = prepare_simulator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, default=DEFAULT_OUTPUT,
                        help="Prepared assets/guide directory")
    parser.add_argument("--webroot", type=Path, default=DEFAULT_WEBROOT)
    args = parser.parse_args()
    print(json.dumps(prepare_simulator(args.output_dir, args.webroot), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
