#!/usr/bin/env python3
"""Build the offline guided lab and bundle the exact current SUSFS WebUI."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ROOT = REPO.parent
DEFAULT = ROOT / "build/susfs-guide-interactive-042-20261022"


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT)
    parser.add_argument("--manual", type=Path, default=ROOT / "release/current/SUSFS-0.3.0-WebUI使用手册")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == REPO or output.is_relative_to(REPO):
        raise ValueError("Generated assets belong in workspace build/, outside the repository")
    target = output / "assets/guide"
    target.mkdir(parents=True, exist_ok=True)
    reference_stage = output / "reference-stage"
    reference_builder = load("susfs_reference_asset_builder", HERE.parent / "android/prepare-assets.py")
    # The legacy extractor's default evidence folder belongs to the previous
    # release; direct its new report into this build instead of overwriting it.
    reference_builder.WORK = reference_stage / "reports"
    previous_args = sys.argv
    try:
        sys.argv = ["prepare-assets.py", "--manual", str(args.manual), "--output", str(reference_stage)]
        with contextlib.redirect_stdout(io.StringIO()):
            reference_builder.main()
    finally:
        sys.argv = previous_args
    reference = reference_stage / "assets/guide"
    shutil.copytree(reference, target / "reference", dirs_exist_ok=True)
    adapter = load("susfs_simulator_packager", HERE / "prepare-simulator.py")
    provenance = adapter.prepare_simulator(target)
    for name in ("index.html", "interactive.css", "interactive.js", "lessons.js", "scenes.js", "app-perspective.js", "app-perspective.css"):
        shutil.copyfile(HERE / name, target / name)
    lesson_source = (HERE / "lessons.js").read_text(encoding="utf-8")
    ids = re.findall(r"\bid:\s*'([a-z]+)'\s*,\s*title:", lesson_source)
    assert len(ids) == len(set(ids)) >= 10, "Missing or duplicate interactive lessons"
    metadata = {**provenance, "format": "susfs-guide-interactive-v1", "app": "SUSFS 使用手册",
                "package": "org.susfs4skp.guide", "version": "0.4.2", "versionCode": 5,
                "manual_version": "0.3.0", "date": "2026-10-22", "offline": True,
                "lessons": len(ids), "lesson_ids": ids,
                "svg": len(list((target / "reference/svg").glob("*.svg"))),
                "screenshots": len(list((target / "reference/screenshots").glob("*.png"))),
                "reading": "purpose-first; guided actions in real WebUI; advanced on demand",
                "source_sha256": {p.name: digest(p) for p in HERE.iterdir() if p.is_file()},
                "prepared_html_sha256": digest(target / "index.html"), "device_tested": False}
    (target / "app-metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    work = ROOT / "work/susfs-interactive-guide-042-20261022"
    work.mkdir(parents=True, exist_ok=True)
    (work / "assets.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "prepared", "output": str(target), "lessons": len(ids),
                      "webui_files": provenance["webui_file_count"], "app_version": "0.4.2",
                      "module_changed": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
