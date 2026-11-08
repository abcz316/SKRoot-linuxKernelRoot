#!/usr/bin/env python3
"""Assemble current loader assets and verified per-KMI builds for standalone packaging."""
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from package_standalone import (
    DEFAULT_KMIS, KO_PREFIX, MODULE, ROOT, expected_kmis, kernel_source_hashes,
    validate_lkm_assets, validate_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, action="append", required=True,
                        help="successful build-receipt.json, once for each expected KMI")
    parser.add_argument("--insmod", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, default=ROOT.parent,
                        help="base for workspace-relative receipt artifact paths")
    parser.add_argument("--expected-kmis", nargs="+", default=DEFAULT_KMIS)
    args = parser.parse_args()
    expected = expected_kmis(args.expected_kmis)
    if args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())):
        raise SystemExit("LKM assembly output must not exist or must be an empty directory")
    if not args.insmod.is_file():
        raise SystemExit("missing susfs_insmod loader binary")
    sources = kernel_source_hashes()
    builds = {}
    for receipt_path in args.receipt:
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise SystemExit(f"cannot read LKM build receipt: {receipt_path}") from exc
        if not isinstance(receipt, dict) or receipt.get("variant") not in expected:
            raise SystemExit(f"receipt has an unexpected KMI: {receipt_path}")
        kmi = receipt["variant"]
        if kmi in builds:
            raise SystemExit(f"duplicate build receipt for {kmi}")
        artifact = receipt.get("artifact", {})
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise SystemExit(f"receipt has no artifact path: {receipt_path}")
        ko = Path(artifact["path"])
        if not ko.is_absolute():
            ko = args.workspace_root / ko
        if not ko.is_file():
            raise SystemExit(f"missing LKM build artifact: {ko}")
        validate_receipt(receipt, kmi, ko, sources)
        builds[kmi] = (ko, receipt_path)
    if set(builds) != set(expected):
        raise SystemExit("build receipts do not match the expected KMI matrix")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".susfs-lkm-", dir=args.out.parent) as temp:
        staging = Path(temp)
        (staging / "bin").mkdir()
        (staging / "lib").mkdir()
        for name in ("load.sh", "kmi.sh"):
            shutil.copyfile(MODULE / name, staging / name)
        shutil.copyfile(args.insmod, staging / "bin/susfs_insmod")
        (staging / "kmis").write_bytes(("\n".join(expected) + "\n").encode("utf-8"))
        for kmi, (ko, receipt_path) in builds.items():
            shutil.copyfile(ko, staging / "lib" / f"{KO_PREFIX}{kmi}.ko")
            shutil.copyfile(receipt_path, staging / "lib" / f"{KO_PREFIX}{kmi}.receipt.json")
        validate_lkm_assets(staging, expected)
        # Destination is empty by contract; no previous build is silently merged.
        args.out.mkdir(exist_ok=True)
        for source in staging.iterdir():
            shutil.move(str(source), str(args.out / source.name))
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
