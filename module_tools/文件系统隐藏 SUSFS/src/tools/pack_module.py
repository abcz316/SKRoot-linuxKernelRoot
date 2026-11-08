#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pack a flashable KernelSU module from a release's .ko set and susfs_insmod.

Bundles the module scripts, every susfs_guard_lkm-<kmi>.ko found and the loader
into one ZIP, with a generated kmis list, module.prop and provenance.json. The
module picks the .ko matching the device kernel at boot and insmods it once.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ko-dir", required=True, help="directory holding susfs_guard_lkm-*.ko")
    ap.add_argument("--insmod", required=True, help="path to the susfs_insmod binary")
    ap.add_argument("--tag", required=True, help="release tag, used as the module version")
    ap.add_argument("--out", required=True, help="output ZIP path")
    args = ap.parse_args()

    ko_dir = Path(args.ko_dir)
    insmod = Path(args.insmod)
    kos = sorted(ko_dir.glob("susfs_guard_lkm-*.ko"))
    if not kos:
        raise SystemExit(f"no susfs_guard_lkm-*.ko in {ko_dir}")
    if not insmod.is_file():
        raise SystemExit(f"loader not found: {insmod}")

    kmis = [re.sub(r"^susfs_guard_lkm-|\.ko$", "", p.name) for p in kos]
    # epoch seconds: monotonic so two builds on one day still differ, and within int32 until 2038.
    version_code = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    low = min(kmis, key=lambda k: tuple(int(n) for n in k.split("-", 1)[1].split("."))).split("-", 1)[1]
    high = max(kmis, key=lambda k: tuple(int(n) for n in k.split("-", 1)[1].split("."))).split("-", 1)[1]

    # The description is the status line on the KernelSU module card, so it starts out saying
    # the module has not run yet and load.sh replaces it with the outcome of the boot - a
    # device where the load failed and one where it worked should not look the same.
    module_prop = (
        "id=susfs_guard_lkm\n"
        "name=SUSFS Guard (LKM)\n"
        f"version={args.tag}\n"
        f"versionCode={version_code}\n"
        "author=inforcqb\n"
        f"description=not loaded yet - loads the matching .ko on boot "
        f"({len(kmis)} arm64 KMIs, {low}-{high}). Loader only, no rules.\n"
    )
    provenance = {
        "repository": "https://github.com/inforcqb/susfs4ksu-lkm",
        "tag": args.tag,
        "architecture": "arm64",
        "supported_kmis": kmis,
        "assets_sha256": {p.name: sha256(p) for p in kos} | {insmod.name: sha256(insmod)},
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in ("post-fs-data.sh", "customize.sh", "kmi.sh", "early-dispatch.sh", "load.sh", "uninstall.sh"):
            z.write(ROOT / "module" / name, name)
        z.writestr("kmis", "".join(k + "\n" for k in kmis))
        z.writestr("module.prop", module_prop)
        z.write(insmod, "bin/susfs_insmod")
        for p in kos:
            z.write(p, "lib/" + p.name)
        z.write(ROOT / "LICENSE", "LICENSE")
        z.writestr("provenance.json", json.dumps(provenance, indent=2) + "\n")
    print(out)
    print("sha256:", sha256(out))


if __name__ == "__main__":
    main()
