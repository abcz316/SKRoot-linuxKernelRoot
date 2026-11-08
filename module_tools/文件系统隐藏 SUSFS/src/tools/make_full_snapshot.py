#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Encode a DEVELOPMENT five-family runtime-facts snapshot, not product config.

All fields are mandatory: schema, subjects, paths, kstats, maps, redirects,
mounts. The first five follow make_object_snapshot.py. Redirect entries are
{profile_id, source, target}; mounts are {profile_id, path}. Paths must be
canonical absolute non-root paths. Empty families must be explicit [].
The kernel resolves object identity, mount namespace and topology; this tool
does not infer package identity, supply mount IDs, connect or replay writes.
"""
import argparse
import json
import struct
from pathlib import Path

import make_object_snapshot as objects
import make_path_snapshot as paths

CONFIG_BYTES = 121576
REDIRECT_OFFSET = 71400
MOUNT_OFFSET = 104680


def encode(document):
    paths.fields(document, ("schema", "subjects", "paths", "kstats", "maps", "redirects", "mounts"), "snapshot")
    base = objects.encode({key: document[key] for key in ("schema", "subjects", "paths", "kstats", "maps")})
    redirects, mounts = document["redirects"], document["mounts"]
    if type(redirects) is not list or len(redirects) > 64:
        raise ValueError("redirects: invalid array or capacity")
    if type(mounts) is not list or len(mounts) > 64:
        raise ValueError("mounts: invalid array or capacity")
    sources, targets = [], []
    seen = set()
    for rule in redirects:
        paths.fields(rule, ("profile_id", "source", "target"), "redirects[]")
        sources.append(dict(profile_id=rule["profile_id"], path=rule["source"]))
        targets.append(dict(profile_id=rule["profile_id"], path=rule["target"]))
        # No self redirects, chains, shared target or duplicate source within
        # a profile. Resolved aliases are additionally checked by the kernel.
        for value in (rule["source"], rule["target"]):
            if type(value) is not str or type(rule["profile_id"]) is not int:
                raise ValueError("redirects[]: invalid profile or path type")
            key = (rule["profile_id"], value)
            if key in seen:
                raise ValueError("redirects[]: overlapping source or target")
            seen.add(key)
    source_config = paths.encode(dict(schema=document["schema"], subjects=document["subjects"], paths=sources))
    target_config = paths.encode(dict(schema=document["schema"], subjects=document["subjects"], paths=targets))
    mount_config = paths.encode(dict(schema=document["schema"], subjects=document["subjects"], paths=mounts))
    result = bytearray(CONFIG_BYTES)
    result[:objects.CONFIG_BYTES] = base
    struct.pack_into("<4I", result, objects.CONFIG_BYTES, 1, len(redirects), len(mounts), 0)
    for index in range(len(redirects)):
        offset = REDIRECT_OFFSET + index * 520
        path_offset = 9416 + index * 264
        result[offset:offset + 264] = source_config[path_offset:path_offset + 264]
        result[offset + 264:offset + 520] = target_config[path_offset + 8:path_offset + 264]
    result[MOUNT_OFFSET:MOUNT_OFFSET + len(mounts) * 264] = mount_config[9416:9416 + len(mounts) * 264]
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="fresh complete runtime-facts JSON")
    parser.add_argument("output", type=Path, help="new raw snapshot; overwrite refused")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as source:
            data = source.read(paths.MAX_INPUT_BYTES + 1)
        if len(data) > paths.MAX_INPUT_BYTES:
            raise ValueError("JSON: exceeds development input limit")
        document = paths.load(data.decode("utf-8", errors="strict"))
        snapshot = encode(document)
        with args.output.open("xb") as target:
            target.write(snapshot)
    except (OSError, ValueError) as exc:
        print(json.dumps(dict(result="invalid_input", reason="file_io" if isinstance(exc, OSError) else "invalid_snapshot")))
        return 2
    print(json.dumps(dict(result="encoded", development_only=True, bytes=len(snapshot),
        path_count=len(document["paths"]), kstat_count=len(document["kstats"]), map_count=len(document["maps"]),
        redirect_count=len(document["redirects"]), mount_count=len(document["mounts"]),
        profile_count=len(document["subjects"]["profiles"]))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
