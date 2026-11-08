#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Encode a DEVELOPMENT complete path/kstat/map runtime-facts snapshot.

This is not PackageManager integration or persistent product configuration.
Fresh user-0 subject facts use the same schema as make_path_snapshot.py. Input:
 {"schema":1,"subjects":{...},"paths":[],
  "kstats":[{"profile_id":1,"path":"/owned/fixture",
             "values":{"ino":123,"size":4096,"ctime_sec":-1}}],
  "maps":[{"profile_id":1,"path":"/owned/mapped-file"}]}

Each values key selects its corresponding corrected upstream KSTAT_SPOOF bit;
omitted values are zero. At least one value is required. Names: ino, dev_encoded,
nlink, size, atime_sec, atime_nsec, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec,
blocks, blksize. dev_encoded is new_encode_dev(), not raw s_dev. The kernel
resolves all targets and rejects same-profile aliases. The raw 71384-byte output
is sent by skp_policyctl apply-objects; missing families must be explicit [].
No socket, device connection, credentials, identity inference or write replay.
"""
import argparse
import json
import struct
from pathlib import Path

import make_path_snapshot as paths

CONFIG_BYTES = 71384
KSTAT_OFFSET = 43224
MAP_OFFSET = 54488
VALUE_BITS = {name: bit for bit, name in enumerate((
    "ino", "dev_encoded", "nlink", "size", "atime_sec", "atime_nsec",
    "mtime_sec", "mtime_nsec", "ctime_sec", "ctime_nsec", "blocks", "blksize"))}


def encode(document):
    paths.fields(document, ("schema", "subjects", "paths", "kstats", "maps"), "snapshot")
    # Reuse the canonical subject/path encoder, including complete inventory
    # validation, strict lexical paths, profile closure and deterministic tails.
    base = paths.encode({key: document[key] for key in ("schema", "subjects", "paths")})
    maps_config = paths.encode(dict(schema=document["schema"], subjects=document["subjects"],
                                    paths=document["maps"]))
    maps = document["maps"]
    if len(maps) > 64:
        raise ValueError("maps: exceeds capacity")
    kstats = document["kstats"]
    if type(kstats) is not list or len(kstats) > 32:
        raise ValueError("kstats: invalid array or capacity")
    kstat_paths = []
    values = []
    for rule in kstats:
        paths.fields(rule, ("profile_id", "path", "values"), "kstats[]")
        kstat_paths.append({key: rule[key] for key in ("profile_id", "path")})
        selected = rule["values"]
        if type(selected) is not dict or not selected or not set(selected) <= VALUE_BITS.keys():
            raise ValueError("kstats[].values: nonempty supported value keys required")
        parsed = {}
        for name, value in selected.items():
            maximum, minimum = ((1 << 63) - 1, -(1 << 63))
            if name == "ino":
                maximum, minimum = ((1 << 64) - 1, 0)
            elif name in ("dev_encoded", "nlink"):
                maximum, minimum = (0xFFFFFFFF, 0)
            elif name.endswith("_nsec"):
                maximum, minimum = (999999999, 0)
            elif name in ("size", "blocks"):
                minimum = 0
            elif name == "blksize":
                maximum, minimum = (0x7FFFFFFF, 1)
            parsed[name] = paths.integer(value, "kstats[].values." + name, maximum, minimum)
        mask = sum(1 << VALUE_BITS[name] for name in selected)
        values.append(struct.pack("<QQII6q4I", parsed.get("ino", 0),
            parsed.get("dev_encoded", 0), parsed.get("nlink", 0), mask,
            *(parsed.get(key, 0) for key in ("size", "atime_sec", "mtime_sec", "ctime_sec",
                                            "blocks", "blksize")),
            *(parsed.get(key, 0) for key in ("atime_nsec", "mtime_nsec", "ctime_nsec")), 0))
    kstats_config = paths.encode(dict(schema=document["schema"], subjects=document["subjects"],
                                      paths=kstat_paths))
    result = bytearray(CONFIG_BYTES)
    result[:paths.CONFIG_BYTES] = base
    struct.pack_into("<4I", result, paths.CONFIG_BYTES, 1, len(kstats), len(maps), 0)
    for index, value in enumerate(values):
        offset = KSTAT_OFFSET + index * 352
        result[offset:offset + 264] = kstats_config[9416 + index * 264:9416 + (index + 1) * 264]
        result[offset + 264:offset + 352] = value
    result[MAP_OFFSET:MAP_OFFSET + len(maps) * 264] = maps_config[9416:9416 + len(maps) * 264]
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
        reason = "file_io" if isinstance(exc, OSError) else "invalid_snapshot"
        print(json.dumps(dict(result="invalid_input", reason=reason)))
        return 2
    print(json.dumps(dict(result="encoded", development_only=True, bytes=len(snapshot),
        path_count=len(document["paths"]), kstat_count=len(document["kstats"]),
        map_count=len(document["maps"]), profile_count=len(document["subjects"]["profiles"]))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
