#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Encode a DEVELOPMENT runtime-facts/path snapshot for skp_policyctl apply-paths.

This JSON is not a persistent product configuration or a package resolver. The
caller must obtain a fresh complete user-0 inventory and collapse shared UIDs
without conflicting groups. Full UIDs are never truncated or inferred. The
native tool and kernel still independently run the C policy/path validators.

Input shape (all subjects fields are mandatory; paths may be empty):
 {"schema":1,"subjects":{"version":1,"mode":"whitelist","flags":7,
  "facts_generation":17,"profiles":[0,1],"whitelist":[],"blacklist":[],
  "system_apps":[],"bindings":[{"uid":10001,"profile_id":1}]},
  "paths":[{"profile_id":1,"path":"/data/local/tmp/own-fixture"}]}

flags use the policy-core bits: root=1, system-process=2, system-app=4. No
process IDs, inode/device facts, credentials, sockets, node writes or loaders.
The output is a 43208-byte raw config, not the 43240-byte management frame.
"""
import argparse
import json
import struct
from pathlib import Path

POLICY_BYTES = 9400
CONFIG_BYTES = 43208
MAX_INPUT_BYTES = 1024 * 1024


def integer(value, field, maximum=0xFFFFFFFE, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{field}: integer outside supported range")
    return value


def fields(value, expected, field):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f"{field}: missing or unexpected fields")
    return value


def numbers(value, field, capacity, maximum):
    if type(value) is not list or len(value) > capacity:
        raise ValueError(f"{field}: invalid array or capacity")
    result = [integer(item, field, maximum) for item in value]
    if any(left >= right for left, right in zip(result, result[1:])):
        raise ValueError(f"{field}: entries must be strictly increasing")
    return result


def encode(document):
    fields(document, ("schema", "subjects", "paths"), "snapshot")
    if integer(document["schema"], "schema") != 1:
        raise ValueError("schema: unsupported version")
    subjects = fields(document["subjects"], ("version", "mode", "flags", "facts_generation",
        "profiles", "whitelist", "blacklist", "system_apps", "bindings"), "subjects")
    if integer(subjects["version"], "subjects.version") != 1:
        raise ValueError("subjects.version: unsupported version")
    if type(subjects["mode"]) is not str or subjects["mode"] not in ("whitelist", "blacklist"):
        raise ValueError("subjects.mode: whitelist or blacklist required")
    mode = int(subjects["mode"] == "blacklist")
    flags = integer(subjects["flags"], "subjects.flags", 7)
    facts = integer(subjects["facts_generation"], "subjects.facts_generation", (1 << 64)-1, 1)
    profiles = numbers(subjects["profiles"], "subjects.profiles", 32, 0xFFFFFFFE)
    if not profiles or profiles[0] != 0:
        raise ValueError("subjects.profiles: default profile 0 is mandatory")
    white = numbers(subjects["whitelist"], "subjects.whitelist", 128, 99999)
    black = numbers(subjects["blacklist"], "subjects.blacklist", 128, 99999)
    system = numbers(subjects["system_apps"], "subjects.system_apps", 1024, 99999)
    bindings = subjects["bindings"]
    if type(bindings) is not list or len(bindings) > 512:
        raise ValueError("subjects.bindings: invalid array or capacity")
    parsed_bindings = []
    for binding in bindings:
        fields(binding, ("uid", "profile_id"), "subjects.bindings[]")
        uid = integer(binding["uid"], "subjects.bindings[].uid", 99999)
        profile = integer(binding["profile_id"], "subjects.bindings[].profile_id")
        if profile not in profiles:
            raise ValueError("subjects.bindings[].profile_id: undeclared profile")
        if parsed_bindings and uid <= parsed_bindings[-1][0]:
            raise ValueError("subjects.bindings: duplicate/conflicting or unordered UID")
        parsed_bindings.append((uid, profile))
    paths = document["paths"]
    if type(paths) is not list or len(paths) > 128:
        raise ValueError("paths: invalid array or capacity")
    parsed_paths = []
    seen = set()
    for rule in paths:
        fields(rule, ("profile_id", "path"), "paths[]")
        profile = integer(rule["profile_id"], "paths[].profile_id")
        if profile not in profiles:
            raise ValueError("paths[].profile_id: undeclared profile")
        path = rule["path"]
        if type(path) is not str or not path.startswith("/"):
            raise ValueError("paths[].path: absolute canonical path required")
        try:
            encoded = path.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ValueError("paths[].path: invalid UTF-8") from exc
        if (not 1 < len(encoded) < 256 or any(byte < 32 or byte == 127 for byte in encoded)
                or any(part in ("", ".", "..") for part in path.split("/")[1:])):
            raise ValueError("paths[].path: unsupported length or noncanonical path")
        if (profile, encoded) in seen:
            raise ValueError("paths: duplicate path within a profile")
        seen.add((profile, encoded))
        parsed_paths.append((profile, encoded))

    result = bytearray(CONFIG_BYTES)
    struct.pack_into("<8IQ4I", result, 0, 1, mode, flags, len(profiles), len(white),
                     len(black), len(system), len(bindings), facts, 0, 0, 0, 0)
    for offset, values in ((56, profiles), (184, white), (696, black), (1208, system)):
        for index, value in enumerate(values):
            struct.pack_into("<I", result, offset+index*4, value)
    for index, binding in enumerate(parsed_bindings):
        struct.pack_into("<II", result, 5304+index*8, *binding)
    struct.pack_into("<IIQ", result, POLICY_BYTES, 1, len(paths), 0)
    for index, (profile, path) in enumerate(parsed_paths):
        struct.pack_into("<II", result, 9416+index*264, profile, 0)
        result[9424+index*264:9424+index*264+len(path)] = path
    return bytes(result)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON: duplicate field")
        result[key] = value
    return result


def load(text):
    def invalid_constant(_):
        raise ValueError("JSON: non-finite constant")
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="development-only fresh runtime-facts JSON")
    parser.add_argument("output", type=Path, help="new raw snapshot file; existing files are refused")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as source:
            data = source.read(MAX_INPUT_BYTES+1)
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError("JSON: exceeds development input limit")
        document = load(data.decode("utf-8", errors="strict"))
        snapshot = encode(document)
        with args.output.open("xb") as target:
            target.write(snapshot)
    except (OSError, ValueError) as exc:
        # File-system exceptions may include caller paths; keep this machine
        # response free of input paths and runtime app identities.
        reason = "file_io" if isinstance(exc, OSError) else "invalid_snapshot"
        print(json.dumps(dict(result="invalid_input", reason=reason)))
        return 2
    print(json.dumps(dict(result="encoded", development_only=True, bytes=len(snapshot),
                          path_count=len(document["paths"]),
                          profile_count=len(document["subjects"]["profiles"]))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
