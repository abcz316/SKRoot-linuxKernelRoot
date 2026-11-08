#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual pure five-family core with strict and ASan/UBSan host checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from group_objects_runtime_runner import execute, execution_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    sources = ["kernel/skp_subject_policy.c", "kernel/skp_group_paths.c", "kernel/skp_group_objects.c",
               "kernel/skp_full_objects.c", "tools/tests/full_objects_test.c"]
    hashes = sources + ["kernel/skp_full_objects.h", "kernel/skp_policy_adapter.h"]
    receipt = dict(test="full_objects", kernel_calls=False, device_execution=False,
                   source_sha256={name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in hashes},
                   limits="Pure synthetic identity/mount keys; no actual VFS, RCU, namespace or device effects.", runs=[])
    for name, flags in (("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        binary = evidence / ("full-objects-" + name + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"] + flags
        command += [execution_path(repo / source) for source in sources] + ["-o", execution_path(binary)]
        build = execute(command)
        (evidence / (name + ".build.txt")).write_text(build.stdout + build.stderr, encoding="utf-8")
        run = dict(name=name, command=command, build_exit=build.returncode, passed=False)
        if not build.returncode:
            result = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (name + ".run.txt")).write_text(result.stdout + result.stderr, encoding="utf-8")
            match = re.search(r"FULL_OBJECTS_HOST checks=(\d+) passed=true kernel_calls=false production_source=true", result.stdout)
            run.update(exit=result.returncode, checks=int(match.group(1)) if match else 0, passed=result.returncode == 0 and bool(match))
        receipt["runs"].append(run)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
