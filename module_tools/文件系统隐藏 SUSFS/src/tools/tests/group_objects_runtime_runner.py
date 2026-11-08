#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/run the production resolver with typed host VFS doubles and receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def execution_path(path: Path) -> str:
    path = path.resolve()
    if os.name == "nt":
        return "/mnt/" + path.drive[0].lower() + "/" + path.as_posix()[3:]
    return str(path)


def execute(arguments: list[str], timeout: int = 90) -> subprocess.CompletedProcess[str]:
    prefix = ["wsl", "--exec"] if os.name == "nt" else []
    return subprocess.run(prefix + arguments, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_names = ["kernel/skp_subject_policy.c", "kernel/skp_group_paths.c",
                    "kernel/skp_group_paths_runtime.c", "kernel/skp_group_objects.c",
                    "kernel/skp_group_objects_runtime.c",
                    "tools/tests/group_objects_runtime_test.c"]
    hash_names = source_names + ["kernel/skp_group_paths_runtime.h", "kernel/skp_group_objects.h",
                                 "kernel/skp_group_objects_runtime.h",
                                 "tools/tests/group_paths_runtime_shim.h"]
    version = execute([args.cc, "--version"])
    receipt: dict = {
        "schema_version": 1,
        "production_source": "kernel/skp_group_objects_runtime.c",
        "kernel_calls": False,
        "compiler": version.stdout.splitlines()[0] if version.stdout else version.stderr,
        "source_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                          for name in hash_names},
        "scope": ["typed VFS references", "allocation and resolver fault injection",
                  "inode acquisition failure", "bounded basename copy",
                  "profile alias validation", "permission preservation",
                  "partial preparation output isolation", "224-target all failure-position unwind"],
        "limits": "Pure host VFS doubles; not device/kernel/RCU concurrency validation.",
        "runs": [],
    }
    for name, flags in [
        ("strict", ["-O2"]),
        ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined",
                        "-fno-omit-frame-pointer"]),
    ]:
        binary = evidence / ("group-objects-runtime-" + name + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                   "-DSKP_GROUP_PATHS_RUNTIME_HOSTTEST", "-pthread"] + flags
        command += [execution_path(repo / source) for source in source_names]
        command += ["-o", execution_path(binary)]
        build = execute(command)
        (evidence / ("group-objects-runtime-" + name + ".build.stdout.txt")).write_text(
            build.stdout, encoding="utf-8")
        (evidence / ("group-objects-runtime-" + name + ".build.stderr.txt")).write_text(
            build.stderr, encoding="utf-8")
        run_record = {"name": name, "build_exit": build.returncode,
                      "build_command": command, "passed": False}
        if build.returncode == 0:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                           "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / ("group-objects-runtime-" + name + ".stdout.txt")).write_text(
                run.stdout, encoding="utf-8")
            (evidence / ("group-objects-runtime-" + name + ".stderr.txt")).write_text(
                run.stderr, encoding="utf-8")
            match = re.search(r"GROUP_OBJECTS_RUNTIME_HOST checks=(\d+) passed=true "
                              r"kernel_calls=false production_source=true", run.stdout)
            run_record.update(run_exit=run.returncode,
                              checks=int(match.group(1)) if match else 0,
                              passed=run.returncode == 0 and match is not None
                              and int(match.group(1)) >= 7000 and not run.stderr)
        receipt["runs"].append(run_record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "group-objects-runtime-host-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output),
                      "runs": [{key: run[key] for key in ("name", "checks", "passed")
                                if key in run} for run in receipt["runs"]]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
