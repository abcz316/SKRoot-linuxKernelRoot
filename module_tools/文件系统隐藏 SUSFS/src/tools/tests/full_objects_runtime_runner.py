#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build production full-candidate composition with typed dependency doubles."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from group_paths_runtime_runner import execute, execution_path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--evidence", type=Path, required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
args.evidence.mkdir(parents=True, exist_ok=True)
sources = ["kernel/skp_subject_policy.c", "kernel/skp_group_paths.c",
           "kernel/skp_group_objects.c", "kernel/skp_full_objects.c",
           "kernel/skp_full_objects_runtime.c", "tools/tests/full_objects_runtime_test.c"]
inputs = sources + ["kernel/skp_full_objects_runtime.h", "kernel/skp_full_objects.h",
                    "tools/tests/full_objects_runtime_shim.h"]
receipt = {"production_source": "kernel/skp_full_objects_runtime.c", "kernel_calls": False,
           "limits": "Production composition; dependent VFS resolvers use separate actual-source tests. No kernel/RCU/device proof.",
           "source_sha256": {s: hashlib.sha256((repo / s).read_bytes()).hexdigest() for s in inputs}, "runs": []}
for label, flags in [("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
    binary = args.evidence / (label + ".bin")
    command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
               "-DSKP_GROUP_PATHS_RUNTIME_HOSTTEST", "-DSKP_FULL_OBJECTS_RUNTIME_HOSTTEST"] + flags
    command += [execution_path(repo / s) for s in sources] + ["-o", execution_path(binary)]
    build = execute(command)
    (args.evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
    row = {"name": label, "build_exit": build.returncode, "passed": False}
    if not build.returncode:
        run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
        (args.evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
        (args.evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
        match = re.search(r"FULL_OBJECTS_RUNTIME_HOST checks=(\d+) passed=true kernel_calls=false production_source=true", run.stdout)
        row.update(run_exit=run.returncode, checks=int(match[1]) if match else 0,
                   passed=run.returncode == 0 and bool(match) and not run.stderr)
    receipt["runs"].append(row)
receipt["passed"] = all(r["passed"] for r in receipt["runs"])
(args.evidence / "full-objects-runtime-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(json.dumps(receipt))
raise SystemExit(0 if receipt["passed"] else 1)
