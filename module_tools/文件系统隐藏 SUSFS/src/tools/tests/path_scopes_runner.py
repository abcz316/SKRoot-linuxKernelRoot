#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile production path selectors and unchanged family cores with owned facts."""
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
    root = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    sources = ["kernel/skp_subject_policy.c", "kernel/skp_group_paths.c", "kernel/skp_group_objects.c",
               "kernel/skp_full_objects.c", "tools/tests/path_scopes_test.c"]
    inputs = sources + ["kernel/skp_path_scopes.h", "kernel/skp_group_paths.h", "kernel/skp_subject_policy.h",
                        "kernel/skp_group_objects.h", "kernel/skp_full_objects.h", "tools/tests/path_scopes_runner.py"]
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in inputs}
    receipt = dict(test="path_scopes", kernel_calls=False, device_execution=False, source_sha256=hashes,
                   limits="Production pure selectors using synthetic UID/object facts; no kernel RCU, VFS, actual app identity or device effects.", runs=[])
    for name, flags in [("strict", ["-O2", "-Wframe-larger-than=2048"]),
                        ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("path-scopes-" + name + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"] + flags
        command += [execution_path(root / source) for source in sources] + ["-o", execution_path(binary)]
        built = execute(command)
        (evidence / (name + ".build.txt")).write_text(built.stdout + built.stderr, encoding="utf-8")
        run = dict(name=name, command=command, build_exit=built.returncode, passed=False)
        if not built.returncode:
            result = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (name + ".stdout.txt")).write_text(result.stdout, encoding="utf-8")
            (evidence / (name + ".stderr.txt")).write_text(result.stderr, encoding="utf-8")
            match = re.search(r"PATH_SCOPES_HOST checks=(\d+) passed=true kernel_calls=false production_source=true", result.stdout)
            run.update(exit=result.returncode, checks=int(match.group(1)) if match else 0,
                       passed=result.returncode == 0 and bool(match) and not result.stderr)
        receipt["runs"].append(run)
    receipt["changed_inputs"] = [name for name, digest in hashes.items() if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest]
    receipt["passed"] = not receipt["changed_inputs"] and all(run["passed"] for run in receipt["runs"])
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(passed=receipt["passed"], changed_inputs=receipt["changed_inputs"], runs=receipt["runs"])))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
