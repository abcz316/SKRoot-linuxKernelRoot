#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute production mount resolver/stability code using typed VFS doubles."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
from group_objects_runtime_runner import execute, execution_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    sources = ["kernel/skp_subject_policy.c", "kernel/skp_group_paths.c",
               "kernel/skp_group_objects.c", "kernel/skp_full_objects.c",
               "kernel/skp_mount_runtime.c", "tools/tests/mount_runtime_test.c"]
    hashes = sources + ["kernel/skp_mount_runtime.h", "kernel/skp_full_objects.h",
                        "tools/tests/mount_runtime_shim.h"]
    receipt = {"production_source": "kernel/skp_mount_runtime.c", "kernel_calls": False,
               "source_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                                 for name in hashes},
               "limits": "Host typed VFS/seqlock doubles, not kernel/RCU/device evidence.",
               "runs": [], "mutations": []}
    for name, flags in [("strict", ["-O2"]),
                        ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined",
                                        "-fno-omit-frame-pointer"])]:
        binary = evidence / ("mount-runtime-" + name + ".bin")
        cmd = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
               "-DSKP_MOUNT_RUNTIME_HOSTTEST"] + flags
        cmd += [execution_path(repo / source) for source in sources]
        cmd += ["-o", execution_path(binary)]
        build = execute(cmd)
        (evidence / (name + ".build.stdout.txt")).write_text(build.stdout, encoding="utf-8")
        (evidence / (name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        item = {"name": name, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                           "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"MOUNT_RUNTIME_HOST checks=(\d+) passed=true "
                              r"kernel_calls=false production_source=true", run.stdout)
            item.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                        passed=run.returncode == 0 and bool(match) and not run.stderr)
        receipt["runs"].append(item)
    if all(run["passed"] for run in receipt["runs"]):
        original = (repo / "kernel/skp_mount_runtime.c").read_text(encoding="utf-8")
        mutations = {
            "ignore-odd-sequence": ("\tif (sequence & 1)\n\t\treturn false;\n", ""),
            "allow-chroot-publisher": ("if (!skp_mount_publisher_root_supported(runtime))", "if (false)"),
        }
        for label, (anchor, replacement) in mutations.items():
            if original.count(anchor) != 1:
                raise ValueError(f"{label} mutation expected one anchor")
            mutant = evidence / ("mutation-" + label + ".c")
            mutant.write_text(original.replace(anchor, replacement), encoding="utf-8")
            binary = evidence / ("mutation-" + label + ".bin")
            cmd = [args.cc, "-std=c11", "-O2", "-DSKP_MOUNT_RUNTIME_HOSTTEST",
                   "-I", execution_path(repo / "kernel")]
            cmd += [execution_path(mutant if name == "kernel/skp_mount_runtime.c" else repo / name)
                    for name in sources]
            cmd += ["-o", execution_path(binary)]
            build = execute(cmd)
            run = execute([execution_path(binary)]) if not build.returncode else None
            (evidence / ("mutation-" + label + ".stderr.txt")).write_text(
                build.stderr + (run.stderr if run else ""), encoding="utf-8")
            receipt["mutations"].append({"name": label, "build_exit": build.returncode,
                                         "run_exit": run.returncode if run else None,
                                         "detected": run is not None and run.returncode != 0 and "FAIL" in run.stderr})
    receipt["passed"] = (all(run["passed"] for run in receipt["runs"]) and
                         len(receipt["mutations"]) == 2 and
                         all(item["detected"] for item in receipt["mutations"]))
    output = evidence / "mount-runtime-host-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"], "mutations": receipt["mutations"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
