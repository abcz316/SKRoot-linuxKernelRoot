#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run only the visible-root delta against the real mount prepare/stable code."""
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
               "kernel/skp_mount_runtime.c", "tools/tests/mount_visible_root_test.c"]
    hash_names = sources + ["kernel/skp_mount_runtime.h", "kernel/skp_full_objects.h",
                            "tools/tests/mount_runtime_shim.h",
                            "tools/tests/mount_runtime_test.c",
                            "tools/tests/mount_visible_root_runner.py"]
    version = execute([args.cc, "--version"])
    (evidence / "compiler-version.txt").write_text(version.stdout + version.stderr, encoding="utf-8")
    receipt = {"schema_version": 1, "production_source": "kernel/skp_mount_runtime.c",
               "kernel_calls": False, "baseline_suite_executed": False,
               "compiler": version.stdout.splitlines()[0] if version.stdout else version.stderr,
               "source_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                                 for name in hash_names},
               "limits": "Typed host VFS/seqlock doubles, not device/kernel/RCU evidence.",
               "runs": [], "mutations": []}
    for name, flags in [("strict", ["-O2"]),
                        ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined",
                                        "-fno-omit-frame-pointer"])]:
        binary = evidence / ("mount-visible-root-" + name + ".bin")
        cmd = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
               "-DSKP_MOUNT_RUNTIME_HOSTTEST"] + flags
        cmd += [execution_path(repo / source) for source in sources]
        cmd += ["-o", execution_path(binary)]
        build = execute(cmd)
        (evidence / (name + ".build.stdout.txt")).write_text(build.stdout, encoding="utf-8")
        (evidence / (name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        item = {"name": name, "build_command": cmd, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run_cmd = ["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                       "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)]
            run = execute(run_cmd)
            (evidence / (name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"MOUNT_VISIBLE_ROOT_HOST checks=(\d+) scenarios=(\d+) passed=true "
                              r"kernel_calls=false production_source=true", run.stdout)
            item.update(run_command=run_cmd, run_exit=run.returncode,
                        checks=int(match.group(1)) if match else 0,
                        scenarios=int(match.group(2)) if match else 0,
                        passed=run.returncode == 0 and bool(match) and not run.stderr)
        receipt["runs"].append(item)
    if all(run["passed"] for run in receipt["runs"]):
        original = (repo / "kernel/skp_mount_runtime.c").read_text(encoding="utf-8")
        mutations = {
            "require-self-parent": ("supported = runtime->publisher_root.dentry == root->mnt.mnt_root &&",
                                    "supported = READ_ONCE(root->mnt_parent) == root && runtime->publisher_root.dentry == root->mnt.mnt_root &&"),
            "capture-invisible-parent": ("if (&mount->mnt == runtime->publisher_root.mnt) {", "if (parent == mount) {"),
            "allow-subdirectory-publisher": ("if (!skp_mount_publisher_root_supported(runtime))", "if (false)"),
            "allow-visible-root-hide": ("if (!j && &mount->mnt == runtime->publisher_root.mnt) {", "if (false) {"),
            "omit-terminal-root-check": ("runtime->held[i][object->chain_count - 1] != runtime->publisher_root.mnt", "false"),
            "omit-complete-root-stability": ("if (READ_ONCE(runtime->publisher_root.mnt->mnt_root) !=\n\t    runtime->publisher_root.dentry)", "if (false)"),
            "ignore-odd-topology-writer": ("\tif (sequence & 1)\n\t\treturn false;\n", ""),
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
            (evidence / ("mutation-" + label + ".build.stdout.txt")).write_text(build.stdout, encoding="utf-8")
            (evidence / ("mutation-" + label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
            (evidence / ("mutation-" + label + ".stdout.txt")).write_text(run.stdout if run else "", encoding="utf-8")
            (evidence / ("mutation-" + label + ".stderr.txt")).write_text(run.stderr if run else "", encoding="utf-8")
            receipt["mutations"].append({"name": label, "build_command": cmd,
                                         "build_exit": build.returncode,
                                         "run_exit": run.returncode if run else None,
                                         "detected": run is not None and run.returncode != 0 and "FAIL" in run.stderr})
    receipt["passed"] = (all(run["passed"] for run in receipt["runs"]) and
                         len(receipt["mutations"]) == 7 and
                         all(item["detected"] for item in receipt["mutations"]))
    output = evidence / "mount-visible-root-host-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output),
                      "runs": [{key: run[key] for key in ("name", "checks", "scenarios", "passed")
                                if key in run} for run in receipt["runs"]],
                      "mutations": receipt["mutations"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
