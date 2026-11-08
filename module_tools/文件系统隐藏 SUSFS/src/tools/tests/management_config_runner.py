#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict + sanitized schema10 and schema9-import management config regression.

The actual policy core is compiled as C, then linked with the real C++ config,
inventory and JSON helpers. This explicitly checks cross-language ABI/linkage.
No device, kernel control node, PackageManager command or intercept test runs.
"""
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
    parser.add_argument("--cxx", default="c++")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    core = ["kernel/skp_subject_policy.c", "kernel/skp_group_paths.c",
            "kernel/skp_group_objects.c", "kernel/skp_full_objects.c"]
    sources = ["management/config.cpp", "management/inventory.cpp", "management/common.cpp",
               "management/vendor/cJSON.cpp", "tools/tests/management_config_test.cpp"]
    headers = ["management/config.hpp", "management/inventory.hpp", "management/common.hpp",
               "management/wire.hpp", "kernel/skp_full_objects.h", "kernel/skp_policy_adapter.h",
               "kernel/skp_path_scopes.h"]
    receipt = dict(test="management_config", device_execution=False, kernel_calls=False,
        source_sha256={name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                       for name in core + sources + headers},
        limits="Actual production C/C++ source, synthetic complete package inventories; no Android or live kernel effects.", runs=[])
    for name, flags in (("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        build_log = ""
        objects = []
        build_exit = 0
        for source in core:
            target = evidence / f"{name}-{Path(source).stem}.o"
            command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
                       "-c", execution_path(repo / source), "-o", execution_path(target)]
            built = execute(command)
            build_log += built.stdout + built.stderr
            if built.returncode:
                build_exit = built.returncode
                break
            objects.append(target)
        binary = evidence / f"management-config-{name}.bin"
        command = [args.cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
                   *[execution_path(repo / source) for source in sources],
                   *[execution_path(obj) for obj in objects], "-pthread", "-o", execution_path(binary)]
        if not build_exit:
            built = execute(command)
            build_log += built.stdout + built.stderr
            build_exit = built.returncode
        (evidence / f"{name}.build.txt").write_text(build_log, encoding="utf-8")
        run = dict(name=name, command=command, c_core_separate=True,
                   build_exit=build_exit, passed=False)
        if not build_exit:
            result = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / f"{name}.run.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
            match = re.search(r"MANAGEMENT_CONFIG_HOST checks=(\d+) passed=true kernel_calls=false production_source=true", result.stdout)
            run.update(exit=result.returncode, checks=int(match.group(1)) if match else 0,
                       passed=result.returncode == 0 and bool(match))
        receipt["runs"].append(run)
    receipt["source_changed_during_run"] = receipt["source_sha256"] != {
        name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
        for name in receipt["source_sha256"]}
    receipt["passed"] = not receipt["source_changed_during_run"] and all(run["passed"] for run in receipt["runs"])
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
