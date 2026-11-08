#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run actual mount hook bodies with typed host kprobe/uaccess boundaries."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
from map_hook_regression import extract, execute, execution_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    path = repo / "kernel/sus_mount.c"
    source = path.read_text(encoding="utf-8")
    names = ["sus_mount_seq_number", "sus_mount_seq_replace", "sus_mount_fdinfo_replace_mntid",
             "sus_mount_fdinfo_entry", "sus_mount_fdinfo_ret", "sus_mount_statx_entry_sys",
             "sus_mount_statx_entry_do", "sus_mount_statx_ret", "sus_mount_show_pre",
             "sus_mount_parent_entry", "sus_mount_parent_ret", "sus_mount_unregister",
             "sus_mount_register", "susfs_mount_group_write_begin", "susfs_mount_group_write_end",
             "susfs_mount_group_prepare_locked", "susfs_mount_group_routes",
             "sus_mount_keep_rescan", "sus_mount_keep_command", "susfs_sus_mount_supercall"]
    structs = ["sus_mount_kretprobe_state", "sus_mount_parent_state"]
    initializers = ["kp_vfsstat", "kp_mountinfo", "kp_vfsmnt", "kr_mount_parent", "kr_statx",
                    "kr_statx_do", "sus_mount_show_probes", "sus_mount_show_names"]
    pieces = {name: extract(source, name) for name in names}
    pieces.update({name: extract(source, name, "struct") for name in structs})
    pieces.update({name: extract(source, name, "initializer") for name in initializers})
    forwards = "\n".join(pieces[name][:pieces[name].index("{")].strip() + ";" for name in names)
    shim = (repo / "tools/tests/mount_hook_shim.h").read_text(encoding="utf-8")
    before, after = shim.split("/* PRODUCTION_STRUCTURES_AND_PROBES */")
    generated = before + "\n" + forwards + "\n" + "\n".join(pieces[name] for name in structs + initializers) + "\n" + after
    generated = generated.replace("/* PRODUCTION_FUNCTIONS */", "\n\n".join(pieces[name] for name in names))
    cfile = evidence / "mount-hook-extracted.c"
    cfile.write_text(generated, encoding="utf-8")
    receipt = {"production_source": "kernel/sus_mount.c", "kernel_calls": False,
               "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
               "extracted_sha256": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in pieces.items()},
               "limits": "Host doubles, not actual kernel registration/RCU/device effect evidence.",
               "runs": [], "mutations": []}
    for name, flags in [("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / (name + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                   "-Wno-unused-function", "-Wno-unused-parameter", "-I", execution_path(repo / "kernel")]
        command += flags + [execution_path(cfile), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        item = {"name": name, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"MOUNT_HOOK_REGRESSION checks=(\d+) passed=true", run.stdout)
            item.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                        passed=run.returncode == 0 and bool(match) and not run.stderr)
        receipt["runs"].append(item)
    mutations = {
        "fdinfo-double-owner": ("if (mode == SKP_OBJECT_GROUPED)\n        return 0;\n    if (!READ_ONCE(mount_legacy_enabled)",
                                 "if (false)\n        return 0;\n    if (!READ_ONCE(mount_legacy_enabled)"),
        "fdinfo-old-interval": ("for (i = start; i + SUS_MOUNT_MNTID_LABEL_LEN < m->count; i++)",
                                 "for (i = 0; i + SUS_MOUNT_MNTID_LABEL_LEN < m->count; i++)"),
        "parent-old-interval": ("    st->start = m->count;", "    st->start = 0;"),
        "legacy-disable-grouped": ("    if (skp_policy_paths_active()) {", "    if (false) {"),
        "rescan-on-probe-ownership": ("\tif (!READ_ONCE(mount_legacy_enabled))", "\tif (!mount_registered)"),
    }
    if all(run["passed"] for run in receipt["runs"]):
        for label, (old, new) in mutations.items():
            if generated.count(old) != 1:
                raise ValueError(f"mutation {label} expected exactly one anchor")
            mutant = evidence / ("mutation-" + label + ".c")
            mutant.write_text(generated.replace(old, new), encoding="utf-8")
            binary = evidence / ("mutation-" + label + ".bin")
            build = execute([args.cc, "-std=c11", "-O2", "-I", execution_path(repo / "kernel"),
                             execution_path(mutant), "-o", execution_path(binary)])
            run = execute([execution_path(binary)]) if not build.returncode else None
            (evidence / ("mutation-" + label + ".stderr.txt")).write_text(
                build.stderr + (run.stderr if run else ""), encoding="utf-8")
            receipt["mutations"].append({"name": label, "build_exit": build.returncode,
                                          "run_exit": run.returncode if run else None,
                                          "detected": run is not None and run.returncode != 0 and "FAIL" in run.stderr})
    receipt["passed"] = (all(run["passed"] for run in receipt["runs"]) and
                         len(receipt["mutations"]) == len(mutations) and
                         all(item["detected"] for item in receipt["mutations"]))
    output = evidence / "mount-hook-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"], "mutations": receipt["mutations"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
